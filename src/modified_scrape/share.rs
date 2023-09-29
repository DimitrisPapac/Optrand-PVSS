use crate::{
    modified_scrape::{errors::PVSSError, pvss::PVSSCore, decomp::DecompProof},
    Signature,  // EdDSA signature
};

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Read, Write};
use ark_std::collections::BTreeMap;
use std::io::Cursor;


/* PVSSShare represents a PVSSCore instance that has been augmented to include the origin's id,
   as well as a signature on the decomposition proof included in the core PVSS share. */
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PVSSShare<E>
where
    E: PairingEngine,
{
    pub participant_id: usize,            // issuer of this PVSS share
    pub pvss_core: PVSSCore<E>,           // "core" of the PVSS share
    pub decomp_proof: DecompProof<E>,     // proof of knowledge of shared secret
    pub signature_on_decomp: Signature,   // EdDSA-signed knowledge proof
}

/* Struct SignedProof represents a pair consisting of a decomposition proof along with
   a signature on it. */
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct SignedProof<E>
where
    E: PairingEngine,
{
    decomp_proof: DecompProof<E>,
    signature_on_decomp: Signature,
}

/* Struct PVSSAggregatedShare represents an aggregation of PVSS shares. */
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PVSSAggregatedShare<E>
where
    E: PairingEngine,
{
    pub num_participants: usize,
    pub degree: usize,
    pub pvss_core: PVSSCore<E>,                           // "core" of the aggregated PVSS sharing
    pub contributions: BTreeMap<usize, SignedProof<E>>,   // combination of the three following fields

    // pub id_vec: Vec<usize>,                     // vector of participant ids whose shares have been pooled together
    // pub decomp_proofs: Vec<DecompProof<E>>,     // accumulation of decomposition proofs
    // pub signatures_on_decomps: Vec<Signature>,  // accumulation of signatures on decomposition proofs
}


// Utility function for buffering a decomposition proof into a buffer and obtaining a reference
// to said buffer.
pub fn message_from_pi_i<E: PairingEngine>(pi_i: DecompProof<E>) -> Result<Vec<u8>, PVSSError<E>> {
    let mut message_writer = Cursor::new(vec![]);
    pi_i.serialize(&mut message_writer)?;
    Ok(message_writer.get_ref().to_vec())
}


impl<E: PairingEngine> PVSSAggregatedShare<E>
{
    // Function for generating a new (empty) PVSSAggregatedShare instance.
    pub fn empty(degree: usize, num_participants: usize) -> Self {
        Self {
	    num_participants: num_participants,
	    degree: degree,
	    pvss_core: PVSSCore::empty(degree, num_participants),
	    contributions: BTreeMap::new(),
        }
    }

    // Method for aggregating two PVSS aggregated shares.
    pub fn aggregate(&self, other: &Self) -> Result<Self, PVSSError<E>> {
	// Ensure that both PVSS aggregated shares are under a common configuration.
        if self.degree != other.degree || self.num_participants != other.num_participants {
            return Err(PVSSError::TranscriptDifferentConfig(
                self.degree,
                other.degree,
                self.num_participants,
                other.num_participants,
            ));
        }

	// Combine contributions of self and other into a single BTreeMap.
        let contributions = (0..self.num_participants)   // this is: n x amortized O(1)
            .map(
                |i| match (self.contributions.get(&i), other.contributions.get(&i)) {
                    (Some(a), Some(b)) => {
                        if a.decomp_proof.gs != b.decomp_proof.gs {
                            return Err(PVSSError::TranscriptDifferentCommitments);
                        }
                        let signed_proof = SignedProof {
			    // Only keep a's decomposition proof and signature
                            decomp_proof: a.decomp_proof,
                            signature_on_decomp: a.signature_on_decomp.clone(),
                        };
                        Ok(Some((i, signed_proof)))
                    }
                    (Some(a), None) => Ok(Some((i, a.clone()))),
                    (None, Some(b)) => Ok(Some((i, b.clone()))),
                    (None, None) => Ok(None),
                },
            )
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|e| e)
            .collect::<Vec<_>>();

        let aggregated_share = Self {
            num_participants: self.num_participants,
	    degree: self.degree,
            pvss_core: self.pvss_core.aggregate(&other.pvss_core).unwrap(),   // aggregate the two cores of PVSS shares
            contributions: contributions.into_iter().collect(),
        };

        Ok(aggregated_share)
    }
}
