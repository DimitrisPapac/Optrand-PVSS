use crate::{
    modified_scrape::{errors::PVSSError, pvss::PVSSShare, decomp::DecompProof},
    Signature,  // EdDSA signature
};

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Read, Write};
use ark_std::collections::BTreeMap;
use std::io::Cursor;


// PVSSAugmentedShare represents a PVSSShare that has been augmented to include the origin's id,
// as well as a signature on the decomposition proof included in the core PVSS share.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PVSSAugmentedShare<E>
where
    E: PairingEngine,
{
    pub participant_id: usize,            // issuer of the augmented share
    pub pvss_share: PVSSShare<E>,         // "core" PVSS share
    pub decomp_proof: DecompProof<E>,     // proof of knowledge of shared secret
    pub signature_on_decomp: Signature,   // EdDSA-signed knowledge proof
}


// PVSSTranscript represents the transcripts obtained by each aggregator instance
// during execution of the PVSS protocol.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PVSSTranscript<E>
where
    E: PairingEngine,
{
    pub degree: usize,
    pub num_participants: usize,
    pub contributions: BTreeMap<usize, PVSSTranscriptParticipant<E>>,
    pub pvss_share: PVSSShare<E>,
}


// PVSSTranscriptParticipant represents a "contribution" of an individual protocol participant.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PVSSTranscriptParticipant<
    E: PairingEngine,
> {
    pub decomp_proof: DecompProof<E>,           // contains gs
    pub signature_on_decomp: Signature,   
}


// Utility function for buffering a decomposition proof into a buffer and obtaining a reference
// to said buffer.
pub fn message_from_pi_i<E: PairingEngine>(pi_i: DecompProof<E>) -> Result<Vec<u8>, PVSSError<E>> {
    let mut message_writer = Cursor::new(vec![]);
    pi_i.serialize(&mut message_writer)?;
    Ok(message_writer.get_ref().to_vec())
}


impl<
        E: PairingEngine,
    > PVSSTranscript<E>
{
    // Function for generating a new PVSSTranscript instance.
    pub fn empty(degree: usize, num_participants: usize) -> Self {
        Self {
            degree,
            num_participants,
            contributions: BTreeMap::new(),
            pvss_share: PVSSShare::empty(degree, num_participants),
        }
    }

    // Method for aggregating two PVSS transcripts.
    pub fn aggregate(&self, other: &Self) -> Result<Self, PVSSError<E>> {
	    // Ensure that both PVSS transcripts are w.r.t. a common configuration
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
                        let transcript_participant = PVSSTranscriptParticipant {
			                // Only keep a's proof and signature
                            decomp_proof: a.decomp_proof,
                            signature_on_decomp: a.signature_on_decomp.clone(),
                        };
                        Ok(Some((i, transcript_participant)))
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

        let aggregated_tx = Self {
            degree: self.degree,
            num_participants: self.num_participants,
            contributions: contributions.into_iter().collect(),
            pvss_share: self.pvss_share.aggregate(&other.pvss_share).unwrap(),   // aggregate the two core PVSS shares
        };

        Ok(aggregated_tx)
    }
}
