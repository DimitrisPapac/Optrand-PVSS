use crate::{
    modified_scrape::{errors::PVSSError, pvss::PVSSCore, decomp::DecompProof},
    PublicKey,
    Signature,
};

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Read, Write};
use ark_std::collections::BTreeMap;

use std::io::Cursor;

use super::config::Config;


/* Struct SignedProof represents a pair consisting of a decomposition proof along with
   a signature on it. */
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct SignedProof<E>
where
    E: PairingEngine,
{
    pub decomp_proof: DecompProof<E>,     // proof of knowledge of shared secret
    pub signature_on_decomp: Signature,   // EdDSA-signed knowledge proof
}

impl<E: PairingEngine> SignedProof<E> {
    // Method enabling verification of signed proofs.
    fn verify(&mut self, conf: &Config<E>, pk_sig: &PublicKey) -> Result<(), PVSSError<E>> {
        // Verify the NIZK proof
        self.decomp_proof.verify(&conf).unwrap();

        // Verify the signature on the NIZK proof
        self.signature_on_decomp.verify(&mut self.decomp_proof.digest(), &pk_sig).unwrap();

        Ok(())
    }
}

/* PVSSShare represents a PVSSCore instance that has been augmented to include the origin's id,
   as well as a signature on the decomposition proof included in the core PVSS share. */
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PVSSShare<E>
where
    E: PairingEngine,
{
    pub participant_id: usize,            // issuer of this PVSS share
    pub pvss_core: PVSSCore<E>,           // "core" of the PVSS share
    pub signed_proof: SignedProof<E>,     // signed proof of decomposition
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

    // Using a BTreeMap saves us from having to manually manage three vectors instead:
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
	    num_participants,
	    degree,
	    pvss_core: PVSSCore::empty(num_participants),
	    contributions: BTreeMap::new(),
        }
    }

    // Method for aggregating two PVSS aggregated shares.
    // Returns the resulting aggregated PVSS share.
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
                        // Only keep a's signed proof
                        let signed_proof = SignedProof {
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

	// Return the aggregate of the two aggregated PVSS shares.
        Ok(aggregated_share)
    }

    // Method for aggregating a PVSS share to an aggregated PVSS share.
    // Returns the resulting aggregated PVSS share.
    pub fn aggregate_pvss_share(&self, other: &PVSSShare<E>) -> Result<Self, PVSSError<E>> {
	// Convert other from a PVSSShare instance into a PVSSAggregatedShare instance.
	let mut contribs = BTreeMap::new();
	contribs.insert(other.participant_id, SignedProof{ decomp_proof: other.signed_proof.decomp_proof,
							   signature_on_decomp: other.signed_proof.signature_on_decomp});

	let other_agg_share = Self {
            num_participants: self.num_participants,
            degree: self.degree,
            pvss_core: other.pvss_core.clone(),
            contributions: contribs,
        };

	// Return the aggregate of the two aggregated PVSS shares.
	self.aggregate(&other_agg_share)
    }
}


/* Unit tests: */

#[cfg(test)]
mod test {

    use crate::signature::utils::tests::check_serialization;

    use crate::{modified_scrape::share::PVSSCore, generate_production_keypair};
    use crate::modified_scrape::{srs::SRS, config::Config, poly::Polynomial, share::SignedProof};
    use crate::modified_scrape::decomp::Decomp;
    use crate::Scalar;
    use crate::Signature;
    use crate::signature::schnorr::{SchnorrSignature, srs::SRS as SCHSRS};

    use ark_ec::PairingEngine;
    use ark_ff::PrimeField;
    use ark_poly::UVPolynomial;
    use ark_std::UniformRand;
    use ark_bls12_381::{
	    Bls12_381 as E,   // type Bls12_381 = Bls12<Parameters> (Bls12 implements PairingEngine)
    };
    use rand::thread_rng;

    #[test]
    fn test_generate_valid_signed_proof() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        let p_0 = Scalar::<E>::from(10 as u64);

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let g1 = srs.g1;   // affine
        let g2 = srs.g2;   // affine
        
        let conf = Config { srs, degree: t, num_participants: n };

        // EdDSA setup
        let (pk_sig, sk_sig) = generate_production_keypair();

        // generate decomposition proof
        let mut dproof = Decomp::<E>::generate(rng, &conf, &p_0).unwrap();

        // sign the proof
        let sig = Signature::new(&mut dproof.digest(), &sk_sig);

        let mut sproof = SignedProof {decomp_proof: dproof, signature_on_decomp: sig};

        // Verify SignedProof instance
        sproof.verify(&conf, &pk_sig).unwrap();
    }


    #[test]
    fn test_generate_pvss_share() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        let id = 1_usize;

        let p_0 = Scalar::<E>::from(10 as u64);

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let g1 = srs.g1;   // affine
        let g2 = srs.g2;   // affine
        
        let conf = Config { srs, degree: t, num_participants: n };

        // Schnorr SRS ....................................................
        let schnorr_srs = SCHSRS::<<E as PairingEngine>::G1Affine>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // EdDSA setup
        let (pk_sig, sk_sig) = generate_production_keypair();

        // generate decomposition proof
        let mut dproof = Decomp::<E>::generate(rng, &conf, &p_0).unwrap();

        // sign the proof
        let sig = Signature::new(&mut dproof.digest(), &sk_sig);

        let mut sproof = SignedProof {decomp_proof: dproof, signature_on_decomp: sig};
    }


    #[test]
    fn test_serialization() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        // EdDSA setup
        let eddsa_keypair = generate_production_keypair();

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let g1 = srs.g1;   // affine
        let g2 = srs.g2;   // affine
        
        let conf = Config { srs, degree: t, num_participants: n };
        let poly = Polynomial::<E>::rand(t, rng);

        // vector of i's as scalars
        let points = (1..=t)
            .map(|j| Scalar::<E>::from(j as u64))
            .collect::<Vec<_>>();
/*
        // vector of commitments: g_2^{s_i}
	    let evals = (1..=t)
            .map(|j| g2.mul(poly.evaluate(&points[(j-1) as usize]).into_repr()))
            .collect::<Vec<_>>();

        let pid: usize = 1;

	    let core = PVSSCore::<E> {
            encs: //vec![<E as PairingEngine>::G1Projective::rand(rng); n],
            comms: //vec![<E as PairingEngine>::G2Projective::rand(rng); n],
        };

        let dproof = Decomp::<E>::generate(rng, &conf, &poly.coeffs[0]).unwrap();

        check_serialization(core.clone());
*/
    }

}
