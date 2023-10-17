use super::dlk::srs::SRS;
use crate::nizk::{scheme::NIZKProof, utils::{errors::NIZKError, hash::hash_to_field}};

use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_ff::{PrimeField, UniformRand};

use std::fmt::Debug;
use rand::Rng;

use std::hash::Hash;

pub mod srs;


const PERSONALIZATION: &[u8] = b"DLKNIZK";   // persona for the DLK NIZK proof system

// DLKProof type wraps around the SRS and represents the scheme's
// system-wide parameters.
#[derive(Clone, Debug, PartialEq, Hash)]
pub struct DLKProof<C: AffineCurve> {
    pub srs: SRS<C>,   // same SRS as the Schnorr signature scheme
}

// DLKProof implements the NIZKProof trait.
impl<C: AffineCurve> NIZKProof for DLKProof<C> {

    type SRS = SRS<C>;                                  // SRS for Schnorr is just a generator (i.e., an EC point)
    type Witness = C::ScalarField;                      // witnessess are scalars from the field underlying C
    type Challenge = C::ScalarField;                    // challenges are scalars from the field underlying C
    type Statement = C;                                 // public statements are elliptic curve points
    type Proof = (C, C::ScalarField, C::ScalarField);   // proof format: (commitment to nonce, challenge, response)

    // Creates a DLKProof from a given SRS.
    fn from_srs(srs: Self::SRS) -> Result<Self, NIZKError> {
        Ok(Self { srs })
    }

    // Generates a witness, statement pair using a specified RNG.
    fn generate_pair<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Witness, Self::Statement), NIZKError> {
        let w = Self::Witness::rand(rng);
        Ok((w, self.srs.g_public_key.mul(w.into_repr()).into_affine()))
    }

    // Computes a witness, statement pair, given only the witness.
    fn from_witness(
        &self,
        w: &Self::Witness,
    ) -> Result<(Self::Witness, Self::Statement), NIZKError> {
        Ok((*w, self.srs.g_public_key.mul(w.into_repr()).into_affine()))
    }

    // Function for generating a NIZKPoK of discrete logarithm.
    fn prove<R: Rng>(
        &self,
        rng: &mut R,
        w: &Self::Witness,
    ) -> Result<Self::Proof, NIZKError> {

        // Sample a random nonce
        let r = Self::Witness::rand(rng);

        // Compute commitment to nonce as: g_r := r * g
        let g_r = self.srs.g_public_key.mul(r.into_repr()).into_affine();
        
        // serialize g into writer g_bytes
        let mut g_bytes = vec![];
        self.srs.g_public_key.serialize(&mut g_bytes)?;

	// serialize g_r into writer g_r_bytes
        let mut g_r_bytes = vec![];
        g_r.serialize(&mut g_r_bytes)?;

        // Compute the "challenge" part of the proof
        let hashed_message = hash_to_field::<Self::Challenge>(
            PERSONALIZATION, &[&g_bytes[..], &g_r_bytes].concat()
        )?;

        // Compute the "response" part of the proof
        let z = r - (*w * hashed_message);

        // Form and return the result
	let proof = (g_r, hashed_message, z);
        Ok(proof)
    }

    // Function for verifying a NIZKPoK of discrete logarithm.
    fn verify(
        &self,
        stmnt: &Self::Statement,
        proof: &Self::Proof,
    ) -> Result<(), NIZKError> {

        // serialize g into writer g_bytes
        let mut g_bytes = vec![];
        self.srs.g_public_key.serialize(&mut g_bytes)?;

	// serialize g_r into writer g_r_bytes
	let mut g_r_bytes = vec![];
        proof.0.serialize(&mut g_r_bytes)?;

	// compute the challenge corresponding to what was provided
        let hashed_message = hash_to_field::<Self::Challenge>(
            PERSONALIZATION, &[&g_bytes[..], &g_r_bytes].concat()
        )?;

	// compute LHS of the verification condition
	let check = (self.srs.g_public_key.mul(proof.2.into_repr())
            + stmnt.mul(hashed_message.into_repr()))
            .into_affine();

	// Compare LHS against RHS as per the verification condition and ensure
	// the computed challenge matches the supplied challenge
        if check != proof.0 || hashed_message != proof.1 {
            return Err(NIZKError::DLKVerify);
        }

        Ok(())
    }
}


/* Unit tests: */


#[cfg(test)]
mod test {
    use crate::signature::utils::tests::check_serialization;
    use crate::nizk::{dlk::{DLKProof, srs::SRS}, scheme::NIZKProof};

    use ark_ff::{PrimeField, UniformRand};
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::{AffineCurve, ProjectiveCurve};

    use rand::thread_rng;

    #[test]
    fn test_simple_nizk_g1() {
        test_simple_nizk::<G1Affine>();
    }

    #[test]
    fn test_simple_nizk_g2() {
        test_simple_nizk::<G2Affine>();
    }

    fn test_simple_nizk<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let dlk = DLKProof { srs };
        let pair = dlk.generate_pair(rng).unwrap();

        let proof = dlk.prove(rng, &pair.0).unwrap();
        dlk
            .verify(&pair.1, &proof)
            .unwrap();
    }


    #[test]
    #[should_panic]
    fn test_simple_nizk_wrong_statement_g1() {
        test_simple_nizk_wrong_statement::<G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_wrong_statement_g2() {
        test_simple_nizk_wrong_statement::<G2Affine>();
    }

    fn test_simple_nizk_wrong_statement<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let dlk = DLKProof { srs };
        let pair = dlk.generate_pair(rng).unwrap();

        let proof = dlk.prove(rng, &pair.0).unwrap();

        let pair2 = dlk.generate_pair(rng).unwrap();
        dlk
            .verify(&pair2.1, &proof)
            .unwrap();
    }


    // Tests for malformed proofs:


    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_commitment_g1() {
        test_simple_nizk_malformed_commitment::<G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_commitment_g2() {
        test_simple_nizk_malformed_commitment::<G2Affine>();
    }

    fn test_simple_nizk_malformed_commitment<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let dlk = DLKProof { srs };
        let pair = dlk.generate_pair(rng).unwrap();

        let (_, c, z) = dlk.prove(rng, &pair.0).unwrap();

	let new_commitment = dlk.srs.g_public_key.mul(C::ScalarField::rand(rng).into_repr()).into_affine();
	let malformed_proof = (new_commitment, c, z);

        dlk
            .verify(&pair.1, &malformed_proof)
            .unwrap();
    }


    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_challenge_g1() {
        test_simple_nizk_malformed_challenge::<G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_challenge_g2() {
        test_simple_nizk_malformed_challenge::<G2Affine>();
    }

    fn test_simple_nizk_malformed_challenge<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let dlk = DLKProof { srs };
        let pair = dlk.generate_pair(rng).unwrap();

        let (g_r, _, z) = dlk.prove(rng, &pair.0).unwrap();

        let new_challenge = C::ScalarField::rand(rng);
	let malformed_proof = (g_r, new_challenge, z);

        dlk
            .verify(&pair.1, &malformed_proof)
            .unwrap();
    }


    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_response_g1() {
        test_simple_nizk_malformed_response::<G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_response_g2() {
        test_simple_nizk_malformed_response::<G2Affine>();
    }

    fn test_simple_nizk_malformed_response<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let dlk = DLKProof { srs };
        let pair = dlk.generate_pair(rng).unwrap();

        let (g_r, c, _) = dlk.prove(rng, &pair.0).unwrap();

	let new_response = C::ScalarField::rand(rng);
	let malformed_proof = (g_r, c, new_response);

        dlk
	    .verify(&pair.1, &malformed_proof)
            .unwrap();
    }


    #[test]
    fn test_serialization_g1() {
        test_serialization::<G1Affine>();
    }

    #[test]
    fn test_serialization_g2() {
        test_serialization::<G2Affine>();
    }

    fn test_serialization<C: AffineCurve>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C>::setup(rng).unwrap();
        let dlk = DLKProof { srs: srs.clone() };
        let pair = dlk.generate_pair(rng).unwrap();

        let proof = dlk.prove(rng, &pair.0).unwrap();

        check_serialization(srs.clone());
        check_serialization(pair.clone());
        check_serialization(proof.clone());
    }

}
