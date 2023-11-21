use crate::nizk::{
    scheme::NIZKProof, 
    utils::{errors::NIZKError, hash::hash_to_field},
    dleq::srs::SRS
};

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use rand::Rng;
use std::fmt::Debug;

pub mod srs;

const PERSONALIZATION: &[u8] = b"DLEQNIZK";   // persona for the DLEQ NIZK proof system


// DLEQProof type wraps around the SRS and represents the scheme's
// system-wide parameters.
#[derive(Clone, Debug, PartialEq)]
pub struct DLEQProof<C1, C2>
where 
    C1: AffineCurve + CanonicalSerialize + CanonicalDeserialize,
    C2: AffineCurve<ScalarField = C1::ScalarField> + CanonicalSerialize + CanonicalDeserialize,
{
    pub srs: SRS<C1, C2>
}


// DLEQProof implements the NIZKProof trait.
impl<C1: AffineCurve, C2: AffineCurve> NIZKProof for DLEQProof<C1, C2> 
where 
    C1: AffineCurve + CanonicalSerialize + CanonicalDeserialize,
    C2: AffineCurve<ScalarField = C1::ScalarField> + CanonicalSerialize + CanonicalDeserialize,
{
    type SRS = SRS<C1, C2>;                                    		// SRS is a pair of group generators (i.e., EC points)
    type Witness = C1::ScalarField;                            		// witnessess are scalars from the field underlying C1 and C2
    type Challenge = C1::ScalarField;			      		// challenges are scalars from the field underlying C1 and C2
    type Statement = (C1, C2);                                 		// public statements are pairs of elliptic curve points
    type Proof = (Self::Statement, Self::Challenge, C1::ScalarField);   // proof format: ((G_1 commitment to nonce, G_2 commitment to nonce), challenge, response)

    // Creates a DLEQProof from a given SRS.
    fn from_srs(srs: Self::SRS) -> Result<Self, NIZKError> {
        Ok(Self { srs })
    }

    // Generates a witness-statement pair using a specified RNG.
    fn generate_pair<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Witness, Self::Statement), NIZKError> {
        let w = Self::Witness::rand(rng);
        Ok((w, (self.srs.g_public_key.mul(w.into_repr()).into_affine(), self.srs.h_public_key.mul(w.into_repr()).into_affine())))
    }

    // Computes a witness-statement pair, given only the witness.
    fn from_witness(
        &self,
        w: &Self::Witness,
    ) -> Result<(Self::Witness, Self::Statement), NIZKError> {
        Ok((*w, (self.srs.g_public_key.mul(w.into_repr()).into_affine(), self.srs.h_public_key.mul(w.into_repr()).into_affine())))
    }

    // Function for generating a NIZK proof of discrete logarithm equality.
    fn prove<R: Rng>(
        &self,
        rng: &mut R,
        w: &Self::Witness,
    ) -> Result<Self::Proof, NIZKError> {

	// Compute the public key corresponding to generator g of the first group
	let g_w = self.srs.g_public_key.mul(w.into_repr()).into_affine();

	// Compute the public key corresponding to generator h of the second group
	let h_w = self.srs.h_public_key.mul(w.into_repr()).into_affine();

        // Sample a random nonce
        let r = Self::Witness::rand(rng);

        // Compute commitment to nonce as: g_r := r * g
        let g_r = self.srs.g_public_key.mul(r.into_repr()).into_affine();

	// Compute commitment to nonce as: h_r := r * h
        let h_r = self.srs.h_public_key.mul(r.into_repr()).into_affine();

        // serialize g_r into writer g_r_bytes
        let mut g_r_bytes = vec![];
        g_r.serialize(&mut g_r_bytes)?;

	// serialize h_r into writer h_r_bytes
        let mut h_r_bytes = vec![];
        h_r.serialize(&mut h_r_bytes)?;

        // serialize g into writer g_bytes
        let mut g_bytes = vec![];
        self.srs.g_public_key.serialize(&mut g_bytes)?;

	// serialize h into writer h_bytes
        let mut h_bytes = vec![];
        self.srs.h_public_key.serialize(&mut h_bytes)?;

	// serialize g_w into writer g_w_bytes
        let mut g_w_bytes = vec![];
        g_w.serialize(&mut g_w_bytes)?;

	// serialize h_w into writer h_w_bytes
        let mut h_w_bytes = vec![];
        h_w.serialize(&mut h_w_bytes)?;

        // Compute the "challenge" part of the proof
        let hashed_message = hash_to_field::<Self::Challenge>(
            PERSONALIZATION, &[&g_bytes[..], &g_w_bytes, &h_bytes, &h_w_bytes, &g_r_bytes, &h_r_bytes].concat()
        )?;

        // Compute the "response" part of the proof
        let z = r - (*w * hashed_message);

        // Form and return the result
	let proof = ((g_r, h_r), hashed_message, z);
        Ok(proof)
    }

    // Function for verifying a NIZK proof of discrete logarithm equality.
    fn verify(
        &self,
        statement: &Self::Statement,
        proof: &Self::Proof,
    ) -> Result<(), NIZKError> {

	// parse nonce commitments from the supplied proof
	let (g_r, h_r) = proof.0;

	// serialize g_w into g_w_bytes
	let mut g_w_bytes = vec![];
	statement.0.serialize(&mut g_w_bytes)?;

	// serialize h_w into h_w_bytes
	let mut h_w_bytes = vec![];
	statement.1.serialize(&mut h_w_bytes)?;

        // serialize g into writer g_bytes
        let mut g_bytes = vec![];
        self.srs.g_public_key.serialize(&mut g_bytes)?;

	// serialize h into writer h_bytes
        let mut h_bytes = vec![];
        self.srs.h_public_key.serialize(&mut h_bytes)?;

	// serialize g_r into writer g_r_bytes
	let mut g_r_bytes = vec![];
        g_r.serialize(&mut g_r_bytes)?;

	// serialize h_r into writer h_r_bytes
	let mut h_r_bytes = vec![];
        h_r.serialize(&mut h_r_bytes)?;

	// compute the challenge corresponding to what was provided
        let hashed_message = hash_to_field::<Self::Challenge>(
            PERSONALIZATION, &[&g_bytes[..], &g_w_bytes, &h_bytes, &h_w_bytes, &g_r_bytes, &h_r_bytes].concat()
        )?;

	/* By construction, the verification conditions are:
	 * g*z + (g*w)*c == g*r
	 * h*z + (h*w)*c == h*r
	 */

	// compute LHS of the first verification condition
	let lhs1 = (self.srs.g_public_key.mul(proof.2.into_repr())
            + statement.0.mul(hashed_message.into_repr()))
            .into_affine();

	// compute RHS of the first verification condition
	let rhs1 = g_r;

	// compute LHS of the second verification condition
	let lhs2 = (self.srs.h_public_key.mul(proof.2.into_repr())
            + statement.1.mul(hashed_message.into_repr()))
            .into_affine();

	// compute RHS of the second verification condition
	let rhs2 = h_r;

	// Compare LHSs against their respective RHSs and ensure
	// the computed challenge matches the supplied challenge
        if lhs1 != rhs1 || lhs2 != rhs2 || hashed_message != proof.1 {
            return Err(NIZKError::DLEQVerify);
        }

        Ok(())
    }
}



#[cfg(test)]
mod test {
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_ec::{AffineCurve, ProjectiveCurve};

    use crate::signature::utils::tests::check_serialization;
    use crate::nizk::scheme::NIZKProof;
    use crate::nizk::dleq::{DLEQProof, srs::SRS};

    use rand::thread_rng;
    use ark_ff::{PrimeField, UniformRand};

    #[test]
    fn test_simple_nizk_g1_g1() {
        test_simple_nizk::<G1Affine, G1Affine>();
    }

    #[test]
    fn test_simple_nizk_g1_g2() {
        test_simple_nizk::<G1Affine, G2Affine>();
    }

    #[test]
    fn test_simple_nizk_g2_g1() {
        test_simple_nizk::<G2Affine, G1Affine>();
    }

    #[test]
    fn test_simple_nizk_g2_g2() {
        test_simple_nizk::<G2Affine, G2Affine>();
    }


    fn test_simple_nizk<C1: AffineCurve, C2: AffineCurve<ScalarField = C1::ScalarField>>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C1, C2>::setup(rng).unwrap();
        let dleq = DLEQProof { srs };
        let pair = dleq.generate_pair(rng).unwrap();

        // let stmnt = dleq.from_witness(&pair.0).unwrap();

        let proof: ((C1, C2), <C1 as AffineCurve>::ScalarField, <C1 as AffineCurve>::ScalarField) = dleq.prove(rng, &pair.0).unwrap();
        dleq
            .verify(&pair.1, &proof)
            .unwrap();
    }


    #[test]
    #[should_panic]
    fn test_simple_nizk_wrong_statement_g1_g1() {
        test_simple_nizk_wrong_statement::<G1Affine, G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_wrong_statement_g1_g2() {
        test_simple_nizk_wrong_statement::<G1Affine, G2Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_wrong_statement_g2_g1() {
        test_simple_nizk_wrong_statement::<G2Affine, G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_wrong_statement_g2_g2() {
        test_simple_nizk_wrong_statement::<G2Affine, G2Affine>();
    }

    fn test_simple_nizk_wrong_statement<C1: AffineCurve, C2: AffineCurve<ScalarField = C1::ScalarField>>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C1, C2>::setup(rng).unwrap();
        let dleq = DLEQProof { srs };
        let pair = dleq.generate_pair(rng).unwrap();

        let proof = dleq.prove(rng, &pair.0).unwrap();

        let pair2 = dleq.generate_pair(rng).unwrap();
        dleq
            .verify(&pair2.1, &proof)
            .unwrap();
    }


    // Tests with malformed proofs:


    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_commitment_g1_g1() {
        test_simple_nizk_malformed_commitment::<G1Affine, G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_commitment_g1_g2() {
        test_simple_nizk_malformed_commitment::<G1Affine, G2Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_commitment_g2_g1() {
        test_simple_nizk_malformed_commitment::<G2Affine, G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_commitment_g2_g2() {
        test_simple_nizk_malformed_commitment::<G2Affine, G2Affine>();
    }

    fn test_simple_nizk_malformed_commitment<C1: AffineCurve, C2: AffineCurve<ScalarField = C1::ScalarField>>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C1, C2>::setup(rng).unwrap();
        let dleq = DLEQProof { srs };
        let pair = dleq.generate_pair(rng).unwrap();

        let (_, c, z) = dleq.prove(rng, &pair.0).unwrap();

	let new_commitment = (dleq.srs.g_public_key.mul(C1::ScalarField::rand(rng).into_repr()).into_affine(),
			      dleq.srs.h_public_key.mul(C1::ScalarField::rand(rng).into_repr()).into_affine());
	let malformed_proof = (new_commitment, c, z);

        dleq
            .verify(&pair.1, &malformed_proof)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_challenge_g1_g1() {
        test_simple_nizk_malformed_challenge::<G1Affine, G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_challenge_g1_g2() {
        test_simple_nizk_malformed_challenge::<G1Affine, G2Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_challenge_g2_g1() {
        test_simple_nizk_malformed_challenge::<G2Affine, G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_challenge_g2_g2() {
        test_simple_nizk_malformed_challenge::<G2Affine, G2Affine>();
    }


    fn test_simple_nizk_malformed_challenge<C1: AffineCurve, C2: AffineCurve<ScalarField = C1::ScalarField>>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C1, C2>::setup(rng).unwrap();
        let dleq = DLEQProof { srs };
        let pair = dleq.generate_pair(rng).unwrap();

        let (comms, _, z) = dleq.prove(rng, &pair.0).unwrap();

        let new_challenge = C1::ScalarField::rand(rng);
	    let malformed_proof = (comms, new_challenge, z);

        dleq
            .verify(&pair.1, &malformed_proof)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_response_g1_g1() {
        test_simple_nizk_malformed_response::<G1Affine, G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_response_g1_g2() {
        test_simple_nizk_malformed_response::<G1Affine, G2Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_response_g2_g1() {
        test_simple_nizk_malformed_response::<G2Affine, G1Affine>();
    }

    #[test]
    #[should_panic]
    fn test_simple_nizk_malformed_response_g2_g2() {
        test_simple_nizk_malformed_response::<G2Affine, G2Affine>();
    }

    fn test_simple_nizk_malformed_response<C1: AffineCurve, C2: AffineCurve<ScalarField = C1::ScalarField>>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C1, C2>::setup(rng).unwrap();
        let dleq = DLEQProof { srs };
        let pair = dleq.generate_pair(rng).unwrap();

        let (comms, c, _) = dleq.prove(rng, &pair.0).unwrap();

	let new_response = C1::ScalarField::rand(rng);
	let malformed_proof = (comms, c, new_response);

        dleq
            .verify(&pair.1, &malformed_proof)
            .unwrap();
    }


    #[test]
    fn test_serialization_g1_g1() {
        test_serialization::<G1Affine, G1Affine>();
    }

    #[test]
    fn test_serialization_g1_g2() {
        test_serialization::<G1Affine, G2Affine>();
    }

    #[test]
    fn test_serialization_g2_g1() {
        test_serialization::<G2Affine, G1Affine>();
    }

    #[test]
    fn test_serialization_g2_g2() {
        test_serialization::<G2Affine, G2Affine>();
    }

    fn test_serialization<C1: AffineCurve, C2: AffineCurve<ScalarField = C1::ScalarField>>() {
        let rng = &mut thread_rng();
        let srs = SRS::<C1, C2>::setup(rng).unwrap();
        let dleq = DLEQProof { srs: srs.clone() };
        let pair = dleq.generate_pair(rng).unwrap();

        let proof = dleq.prove(rng, &pair.0).unwrap();

        check_serialization(srs.clone());
        check_serialization(pair.clone());
        check_serialization(proof.clone());
    }



    #[test]
    fn test_benchmark_g1_g2() {
	use std::time::Instant;
	let now = Instant::now();

        test_benchmark::<G1Affine, G2Affine>();

	let elapsed = now.elapsed();
    	println!("Elapsed time for 1 DLEQ: {:.2?}", elapsed);

	assert_eq!(2+2, 4);
    }

    #[test]
    fn test_benchmark_g2_g1() {
        use std::time::Instant;
	let now = Instant::now();

        test_benchmark::<G2Affine, G1Affine>();

	let elapsed = now.elapsed();
    	println!("Elapsed time for 1 DLEQ: {:.2?}", elapsed);

	assert_eq!(2+2, 4);
    }


    #[test]
    fn test_benchmark_g1_g2_64() {
	use std::time::Instant;
	let now = Instant::now();

	for _ in 0..64 {
            test_benchmark::<G1Affine, G2Affine>();
	}

	let elapsed = now.elapsed();
    	println!("Elapsed time for 64 DLEQs: {:.2?}", elapsed);

	assert_eq!(2+2, 4);
    }

    #[test]
    fn test_benchmark_g2_g1_64() {
	use std::time::Instant;
	let now = Instant::now();

	for _ in 0..64 {
            test_benchmark::<G2Affine, G1Affine>();
	}

	let elapsed = now.elapsed();
    	println!("Elapsed time for 64 DLEQs: {:.2?}", elapsed);

	assert_eq!(2+2, 4);
    }

    
    fn test_benchmark<C1: AffineCurve, C2: AffineCurve<ScalarField = C1::ScalarField>>() {
	let rng = &mut thread_rng();
        let srs = SRS::<C1, C2>::setup(rng).unwrap();
        let dleq = DLEQProof { srs };
        let pair = dleq.generate_pair(rng).unwrap();

        // let stmnt = dleq.from_witness(&pair.0).unwrap();

        let proof: ((C1, C2), <C1 as AffineCurve>::ScalarField, <C1 as AffineCurve>::ScalarField) = dleq.prove(rng, &pair.0).unwrap();
        dleq
            .verify(&pair.1, &proof)
            .unwrap();
    }
}
