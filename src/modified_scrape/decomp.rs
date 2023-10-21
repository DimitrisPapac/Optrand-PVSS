use crate::{
    ComGroup,
    Digest,
    modified_scrape::{config::Config, errors::PVSSError},
    nizk::{dlk::{DLKProof, srs::SRS as DLKSRS}, scheme::NIZKProof},
    Scalar,
};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::fmt::Debug;

use rand::Rng;
use std::{
    hash::{Hash, Hasher},
    io::Cursor,
    marker::PhantomData,
};

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};


pub type ProofGroup<E> = ComGroup<E>;     // the group over which the decomposition proof is computed
pub type ProofType<E> = DecompProof<E>;   // the type of output decomposition proofs

// Struct Decomp models the Decomposition proof system.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct Decomp<E: PairingEngine> {
    pairing_engine: PhantomData<E>,   // cache E
}

// Struct DecompProof models the actual decomposition proof.
#[derive(Clone, Copy, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DecompProof<E: PairingEngine> {
    pub proof: <DLKProof<ProofGroup<E>> as NIZKProof>::Proof,   // the proof of knowledge of discrete log
    pub gs: ProofGroup<E>,                                      // the associated public statement (i.e., commitment to the secret)
}

impl<E: PairingEngine> Decomp<E> {

    // Associated function for generating decomposition proofs.
    pub fn generate<R: Rng>(rng: &mut R,
                            config: &Config<E>,
			    p_0: &Scalar<E>) -> Result<ProofType<E>, PVSSError<E>> {
	let secret = p_0;
	let generator = config.srs.g2;
	let gs = generator.mul(secret.into_repr()).into_affine();

	let dlk_srs = DLKSRS::<ProofGroup::<E>> { g_public_key: generator };
	let dlk = DLKProof { srs: dlk_srs };   // initialize proof system for DLK NIZKs.

	let proof = dlk.prove(rng, secret).unwrap();

	Ok(DecompProof { proof, gs })
    }
}


impl<E: PairingEngine> Hash for DecompProof<E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.proof.hash(state);
        self.gs.hash(state);
    }
}


impl<E: PairingEngine> DecompProof<E> {

    // Method for verifying decomposition proofs under some configuration.
    pub fn verify(&self, config: &Config<E>) -> Result<(), PVSSError<E>> {
	// Create a proof system for proving knowledge of discrete log
	let dlk = DLKProof { srs: DLKSRS::<ProofGroup::<E>> { g_public_key: config.srs.g2 } };

	// If you intercept a NIZKError, return a PVSSError variant.
	if dlk.verify(&self.gs, &self.proof)
		  .is_err() {
	    return Err(PVSSError::NIZKProofDoesNotVerifyError);
	}

	Ok(())
    }

    pub fn digest(&mut self) -> Digest {
        let mut hasher = Shake256::default();

        let mut proof_bytes = vec![];
        let _ = self.proof.serialize(&mut proof_bytes);

        let mut gs_bytes = vec![];
        let _ = self.gs.serialize(&mut gs_bytes);

        let data = &[&proof_bytes[..], &gs_bytes[..]].concat();

        hasher.update(data);

        let mut reader = hasher.finalize_xof();
        let mut arr = [0_u8; 32];
        XofReader::read(&mut reader, &mut arr);

        Digest(arr)
    }
}


// Utility function for buffering a decomposition proof into a buffer and
// obtaining a reference to said buffer.
pub fn message_from_pi_i<E: PairingEngine>(pi_i: DecompProof<E>) -> Result<Vec<u8>, PVSSError<E>> {
    let mut message_writer = Cursor::new(vec![]);
    pi_i.serialize(&mut message_writer)?;
    Ok(message_writer.get_ref().to_vec())
}


/* Unit tests: */

#[cfg(test)]
mod test {
    use crate::{
        modified_scrape::{
            config::Config,
            decomp::{Decomp, DecompProof},
            poly::Polynomial,
            srs::SRS,
        },
        Scalar,
        signature::utils::tests::check_serialization,
    };

    use ark_bls12_381::Bls12_381 as E;   // implements PairingEngine
    use ark_poly::UVPolynomial;
    use ark_std::UniformRand;

    use rand::thread_rng;


    #[test]
    fn test_simple_decomp_proof() {
        let rng = &mut thread_rng();
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS

	let t = 3;
	let n = 10;
	let conf = Config { srs, degree: t, num_participants: n };
	let poly = Polynomial::<E>::rand(t, rng);

	let dproof = Decomp::<E>::generate(rng, &conf, &poly.coeffs[0]).unwrap();

	dproof.verify(&conf).unwrap()
    }

    #[test]
    #[should_panic]
    fn test_invalid_decomp_proof() {
        let rng = &mut thread_rng();
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS

        let t = 3;
        let n = 10;
        let conf = Config { srs, degree: t, num_participants: n };
        let poly = Polynomial::<E>::rand(t, rng);

        let mut dproof = Decomp::<E>::generate(rng, &conf, &poly.coeffs[0]).unwrap();

        // Malform the proof
        dproof.proof.1 = Scalar::<E>::rand(rng);

        // Create a "bad" proof
        let dproof_bad = DecompProof { proof: dproof.proof, gs: dproof.gs };
        
        dproof_bad.verify(&conf).unwrap();   // PVSSError::NIZKProofDoesNotVerifyError
    }

    #[test]
    fn test_serialization_decomp_proof() {
        let rng = &mut thread_rng();
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS

	let t = 3;
	let n = 10;
	let conf = Config { srs, degree: t, num_participants: n };
	let poly = Polynomial::<E>::rand(t, rng);

	let dproof = Decomp::<E>::generate(rng, &conf, &poly.coeffs[0]).unwrap();

        check_serialization(dproof.clone());
    }

}
