use super::{poly::Polynomial, config::Config};
use crate::signature::schnorr::srs::SRS as DLKSRS;

use crate::nizk::{dlk::DLKProof, scheme::NIZKProof};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use std::marker::PhantomData;
use rand::Rng;
use ark_serialize::*;
use ark_std::fmt::Debug;

type ProofGroup<E> = <E as PairingEngine>::G2Affine;   // the group over which the proof is computed
type ProofType<E> = DecompProof<ProofGroup<E>>;        // the type we want the proof to be

// Struct Decomp models the Decomposition proof system.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct Decomp<E: PairingEngine> {
    pairing_engine: PhantomData<E>,   // caches E
}

// Struct DecompProof models the actual decomposition proof.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DecompProof<G: AffineCurve> {
    pub pi: <DLKProof<G> as NIZKProof>::Proof,   // the proof of knowledge of discrete log
    pub gs: G,                                   // the associated public statement (i.e., commitment to the secret)
}

impl<E: PairingEngine> Decomp<E> {

    // Associated function for generating decomposition proofs.
    pub fn generate<R: Rng>(rng: &mut R, config: &Config<E>, poly: &Polynomial<E>) -> ProofType<E> {   // TODO: Change to Result<...>
        let secret = poly.coeffs[0];
	let generator = config.srs.g2;
	let gs = generator.mul(secret.into_repr()).into_affine();

	let dlk_srs = DLKSRS::<ProofGroup::<E>> { g_public_key: generator };   // maybe generator.clone()???
	let dlk = DLKProof { srs: dlk_srs };   // initialize proof system for DLK NIZKs.

	// Double-check with Adithya's code for Dleq for increased efficiency/security.
	let pi = dlk.prove(rng, &secret).unwrap();

	DecompProof { pi, gs }
    }
}


/* Unit tests: */

#[cfg(test)]
mod test {

    use ark_bls12_381::{Bls12_381 as E};   // implements PairingEngine
    //use ark_bls12_381::{G1Affine, G2Affine as C};
    //use ark_ec::{AffineCurve, ProjectiveCurve, PairingEngine};
    use ark_poly::UVPolynomial;

    use crate::signature::{schnorr::srs::SRS as DLKSRS, utils::tests::check_serialization};
    use crate::nizk::{dlk::DLKProof, scheme::NIZKProof};
    use crate::modified_scrape::{decomp::Decomp, srs::SRS, poly::Polynomial, config::Config};

    use rand::thread_rng;

    #[test]
    fn test_simple_decomp_proof() {
        let rng = &mut thread_rng();
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS

	let t = 3;
	let n = 10;
	let conf = Config { srs, degree: t, num_replicas: n };
	let poly = Polynomial::<E>::rand(t, rng);

	let dproof = Decomp::<E>::generate(rng, &conf, &poly);

	let dlk = DLKProof { srs: DLKSRS { g_public_key: conf.srs.g2 } };   // This is ugly...

        dlk
           .verify(&dproof.gs, &dproof.pi)
           .unwrap()
    }

    #[test]
    fn test_serialization_decomp_proof() {
        let rng = &mut thread_rng();
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS

	let t = 3;
	let n = 10;
	let conf = Config { srs, degree: t, num_replicas: n };
	let poly = Polynomial::<E>::rand(t, rng);

	let dproof = Decomp::<E>::generate(rng, &conf, &poly);

        check_serialization(dproof.clone());
    }

}