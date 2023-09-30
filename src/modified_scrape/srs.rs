use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;
use crate::modified_scrape::errors::PVSSError;
use rand::Rng;

/* The Structured Reference String (SRS) of the modified SCRAPE PVSS scheme. */

#[derive(Clone)]
pub struct SRS<E: PairingEngine> {
    pub g1: E::G1Affine,        // generator g_1 of the public key group G_1
    pub g2: E::G2Affine,        // generator g_2 of the commitment group G_2
    pub g2_prime: E::G2Affine   // generator g_2_prime of the commitment group G_2
}

impl<E: PairingEngine> SRS<E> {

    // Function setup generates an SRS instance using a specified RNG.
    pub fn setup<R: Rng>(rng: &mut R) -> Result<Self, PVSSError<E>> {
        Ok(Self {
            g1: E::G1Projective::rand(rng).into_affine(),
            g2: E::G2Projective::rand(rng).into_affine(),
            g2_prime: E::G2Projective::rand(rng).into_affine(),
        })
    }
}
