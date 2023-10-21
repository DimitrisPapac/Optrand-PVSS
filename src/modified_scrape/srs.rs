use crate::{
    ComGroup,
    ComGroupP,
    EncGroup,
    EncGroupP,
    modified_scrape::errors::PVSSError,
};

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;

use rand::Rng;

/* The Structured Reference String (SRS) of the Optrand-based PVSS scheme. */

#[derive(Clone)]
pub struct SRS<E: PairingEngine> {
    pub g1: EncGroup<E>,        // generator g_1 of the public key group G_1
    pub g2: ComGroup<E>,        // generator g_2 of the commitment group G_2
    pub g2_prime: ComGroup<E>   // generator g_2_prime of the commitment group G_2
}

impl<E: PairingEngine> SRS<E> {

    // Function setup generates an SRS instance using a specified RNG.
    pub fn setup<R: Rng>(rng: &mut R) -> Result<Self, PVSSError<E>> {
        Ok(Self {
            g1: EncGroupP::<E>::rand(rng).into_affine(),
            g2: ComGroupP::<E>::rand(rng).into_affine(),
            g2_prime: ComGroupP::<E>::rand(rng).into_affine(),
        })
    }
}
