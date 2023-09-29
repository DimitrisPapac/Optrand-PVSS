use crate::nizk::utils::errors::NIZKError;
use ark_ec::AffineCurve;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use rand::Rng;

use std::hash::Hash;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize, Clone, PartialEq, Hash)]
pub struct SRS<C: AffineCurve> {
    pub g_public_key: C,   // group generator
}

impl<C: AffineCurve> SRS<C> {

    // Function setup samples the SRS generator
    pub fn setup<R: Rng>(_: &mut R) -> Result<Self, NIZKError> {
        let srs = Self {
            g_public_key: C::prime_subgroup_generator(),
        };
        Ok(srs)
    }
}
