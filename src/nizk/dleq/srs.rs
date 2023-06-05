use crate::nizk::utils::errors::NIZKError;
use ark_ec::AffineCurve;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};

use rand::Rng;

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize, Clone, PartialEq)]
pub struct SRS<C1, C2>
where 
    C1: AffineCurve + CanonicalSerialize + CanonicalDeserialize,
    C2: AffineCurve<ScalarField = C1::ScalarField> + CanonicalSerialize + CanonicalDeserialize
{
    pub g_public_key: C1,   // first group generator
    pub h_public_key: C2,   // second group generator
}

impl<C1, C2> SRS<C1, C2> 
where 
    C1: AffineCurve + CanonicalSerialize + CanonicalDeserialize,
    C2: AffineCurve<ScalarField = C1::ScalarField> + CanonicalSerialize + CanonicalDeserialize
{

    // Function setup samples the SRS generators
    pub fn setup<R: Rng>(_: &mut R) -> Result<Self, NIZKError> {
        let srs = Self {
            g_public_key: C1::prime_subgroup_generator(),
	    h_public_key: C2::prime_subgroup_generator(),
        };
        Ok(srs)
    }
}
