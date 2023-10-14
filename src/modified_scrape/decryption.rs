use crate::Scalar;
use ark_ec::{PairingEngine, AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField};


// Struct DecryptedShare represents a decrypted share obtained when a node cancels out its secret
// key from some given encrypted share.
// NOTE: It should be noted that without the use of DLEQs, it is not possible to define verification
// of decryptions.
#[derive(Clone)]
pub struct DecryptedShare<E: PairingEngine> {
    pub dec: E::G1Affine,   // the decrypted share
    pub origin: usize,      // index in the pk_map
}

impl<E: PairingEngine> DecryptedShare<E> {

    // Associated function for generating a decrypted share from a given encrypted share.
    pub fn generate(enc: &E::G1Affine, sk: &Scalar<E>, my_id: usize) -> DecryptedShare<E> {
        // dec := enc * sk^{-1}
        let dec = enc.mul(sk.inverse().unwrap().into_repr()).into_affine();

    	DecryptedShare {dec, origin: my_id}
    }
}
