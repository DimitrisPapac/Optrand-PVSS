use crate::nizk::utils::errors::NIZKError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use std::fmt::Debug;

// NIZK proof systems must implement the NIZKProof trait.
pub trait NIZKProof: Debug + Clone + PartialEq + Sized {
    type SRS: Clone;                                                     // proof system's associated SRS
    type Witness;                                                        // type for secret witnesses
    type Challenge;							 // type for challenges/challenge space
    type Statement: Clone + CanonicalSerialize + CanonicalDeserialize;   // type for public statements
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize;       // type for statements

    // Function for setting parameters given an input SRS.
    fn from_srs(srs: Self::SRS) -> Result<Self, NIZKError>;

    // Method for generating a witness, statement pair by sampling an input RNG.
    fn generate_pair<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Witness, Self::Statement), NIZKError>;

    // Method for computing a key pair, given only the secret key.
    fn from_witness(&self, w: &Self::Witness)
        -> Result<(Self::Witness, Self::Statement), NIZKError>;

    // Method for creating a proof for a statement, using witness w, and a specified RNG.
    fn prove<R: Rng>(
        &self,
        rng: &mut R,
        w: &Self::Witness,
    ) -> Result<Self::Proof, NIZKError>;

    // Method for verifying a given proof against a public statement stmnt.
    fn verify(
        &self,
        stmnt: &Self::Statement,
        proof: &Self::Proof,
    ) -> Result<(), NIZKError>;
}
