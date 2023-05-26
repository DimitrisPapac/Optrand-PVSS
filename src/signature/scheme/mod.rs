use crate::signature::utils::errors::SignatureError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use std::fmt::Debug;

// All signature schemes must implement the SignatureScheme trait.
pub trait SignatureScheme: Debug + Clone + PartialEq + Sized {
    type SRS: Clone;                                                     // scheme's associated SRS
    type Secret;                                                         // type for secret keys
    type PublicKey: Clone + CanonicalSerialize + CanonicalDeserialize;   // type for public keys
    type Signature: Clone + CanonicalSerialize + CanonicalDeserialize;   // type for signatures

    // Function for setting parameters given an input SRS.
    fn from_srs(srs: Self::SRS) -> Result<Self, SignatureError>;

    // Method for generating a key pair by sampling an input RNG.
    fn generate_keypair<R: Rng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::Secret, Self::PublicKey), SignatureError>;

    // Method for computing a key pair, given only the secret key.
    fn from_sk(&self, sk: &Self::Secret)
               -> Result<(Self::Secret, Self::PublicKey), SignatureError>;

    // Method for creating a digital signature on an
    // input message, using the signer's secret key, and a
    // specified RNG.
    fn sign<R: Rng>(
        &self,
        rng: &mut R,
        sk: &Self::Secret,
        message: &[u8],
    ) -> Result<Self::Signature, SignatureError>;

    // Method for verifying a digital signature on an
    // input message, w.r.t. the signer's public key.
    fn verify(
        &self,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), SignatureError>;
}

// All signature schemes that support aggregation must implement
// the AggregatableSignatureScheme trait.
pub trait AggregatableSignatureScheme: SignatureScheme {

    // Method for aggregating public keys.
    fn aggregate_public_keys(
        &self,
        public_keys: &[&Self::PublicKey],
    ) -> Result<Self::PublicKey, SignatureError>;

    // Method for aggregating signatures.
    fn aggregate_signatures(
        &self,
        signatures: &[&Self::Signature],
    ) -> Result<Self::Signature, SignatureError>;
}

// All signature schemes that support batch verification must implement
// the BatchVerifiableSignatureScheme trait.
pub trait BatchVerifiableSignatureScheme: SignatureScheme {

    // Method for allowing batch verification of a slice of signatures,
    // w.r.t. matching pablic keys and messages.
    fn batch_verify<R: Rng>(
        &self,
        rng: &mut R,
        public_keys: &[&Self::PublicKey],
        messages: &[&[u8]],
        signatures: &[&Self::Signature],
    ) -> Result<(), SignatureError>;
}
