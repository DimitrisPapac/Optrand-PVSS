#[macro_use]
extern crate ark_std;

pub mod modified_scrape;
pub mod signature;
pub mod nizk;

use ark_ec::PairingEngine;

// EdDSA imports

use ed25519_dalek as dalek;
use ed25519_dalek::ed25519;
use ed25519_dalek::Signer as _;
use rand::{CryptoRng, RngCore, rngs::OsRng};
use std::{array::TryFromSliceError, convert::{TryFrom, TryInto}, fmt};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError, Read, Write};


// The scalar field of the pairing groups
pub type Scalar<E> = <E as PairingEngine>::Fr;

// The group of commitments
pub type ComGroup<E> = <E as PairingEngine>::G2Affine;
pub type ComGroupP<E> = <E as PairingEngine>::G2Projective;

// Keys
pub type SecKey<E> = Scalar<E>;
pub type PubKey<E> = <E as PairingEngine>::G1Affine;
pub type PubKeyP<E> = <E as PairingEngine>::G1Projective;

// The Encryption group is the same as the public key group.
// Which is G1 for type 3 pairings.
pub type EncGroup<E> = PubKey<E>;
pub type EncGroupP<E> = PubKeyP<E>;

// The target group GT of the pairing
pub type GT<E> = <E as PairingEngine>::Fqk;


// EdDSA definitions

pub type CryptoError = ed25519::Error;


#[derive(Hash, PartialEq, Default, Eq, Clone)]
pub struct Digest(pub [u8; 32_usize]);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(self.0).get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest(item.try_into()?))
    }
}

impl CanonicalSerialize for Digest {
    #[inline]
    fn serialize<W: Write>(
    &self,
    mut writer: W,
    ) -> Result<(), SerializationError> {
        for item in self.0.iter() {
            item.serialize(&mut writer)?;
        }

	Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.0.iter()
            .map(|item| item.serialized_size())
            .sum::<usize>()
    }
}

impl CanonicalDeserialize for Digest {
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let result = Digest( core::array::from_fn(|_| {
            u8::deserialize(&mut reader).unwrap()
        }) );

        Ok(result)
    }
}

pub trait Hash {
    fn digest(&self) -> Digest;
}

/* Struct PublicKey models the public (verification) key for the EdDSA signature scheme. */

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub struct PublicKey(pub [u8; 32_usize]);

impl PublicKey {
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn from_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;

        Ok(Self(array))
    }
}

impl CanonicalSerialize for PublicKey {
    #[inline]
    fn serialize<W: Write>(
    &self,
    mut writer: W,
    ) -> Result<(), SerializationError> {
	// self.0.serialize_with_mode(&mut writer, compress)
        for item in self.0.iter() {
            item.serialize(&mut writer)?;
        }

	Ok(())
    }

    fn serialized_size(&self) -> usize {
	    self.0.iter()
            .map(|item| item.serialized_size())
            .sum::<usize>()
    }
}

impl CanonicalDeserialize for PublicKey {
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let result = PublicKey( core::array::from_fn(|_| {
            u8::deserialize(&mut reader).unwrap()
        }) );

        Ok(result)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_base64().get(0..16).unwrap())
    }
}

/* Struct SecretKey models the secret (signing) key of the EdDSA signature scheme. */

#[derive(Clone)]
pub struct SecretKey([u8; 64_usize]);

impl SecretKey {
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn from_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..64]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;

        Ok(Self(array))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.to_base64())
    }
}

impl CanonicalSerialize for SecretKey {
    #[inline]
    fn serialize<W: Write>(
    &self,
    mut writer: W,
    ) -> Result<(), SerializationError> {
	// self.0.serialize_with_mode(&mut writer, compress)
	for item in self.0.iter() {
            item.serialize(&mut writer)?;
        }

	Ok(())
    }

    fn serialized_size(&self) -> usize {
	self.0.iter()
            .map(|item| item.serialized_size())
            .sum::<usize>()
    }
}

impl CanonicalDeserialize for SecretKey {
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let result = SecretKey( core::array::from_fn(|_| {
            u8::deserialize(&mut reader).unwrap()
        }) );

        Ok(result)
    }
}

pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    generate_keypair(&mut OsRng)
}

pub fn generate_keypair<R>(csprng: &mut R) -> (PublicKey, SecretKey)
where
    R: CryptoRng + RngCore,
{
    let keypair = dalek::Keypair::generate(csprng);
    let public = PublicKey(keypair.public.to_bytes());
    let secret = SecretKey(keypair.to_bytes());
    (public, secret)
}

/* Struct representing an EdDSA signature. */

#[derive(Clone, Default, Debug, Copy, PartialEq)]
pub struct Signature {
    part1: [u8; 32],
    part2: [u8; 32],
}

impl Signature {
    pub fn new(digest: &Digest, secret: &SecretKey) -> Self {
        let keypair = dalek::Keypair::from_bytes(&secret.0).expect("Unable to load secret key");
        let sig = keypair.sign(&digest.0).to_bytes();
        let part1 = sig[..32].try_into().expect("Unexpected signature length");
        let part2 = sig[32..64].try_into().expect("Unexpected signature length");
        Signature { part1, part2 }
    }

    fn flatten(&self) -> [u8; 64] {
        [self.part1, self.part2]
            .concat()
            .try_into()
            .expect("Unexpected signature length")
    }

    pub fn verify(&self, digest: &Digest, public_key: &PublicKey) -> Result<(), CryptoError> {
        let signature = ed25519::signature::Signature::from_bytes(&self.flatten())?;
        let key = dalek::PublicKey::from_bytes(&public_key.0)?;
        key.verify_strict(&digest.0, &signature)
    }

    pub fn verify_batch<'a, I>(digest: &Digest, votes: I) -> Result<(), CryptoError>
    where
        I: IntoIterator<Item = (&'a PublicKey, &'a Signature)>,
    {
        let mut messages: Vec<&[u8]> = Vec::new();
        let mut signatures: Vec<dalek::Signature> = Vec::new();
        let mut keys: Vec<dalek::PublicKey> = Vec::new();

        for (key, sig) in votes.into_iter() {
            messages.push(&digest.0[..]);
            signatures.push(ed25519::signature::Signature::from_bytes(&sig.flatten())?);
            keys.push(dalek::PublicKey::from_bytes(&key.0)?);
        }

        dalek::verify_batch(&messages[..], &signatures[..], &keys[..])
    }

    // Added to enable serialization and deserialization.
    pub fn to_base64(&self) -> String {
        base64::encode(self.flatten())
    }
}

impl CanonicalSerialize for Signature {
    #[inline]
    fn serialize<W: Write>(
    &self,
    mut writer: W,
    ) -> Result<(), SerializationError> {
        for item in self.part1.iter() {
            item.serialize(&mut writer)?;
        }

        for item in self.part2.iter() {
            item.serialize(&mut writer)?;
        }

        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.part1.iter()
            .map(|item| item.serialized_size())
            .sum::<usize>() +
        self.part2.iter()
            .map(|item| item.serialized_size())
            .sum::<usize>()
    }
}

impl CanonicalDeserialize for Signature {
    #[inline]
    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
        let result: [u8; 64_usize] = core::array::from_fn(|_| {
            u8::deserialize(&mut reader).unwrap()
        });
        let pt1 = result[..32].try_into().expect("Unexpected signature length");
        let pt2 = result[32..64].try_into().expect("Unexpected signature length");

        Ok(Signature {part1: pt1, part2: pt2} )
    }
}
