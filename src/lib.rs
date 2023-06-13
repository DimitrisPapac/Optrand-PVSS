#[macro_use]
extern crate ark_std;

pub mod modified_scrape;
pub mod signature;
pub mod nizk;



use ark_poly::univariate::DensePolynomial;
use ark_ec::PairingEngine;


///////////////////////////////////////////////////////////////////

// Also declared in poly.rs:

/// The scalar field of the pairing groups
pub type Scalar<E> = <E as PairingEngine>::Fr;

/// A polynomial with the various coefficients in the Scalar Group
pub type Polynomial<E> = DensePolynomial<Scalar<E>>;

///////////////////////////////////////////////////////////////////



/// The target group GT of the pairing
pub type GT<E> = <E as PairingEngine>::Fqk;

/// The secret that we will be encoding
/// Also the beacon
pub type Secret<E> = GT<E>;

/// The Share type
pub type Share<E> = Encryptions<E>;
pub type Commitment<E> = <E as PairingEngine>::G1Affine;

pub type CommitmentP<E> = <E as PairingEngine>::G1Projective;
pub type SecretKey<E> = Scalar<E>;
pub type PublicKey<E> = <E as PairingEngine>::G2Projective;

/// The Encryption group is the same as the public key group
/// Which is G1 for type 3 pairings
pub type Encryptions<E> = PublicKey<E>;
