use crate::{modified_scrape::participant::Participant, SecretKey};
use ark_ec::PairingEngine;

// Struct Dealer models the aspects of each party in the network, when acting as a dealer
// in the PVSS scheme.
#[derive(Clone)]
pub struct Dealer<
    E: PairingEngine,
> {
    pub private_key_sig: SecretKey,    // Dealer's secret (signing) key
    pub participant: Participant<E>,   // Dealers have participant characteristics (structural composition)

    // MAY BE REDUNDANT
    pub accumulated_secret: E::G2Affine,     // Dealer's accumulated secret (in G_2)
    // MAY BE REDUNDANT
    pub decryptions: Vec<(usize, E::G1Affine)>,   // Dealer's list of accumulated decryptions, along with the respective participant ids
}
