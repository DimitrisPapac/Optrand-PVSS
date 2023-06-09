use crate::{modified_scrape::participant::Participant, signature::scheme::BatchVerifiableSignatureScheme};
use ark_ec::PairingEngine;

// Struct Dealer models the aspects of each party in the network, when acting as a dealer
// in the PVSS scheme.
#[derive(Clone)]
pub struct Dealer<
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    pub private_key_sig: SSIG::Secret,            // Dealer's secret (signing) key

    // MAY BE REDUNDANT
    pub accumulated_secret: E::G2Affine,     // Dealer's accumulated secret (in G_2)

    // MAY BE REDUNDANT
    pub decryptions: Vec<(usize, E::G1Affine)>,   // Dealer's list of accumulated decryptions, along with the respective participant ids

    pub participant: Participant<E, SSIG>,        // Dealers have participant characteristics (structural composition)
}
