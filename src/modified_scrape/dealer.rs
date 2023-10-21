use crate::{
    EncGroup,
    modified_scrape::participant::Participant,
    signature::scheme::BatchVerifiableSignatureScheme,
    Scalar,
    SecretKey,
};

use ark_ec::PairingEngine;

// Struct Dealer models the aspects of each party in the network, when acting as a dealer
// in the PVSS scheme.
#[derive(Clone)]
pub struct Dealer<
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = EncGroup<E>, Secret = Scalar<E>>,
> {
    pub private_key_sig: SSIG::Secret,       // Dealer's secret (decryption) key
    pub private_key_ed: SecretKey,           // EdDSA secret (signing) key
    pub participant: Participant<E, SSIG>,   // Dealers have participant characteristics (structural composition)
}
