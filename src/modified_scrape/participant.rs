use crate::PublicKey;
use ark_ec::PairingEngine;
use std::marker::PhantomData;
use crate::signature::scheme::BatchVerifiableSignatureScheme;

// Struct ParticipantState models the states that each participant in the PVSS
// scheme goes through.
#[derive(Clone)]
pub enum ParticipantState {
    Dealer,
    DealerShared,
    Initial,
    Verified,
}

// Struct Participant models each individual party participating in the PVSS scheme.
#[derive(Clone)]
pub struct Participant<
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,   // G1 is the encryption group
> {
    pub pairing_type: PhantomData<E>,
    pub id: usize,                         // participant id
    pub public_key_sig: SSIG::PublicKey,   // public (encryption) key (in G1)
    pub public_key_ed: PublicKey,          // EdDSA public (verification) key
    pub state: ParticipantState,           // participant current state
}
