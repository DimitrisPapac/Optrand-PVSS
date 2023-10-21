use crate::{
    EncGroup,
    PublicKey,
    Scalar,
    signature::scheme::BatchVerifiableSignatureScheme,
};

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError, Read, Write};

use std::marker::PhantomData;


// Struct ParticipantState models the states that each participant in the PVSS
// scheme goes through. (UNUSED)
#[derive(Clone)]
pub enum ParticipantState {
    Dealer,
    DealerShared,
    Initial,
    Verified,
}

// Struct Participant models each individual party participating in the PVSS scheme.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Participant<
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = EncGroup<E>, Secret = Scalar<E>>,   // G1 is the encryption group
> {
    pub pairing_type: PhantomData<E>,
    pub id: usize,                         // participant id
    pub public_key_sig: SSIG::PublicKey,   // public (encryption) key (in G1)
    pub public_key_ed: PublicKey,          // EdDSA public (verification) key
    // pub state: ParticipantState,        // participant current state
}
