use crate::Signature;
use ark_ec::PairingEngine;
use std::marker::PhantomData;

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
> {
    pub pairing_type: PhantomData<E>,
    pub id: usize,                         // participant id
    pub public_key_sig: Signature,
    pub state: ParticipantState,           // participant current state
}
