use super::srs::SRS;
use ark_ec::PairingEngine;

/* Struct config models the system-wide public parameters that each party
   in the network needs to know in order to generate/verify a PVSS sharing.
*/

#[derive(Clone)]
pub struct Config<E: PairingEngine> {
    pub srs: SRS<E>,               // the associated SRS
    pub degree: usize,             // polynomial degree (t)
    pub num_participants: usize,   // the total number of participants in the protocol
}
