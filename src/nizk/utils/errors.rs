use ark_serialize::SerializationError;
use thiserror::Error;

// Enumeration whose variants model the various errors that can
// occur w.r.t. generating and processing a NIZK proof.
#[derive(Error, Debug)]
pub enum NIZKError {
    #[error("Could not generate SRS")]
    SRSSetupError,
    #[error("Failed parsing DLK proof")]
    DLKParseError,
    #[error("Failed verifying DLK proof")]
    DLKVerify,
    #[error("SerializationError: {0}")]
    SerializationError(#[from] SerializationError),
}
