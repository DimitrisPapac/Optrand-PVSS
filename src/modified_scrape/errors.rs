use crate::signature::utils::errors::SignatureError;
use ark_ec::PairingEngine;
use ark_serialize::SerializationError;
use thiserror::Error;

// Enumeration defining appropriate errors for various situations
#[derive(Error, Debug)]
pub enum PVSSError<E: PairingEngine> {
    #[error("Insufficient evaluations")]
    InsufficientEvaluationsError,
    #[error("Different number of points and evaluations")]
    DifferentPointsEvalsError,
    #[error("Could not generate decomposition proof")]
    DecompGenerationError,
    #[error("Invalid participant ID: {0}")]
    InvalidParticipantId(usize),
    #[error("Mismatch between provided encryptions ({0} given), commitments ({1} given), and replicas ({2} given)")]
    MismatchedCommitsEncryptionsReplicasError(usize, usize, usize),
    #[error("Degree check failed. Dual code condition does not hold")]
    DualCodeError,
    #[error("gs check failed")]
    GSCheckError,
    #[error("Empty shares vector provided")]
    EmptySharesVectorError,
    #[error("Insufficient elements in the identities vector")]
    InsufficientIdsError,
    #[error("Insufficient commitments in PVSS share. Found: {0}, Expected: {1}")]
    InsufficientCommitsInShareError(usize, usize),
    #[error("Insufficient encryptions in PVSS share. Found: {0}, Expected: {1}")]
    InsufficientEncryptionsInShareError(usize, usize),
    #[error("Share's encryptions vector is empty")]
    EmptyEncryptionsVectorError,
    #[error("Mismatched commitment vector lengths. First has: {0}, Second has: {1}")]
    MismatchedCommitmentsError(usize, usize),
    #[error("Mismatched encryption vector lengths. First has: {0}, Second has: {1}")]
    MismatchedEncryptionsError(usize, usize),
    #[error("Mismatched commitment and encryption vector lengths within share. First has: {0}, Second has: {1}")]
    MismatchedCommitmentsEncryptionsError(usize, usize),


    #[error("Ratio incorrect")]
    RatioIncorrect,
    #[error("Evaluations are wrong: product = {0}")]
    EvaluationsCheckError(E::G1Affine),
    #[error("Could not generate evaluation domain")]
    EvaluationDomainError,
    #[error("Config, dealer and nodes had different SRSes")]
    DifferentSRS,
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Transcripts have different degree or number of participants: self.degree={0}, other.degree={1}, self.num_participants={2}, self.num_participants={3}")]
    TranscriptDifferentConfig(usize, usize, usize, usize),
    #[error("Transcripts have different commitments")]
    TranscriptDifferentCommitments,
}
