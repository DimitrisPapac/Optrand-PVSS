use crate::modified_scrape::poly::{ensure_degree, lagrange_interpolation_simple};   // poly::Polynomial, lagrange_interpolation
use crate::modified_scrape::errors::PVSSError;
use crate::modified_scrape::pvss::PVSSShare;
use crate::modified_scrape::share::{PVSSTranscript, PVSSTranscriptParticipant, PVSSAugmentedShare};
use crate::modified_scrape::participant::Participant;
use crate::signature::scheme::BatchVerifiableSignatureScheme;
use crate::modified_scrape::decomp::{DecompProof, message_from_pi_i};

//use crate::modified_scrape::decomp::ProofGroup;

use super::config::Config;
use crate::Scalar;

use ark_ec::{PairingEngine, ProjectiveCurve};   // msm::VariableBaseMSM, AffineCurve
use ark_std::collections::BTreeMap;

//use ark_ff::{One, PrimeField, UniformRand, Zero};

use rand::Rng;
//use std::ops::Neg;



pub struct PVSSAggregator<
    E: PairingEngine,
    // SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = Scalar<E>>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = Scalar<E>>,
> {
    pub config: Config<E>,
    // pub scheme_pok: SPOK,   // might be redundant
    pub scheme_sig: SSIG,
    pub participants: BTreeMap<usize, Participant<E, SSIG>>,   // maps ids to Participant instances

    pub transcript: PVSSTranscript<E, SSIG>,   // <E, SPOK, SSIG>
}


impl<
        E: PairingEngine,
        // SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = Scalar<E>>,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = Scalar<E>>,   // NOTE: might want to switch to projective coordinates
    > PVSSAggregator<E, SSIG>   // <E, SPOK, SSIG>
{

    // Method for handling a received an augmented PVSS share instance.
    pub fn receive_share<R: Rng>(
        &mut self,
        rng: &mut R,
        share: &PVSSAugmentedShare<E, SSIG>,
    ) -> Result<(), PVSSError<E>> {
	// Verify augmented PVSS share.
        self.share_verify(rng, share)?;

	// Q: What if we receive the same PVSS share instance twice in a row?
	// Does its "weight" somehow factor in?

	// Create a PVSS transcript from the info included in the augmented share.
        let transcript = PVSSTranscript {
            degree: self.config.degree,
            num_participants: self.participants.len(),
            contributions: vec![(
                share.participant_id,
                PVSSTranscriptParticipant {
                    decomp_proof: share.decomp_proof.clone(),
    		    signature_on_decomp: share.signature_on_decomp.clone(),   
                },
            )]
            .into_iter()
            .collect(),
            pvss_share: share.pvss_share.clone(),
        };

	// Aggregate the newly generated transcript to the current aggregate.
        self.transcript = self.transcript.aggregate(&transcript)?;

        Ok(())
    }


    // Method for handling a received PVSSTranscript instance.
    pub fn receive_transcript<R: Rng>(
        &mut self,
        rng: &mut R,
        transcript: &PVSSTranscript<E, SSIG>,
    ) -> Result<(), PVSSError<E>> {

	// Perform checks on the transcript analogous to Context::verify_aggregation

        let mut c = E::G1Projective::zero();
        let mut public_keys_sig = vec![];
        let mut messages_sig = vec![];
        let mut signatures_sig = vec![];

        let mut public_keys_pok = vec![];
        let mut messages_pok = vec![];
        let mut signatures_pok = vec![];

        for (participant_id, contribution) in transcript.contributions.iter() {
	    // Retrieve participant's profile.
            let participant = self
                .participants
                .get(participant_id)
                .ok_or(PVSSError::<E>::InvalidParticipantId(*participant_id))?;

	    // serialize decomposition proof into an array of bytes.
            let message = message_from_pi_i(contribution.decomp_proof)?;

            public_keys_sig.push(&participant.public_key_sig);
            messages_sig.push(message.clone());
            signatures_sig.push(&contribution.signature_on_decomp);

            public_keys_pok.push(&contribution.decomp_proof);
            messages_pok.push(message);
            signatures_pok.push(&contribution.c_i_pok);

            c += &contribution
                .c_i
                .mul(<E::Fr as From<u64>>::from(contribution.weight));
        }
        let sig_timer = start_timer!(|| "Signature batch verification");
        self.scheme_sig.batch_verify(
            rng,
            &public_keys_sig,
            &messages_sig
                .iter()
                .map(|v| v.as_slice())
                .collect::<Vec<_>>(),
            &signatures_sig,
        )?;
        end_timer!(sig_timer);

        let pok_timer = start_timer!(|| "POK batch verification");
        self.scheme_pok.batch_verify(
            rng,
            &public_keys_pok,
            &messages_pok
                .iter()
                .map(|v| v.as_slice())
                .collect::<Vec<_>>(),
            &signatures_pok,
        )?;
        end_timer!(pok_timer);

	// Verify PVSS share
        let pvss_timer = start_timer!(|| "PVSS share verification");
        self.pvss_share_verify(rng, c.into_affine(), &transcript.pvss_share)?;
        end_timer!(pvss_timer);

        Ok(())
    }


    // Method for verifying individual PVSS shares against a commitment to some secret.
    pub fn pvss_share_verify<R: Rng>(
        &self,
        rng: &mut R,
	decomp_proof: &DecompProof<E>,   // need to pass on separately since PVSSShares don't have decomps attached
        share: &PVSSShare<E>,
    ) -> Result<(), PVSSError<E>> {

	// Check that the sizes are correct
	if share.encs.len() != self.config.num_participants ||
           share.comms.len() != self.config.num_participants {
	    return Err(PVSSError::MismatchedCommitsEncryptionsReplicasError(share.encs.len(),
			share.comms.len(), self.config.num_participants));
	}

	// Coding check for the commitments to ensure that they represent a
	// commitment to a degree t polynomial.
	if ensure_degree::<E, _>(rng, &share.comms, self.config.degree as u64).is_err() {
            return Err(PVSSError::DualCodeError);
        }

	// Q: Is a pairing condition check truly necessary here?

        // Check decomposition proof.
	let point = lagrange_interpolation_simple::<E>(&share.comms, self.config.degree as u64).unwrap();   // E::G2Projective

	if point.into_affine() != decomp_proof.gs {
	    return Err(PVSSError::GSCheckError);
	}

	// Verify decomposition proof against our config.
        if decomp_proof.verify(&self.config).is_err() {
	    return Err(PVSSError::DecompProofVerificationError);
	}

        Ok(())
    }


    // Method for verifying a received PVSSAugmentedShare instance.
    pub fn share_verify<R: Rng>(
        &mut self,
        rng: &mut R,
        share: &PVSSAugmentedShare<E, SSIG>,
    ) -> Result<(), PVSSError<E>> {
        // Retrieve the Participant instance using the id within the augmented share.
	let participant_id = share.participant_id;
        let participant = self
            .participants
            .get(&participant_id)
            .ok_or(PVSSError::<E>::InvalidParticipantId(participant_id))?;

	// Verify the "core" PVSS share against the provided decomposition proof.
	self.pvss_share_verify(rng, &share.decomp_proof, &share.pvss_share)?;

        // Verify signature on decomposition proof against participant i's public key.
        self.scheme_sig.verify(
            &participant.public_key_sig,
            &message_from_pi_i(share.decomp_proof)?,
            &share.signature_on_decomp,
        )?;

        // Verify POK of C_i.
        // self.scheme_pok
        //     .verify(&share.c_i, &message_from_c_i(share.c_i)?, &share.c_i_pok)?;

        Ok(())
    }

}
