use crate::modified_scrape::poly::{ensure_degree, lagrange_interpolation_simple};   // poly::Polynomial, lagrange_interpolation
use crate::modified_scrape::errors::PVSSError;
use crate::modified_scrape::pvss::PVSSShare;
use crate::modified_scrape::share::{PVSSTranscript, PVSSTranscriptParticipant, PVSSAugmentedShare};
use crate::modified_scrape::participant::Participant;
use crate::signature::scheme::BatchVerifiableSignatureScheme;
use crate::modified_scrape::decomp::{DecompProof, message_from_pi_i};

//use crate::modified_scrape::decomp::ProofGroup;

use super::config::Config;
//use crate::Scalar;

use ark_ec::{PairingEngine, ProjectiveCurve};   // msm::VariableBaseMSM, AffineCurve
use ark_std::collections::BTreeMap;

//use ark_ff::{PrimeField, UniformRand};
use ark_ff::{One, Zero};
use ark_std::ops::AddAssign;

use rand::Rng;
use std::ops::Neg;


pub struct PVSSAggregator<E, SSIG>
where
    E: PairingEngine,
    <E as PairingEngine>::G2Affine: AddAssign,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
{
    pub config: Config<E>,
    pub scheme_sig: SSIG,   // scheme for encryption
    //pub ,   // EdDSA public key
    pub participants: BTreeMap<usize, Participant<E, SSIG>>,   // maps ids to Participant instances
    pub transcript: PVSSTranscript<E>,
}


impl<E, SSIG> PVSSAggregator<E, SSIG>
where
	E: PairingEngine,
	<E as PairingEngine>::G2Affine: AddAssign,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
{
    // Method for handling a received augmented PVSS share instance.
    // The share is aggregated into the aggregator's currently aggregated
    // transcript.
    pub fn receive_share<R: Rng>(
        &mut self,
        rng: &mut R,
        share: &PVSSAugmentedShare<E>,
    ) -> Result<(), PVSSError<E>> {

	    // Verify augmented PVSS share.
        self.share_verify(rng, share)?;

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

	    // Aggregate the newly generated transcript to the currently held aggregated transcript.
        self.transcript = self.transcript.aggregate(&transcript)?;

        Ok(())
    }


    // Method for handling a received PVSS transcript instance.
    pub fn receive_transcript<R: Rng>(
        &mut self,
        rng: &mut R,
        transcript: &PVSSTranscript<E>,
    ) -> Result<(), PVSSError<E>> {

	    // Perform checks on the transcript analogous to Context::verify_aggregation:

	    // Check that the sizes of commitments and encryptions are correct.
	    if transcript.pvss_share.encs.len() != self.config.num_participants || 
            transcript.pvss_share.comms.len() != self.config.num_participants ||
            transcript.contributions.len() < self.config.degree {   // NOTE: maybe break down into individual checks for better control
            return Err(PVSSError::LengthMismatchError);
    	}

    	// Coding check for the commitments to ensure that they represent a
	    // commitment to a degree t polynomial.
	    if ensure_degree::<E, _>(rng, &transcript.pvss_share.comms, self.config.degree as u64).is_err() {
            return Err(PVSSError::DualCodeError);
    	}

	    // Pairing check (e(pk_i, com_i) = e(enc_i, g2))

	    let correct_encryptions = (0..self.config.num_participants)
	        .all(|i| { let pairs = [
            	(self.participants.get(&i).unwrap().public_key_sig.into(), transcript.pvss_share.comms[i].into_affine().into()),
            	(transcript.pvss_share.encs[i].neg().into_affine().into(), self.config.srs.g2.into()),
        	]; 
		E::product_of_pairings(pairs.iter()).is_one() });

	    if !correct_encryptions {
	        return Err(PVSSError::EncryptionCorrectnessError);
	    }

	    // Decomposition proof check

	    let point = lagrange_interpolation_simple::<E>(&transcript.pvss_share.comms, self.config.degree as u64).unwrap();   // E::G2Projective

	    let mut gs_total = E::G2Affine::zero();

	    for (participant_id, contribution) in transcript.contributions.iter() {
	        if contribution.decomp_proof.verify(&self.config).is_err() {
		        return Err(PVSSError::DecompositionInTranscriptError);
	        }
	        gs_total += contribution.decomp_proof.gs;
	    }

	    if gs_total != point.into_affine() {
	        return Err(PVSSError::AggregationReconstructionMismatchError);
	    }

	    /*
	    auto point = Polynomial::lagrange_interpolation(config.num_faults(), agg.commitments);
    	auto gs_prod = Com_Group::zero();
    	for(auto& dec_i: agg.decomposition) {
        	if(!dec_i.pi.verify(Com_generator, dec_i.gs)) {
            		std::cout << "Decomposition in agg vec is incorrect" << std::endl;
            	return false;
        	}
        	gs_prod = gs_prod + dec_i.gs;
    	}
    	return gs_prod == point;
	    */

	    // Verify PVSS share
        //let pvss_timer = start_timer!(|| "PVSS share verification");
        //self.pvss_share_verify(rng, c.into_affine(), &transcript.pvss_share)?;
        //end_timer!(pvss_timer);

        Ok(())
    }


    // Method for verifying individual "core" PVSS shares against a commitment to some secret.
    pub fn pvss_share_verify<R: Rng>(
        &self,
        rng: &mut R,
	    decomp_proof: &DecompProof<E>,   // need to pass on separately since PVSSShares don't have decomps attached
        share: &PVSSShare<E>,
    ) -> Result<(), PVSSError<E>> {

	    // Check that the sizes of commitments and encryptions are correct.
	    if share.encs.len() != self.config.num_participants ||
           share.comms.len() != self.config.num_participants {
	        return Err(PVSSError::MismatchedCommitsEncryptionsParticipantsError(share.encs.len(),
			    share.comms.len(), self.config.num_participants));
	    }

	    // Coding check for the commitments to ensure that they represent a
	    // commitment to a degree t polynomial.
	    if ensure_degree::<E, _>(rng, &share.comms, self.config.degree as u64).is_err() {
            return Err(PVSSError::DualCodeError);
        }

	    // The pairing condition for correctness of encryption is: e(pk_i, v_i) = e(enc_i, g_2).
	    // NOTE: However, we do not have access to the sender's identity at this point (and by
	    // extension, its public key). Hence, this check is done in share_verify.

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
        share: &PVSSAugmentedShare<E>,
    ) -> Result<(), PVSSError<E>> {

        // Retrieve the Participant instance using the id within the augmented share.
	    let participant_id = share.participant_id;
        let participant = self
            .participants
            .get(&participant_id)
            .ok_or(PVSSError::<E>::InvalidParticipantId(participant_id))?;

	    // Verify correctness of encryption:

	    let pairs = [
            (participant.public_key_sig.into(), share.pvss_share.comms[participant_id].into_affine().into()),
            (share.pvss_share.encs[participant_id].neg().into_affine().into(), self.config.srs.g2.into()),
        ];

        if !E::product_of_pairings(pairs.iter()).is_one() {
            return Err(PVSSError::EncryptionCorrectnessError);
        }

	    // Verify the "core" PVSS share against the provided decomposition proof.
	    self.pvss_share_verify(rng, &share.decomp_proof, &share.pvss_share)?;

        // Verify signature on decomposition proof against participant i's public key.
        self.scheme_sig.verify(
            &participant.public_key_sig,
            &message_from_pi_i(share.decomp_proof)?,
            &share.signature_on_decomp,
        )?;

        Ok(())
    }

}
