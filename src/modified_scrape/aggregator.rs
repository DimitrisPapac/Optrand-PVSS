use crate::modified_scrape::poly::{ensure_degree, lagrange_interpolation_simple};   // poly::Polynomial, lagrange_interpolation
use crate::modified_scrape::errors::PVSSError;
use crate::modified_scrape::pvss::PVSSCore;
use crate::modified_scrape::share::{PVSSAggregatedShare, PVSSShare};
use crate::modified_scrape::participant::Participant;
use crate::modified_scrape::decomp::{DecompProof};   // message_from_pi_i
use crate::signature::scheme::BatchVerifiableSignatureScheme;
use crate::{Signature, Digest, PublicKey};
use super::config::Config;

use ark_ec::{PairingEngine, ProjectiveCurve};   // msm::VariableBaseMSM, AffineCurve
use ark_std::collections::BTreeMap;
use ark_ff::{One, Zero};
use ark_std::ops::AddAssign;

use rand::Rng;
use std::ops::Neg;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};


/* A PVSSAggregator is responsible for receiving PVSS shares, verifying them, and
   aggregating them to an aggregated transcript. */
pub struct PVSSAggregator<E, SSIG>
where
    E: PairingEngine,
    //<E as PairingEngine>::G2Affine: AddAssign,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
{
    pub config: Config<E>,                                     // the "global" configuration parameters
    pub scheme_sig: SSIG,                                      // scheme for encryption
    pub participants: BTreeMap<usize, Participant<E, SSIG>>,   // maps ids to Participant instances (incl. their pks)
    pub aggregated_tx: PVSSAggregatedShare<E>,                 // aggregated transcript of PVSS shares
}


impl<E, SSIG> PVSSAggregator<E, SSIG>
where
    E: PairingEngine,
    <E as PairingEngine>::G2Affine: AddAssign,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
{
    // Utility method for verifying individual "core" PVSS shares.
    pub fn core_verify<R: Rng>(
        &self,
        rng: &mut R,
	decomp_proof: &DecompProof<E>,   // need to pass on separately since cores do not have decomps attached
        core: &PVSSCore<E>,
    ) -> Result<(), PVSSError<E>> {

	// Check that the sizes of commitments and encryptions are correct.
	if core.encs.len() != self.config.num_participants ||
           core.comms.len() != self.config.num_participants {
	        return Err(PVSSError::MismatchedCommitsEncryptionsParticipantsError(core.encs.len(),
			    core.comms.len(), self.config.num_participants));
	}

	// Coding check for the commitments to ensure that they represent a
	// commitment to a degree t polynomial.
	if ensure_degree::<E, _>(rng, &core.comms, self.config.degree as u64).is_err() {
            return Err(PVSSError::DualCodeError);
        }

	// The pairing condition for correctness of encryption is: e(pk_i, v_i) = e(enc_i, g_2).
	// NOTE: However, we do not have access to the sender's identity at this point (and by
	// extension, its public key). Hence, this check is carried out in share_verify.

        // Check decomposition proof.
	let point = lagrange_interpolation_simple::<E>(&core.comms, self.config.degree as u64).unwrap();   // E::G2Projective

	if point.into_affine() != decomp_proof.gs {
	        return Err(PVSSError::GSCheckError);
	}

	// Verify decomposition proof against our config.
        if decomp_proof.verify(&self.config).is_err() {
	    return Err(PVSSError::DecompProofVerificationError);
	}

        Ok(())
    }


    // Method for verifying a received PVSSShare instance.
    // Essentially performs the checks from "verify_sharing".
    pub fn share_verify<R: Rng>(
        &mut self,
        rng: &mut R,
        share: &mut PVSSShare<E>,
    ) -> Result<(), PVSSError<E>> {

        // Retrieve the Participant instance using the id within the augmented share.
	let participant_id = share.participant_id;

        let participant = self
            .participants
            .get(&participant_id)
            .ok_or(PVSSError::<E>::InvalidParticipantId(participant_id))?;

	// Verify correctness of encryption:
	let pairs = [
            (participant.public_key_sig.into(), share.pvss_core.comms[participant_id].into_affine().into()),
            (share.pvss_core.encs[participant_id].neg().into_affine().into(), self.config.srs.g2.into()),
        ];

        if !E::product_of_pairings(pairs.iter()).is_one() {
            return Err(PVSSError::EncryptionCorrectnessError);
        }

	// Verify the "core" PVSS share against the provided decomposition proof.
	self.core_verify(rng, &share.decomp_proof, &share.pvss_core)?;

        // Verify signature on decomposition proof against participant i's public key:
	let digest = share.decomp_proof.digest();

	if share.signature_on_decomp.verify(&digest, &participant.public_key_ed).is_err() {
	    return Err(PVSSError::EdDSAInvalidSignatureError);
	}

        Ok(())
    }


    // Method for verifying aggregation in a PVSSAggregatedShare instance.
    // Essentially performs the checks from "verify_aggregation".
    pub fn aggregation_verify<R: Rng>(
        &mut self,
        rng: &mut R,
        agg_share: &PVSSAggregatedShare<E>,
    ) -> Result<(), PVSSError<E>> {

        // Check that the sizes of commitments and encryptions are correct.
	if agg_share.pvss_core.encs.len() != self.config.num_participants ||
           agg_share.pvss_core.comms.len() != self.config.num_participants {
	        return Err(PVSSError::MismatchedCommitsEncryptionsParticipantsError(
			    agg_share.pvss_core.encs.len(),
			    agg_share.pvss_core.comms.len(), self.config.num_participants));
	}

        // if agg_share.contributions.len() < self.config.degree {}

	// Coding check for the commitments to ensure that they represent a
	// commitment to a degree t polynomial.
	if ensure_degree::<E, _>(rng, &agg_share.pvss_core.comms, self.config.degree as u64).is_err() {
            return Err(PVSSError::DualCodeError);
        }

	
	// Pairing check: e(pk_i, com_i) = e(enc_i, g2)

	let correct_encryptions = (0..self.config.num_participants)
	        .all(|i| { let pairs = [
            	    (self.participants.get(&i).unwrap().public_key_sig.into(), agg_share.pvss_core.comms[i].into_affine().into()),
            	    (agg_share.pvss_core.encs[i].neg().into_affine().into(), self.config.srs.g2.into()),
        	];

		E::product_of_pairings(pairs.iter()).is_one()
	    }
	);

	if !correct_encryptions {
	    return Err(PVSSError::EncryptionCorrectnessError);
	}

	// Decomposition proof check:

	let point = lagrange_interpolation_simple::<E>(&agg_share.pvss_core.comms, self.config.degree as u64).unwrap();   // E::G2Projective

	let mut gs_total = E::G2Affine::zero();

	// Contributions are essentially signed decomposition proofs.
	for (_participant_id, contribution) in agg_share.contributions.iter() {
	    if contribution.decomp_proof.verify(&self.config).is_err() {
		return Err(PVSSError::DecompositionInTranscriptError);
	    }

	    gs_total += contribution.decomp_proof.gs;
	}

	if gs_total != point.into_affine() {
	    return Err(PVSSError::AggregationReconstructionMismatchError);
	}

	// Batch-verification of signatures:
	let mut dproofs = Vec::new();
	let mut pks: Vec<PublicKey> = Vec::new();
	let mut sigs: Vec<Signature> = Vec::new();

	for (participant_id, contribution) in agg_share.contributions.iter() {
	    dproofs.push(contribution.decomp_proof.clone());
	    sigs.push(contribution.signature_on_decomp.clone());
	    pks.push(self.participants.get(&participant_id).unwrap().public_key_ed.into());
	}

	let mut hasher = DefaultHasher::new();
	for dproof in dproofs {   // not very elegant
	    dproof.hash(&mut hasher);
	}
        let byte_array= hasher.finish().to_ne_bytes();   // TODO: use cryptographically secure hash
        let mut arr = [0; 32];
        arr[..byte_array.len()].copy_from_slice(&byte_array);

	let digest = Digest(arr);
	let votes: std::iter::Zip<std::slice::Iter<'_, PublicKey>, std::slice::Iter<'_, Signature>> = pks.iter().zip(sigs.iter());
	
	
	if Signature::verify_batch(&digest, votes).is_err() {
		return Err(PVSSError::EdDSAInvalidSignatureBatchError);
	}

        Ok(())
    }

    // Method for handling a received PVSSShare instance.
    // The share is aggregated into the aggregator's currently aggregated
    // transcript.
    pub fn receive_share<R: Rng>(
        &mut self,
        rng: &mut R,
        share: &mut PVSSShare<E>,
    ) -> Result<(), PVSSError<E>> {

	// Verify the PVSS share.
        self.share_verify(rng, share)?;

	// Aggregate the PVSS share into the aggregator's internal aggregated transcript.
	self.aggregated_tx = self.aggregated_tx.aggregate_pvss_share(&share)?;

        Ok(())
    }


    // Method for handling a received PVSSAggregatedShare instance.
    // The share is aggregated into the aggregator's currently aggregated
    // transcript.
    pub fn receive_aggregated_share<R: Rng>(
        &mut self,
        rng: &mut R,
        agg_share: &PVSSAggregatedShare<E>,
    ) -> Result<(), PVSSError<E>> {

	// Verify aggregation
	self.aggregation_verify(rng, agg_share)?;

	// Aggregate the received aggregated PVSS share into the aggregator's internal aggregated transcript.
	self.aggregated_tx = self.aggregated_tx.aggregate(&agg_share).unwrap();

        Ok(())
    }

}
