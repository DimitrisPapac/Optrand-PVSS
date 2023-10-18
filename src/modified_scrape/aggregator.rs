use crate::{
    // Digest,
    modified_scrape::{
	config::Config,
        decomp::DecompProof,
        errors::PVSSError,
        participant::Participant,
        poly::{ensure_degree, lagrange_interpolation_simple},   // poly::Polynomial, lagrange_interpolation
        pvss::PVSSCore,
        share::{PVSSAggregatedShare, PVSSShare},   // message_from_pi_i
    },
    // PublicKey,
    // Signature,
    signature::scheme::BatchVerifiableSignatureScheme,
};

use ark_ec::{PairingEngine, ProjectiveCurve};   // msm::VariableBaseMSM, AffineCurve
use ark_ff::{One, Zero};
// use ark_serialize::CanonicalSerialize;
use ark_std::collections::BTreeMap;

use rand::Rng;
use std::{
    // collections::hash_map::DefaultHasher,
    // hash::{Hash, Hasher},
    // iter::Zip,
    ops::Neg,
    // slice::Iter,
};

// use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
// use std::{fmt::Write, num::ParseIntError};


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
    //<E as PairingEngine>::G2Affine: AddAssign,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
{
    // Associated function for creating a new PVSSAggregator instance.
    pub fn new(
        config: Config<E>,
        scheme_sig: SSIG,
        participants: BTreeMap<usize, Participant<E, SSIG>>,
    ) -> Result<Self, PVSSError<E>> {
        let degree = config.degree;
        let num_participants = config.num_participants;

        Ok(PVSSAggregator {
            config,
            scheme_sig,
            participants,
            aggregated_tx: PVSSAggregatedShare::empty(degree, num_participants),
        })
    }

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
	    let point = lagrange_interpolation_simple::<E>(
            &core.comms, self.config.degree as u64).unwrap();   // E::G2Projective

	    if point != decomp_proof.gs {
	        return Err(PVSSError::GSCheckError);
	    }

        // Verification is now performed from within SignedProof::verify()
	    // Verify decomposition proof against our config.
        // if decomp_proof.verify(&self.config).is_err() {
	    //     return Err(PVSSError::DecompProofVerificationError);
	    // }

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

        // Verify correctness of encryption: e(pk_i, v_i) = e(enc_i, g_2).
        let pairs = [
            (participant.public_key_sig.into(), share.pvss_core.comms[participant_id].into()),
            (share.pvss_core.encs[participant_id].neg().into(), self.config.srs.g2.into()),
        ];

        if !E::product_of_pairings(pairs.iter()).is_one() {
            return Err(PVSSError::EncryptionCorrectnessError);
        }

        // Verify the "core" PVSS share against the provided decomposition proof.
        self.core_verify(rng, &share.signed_proof.decomp_proof, &share.pvss_core)?;

        // Verify proof and signature on decomposition proof against participant i's public key:
        if share.signed_proof.verify(&self.config, &participant.public_key_ed).is_err() {
            return Err(PVSSError::InvalidSignedProofError);
        }

        // The following check is now delegated to SignedProof::verify()
        //let digest = share.signed_proof.decomp_proof.digest();

        //if share.signed_proof.signature_on_decomp.verify(&digest, &participant.public_key_ed).is_err() {
        //    return Err(PVSSError::EdDSAInvalidSignatureError);
        //}

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
			    agg_share.pvss_core.comms.len(),
                            self.config.num_participants));
        }

        // if agg_share.contributions.len() < self.config.degree {}

	    // Coding check for the commitments to ensure that they represent a
	    // commitment to a degree t polynomial.
	    if ensure_degree::<E, _>(rng, &agg_share.pvss_core.comms, self.config.degree as u64).is_err() {
            return Err(PVSSError::DualCodeError);
        }
	
	    // Pairing check: e(pk_i, com_i) = e(enc_i, g2).

	    let correct_encryptions = (0..self.config.num_participants)
	        .all(|i| { let pairs = [
            	    (self.participants.get(&i).unwrap().public_key_sig.into(), agg_share.pvss_core.comms[i].into()),
            	    (agg_share.pvss_core.encs[i].neg().into(), self.config.srs.g2.into()),
        	];

		    E::product_of_pairings(pairs.iter()).is_one()
	        }
	    );

	    if !correct_encryptions {
	        return Err(PVSSError::EncryptionCorrectnessError);
	    }

	    // Decomposition proof check:

	    let point = lagrange_interpolation_simple::<E>(&agg_share.pvss_core.comms, self.config.degree as u64).unwrap();   // E::G2Projective

	    //let mut gs_total = E::G2Affine::zero();
        let mut gs_total = E::G2Projective::zero();

	    // Contributions are essentially signed decomposition proofs.
	    for (_participant_id, contribution) in agg_share.contributions.iter() {
            // let party = self.participants.get(participant_id).unwrap();
            // if contribution.verify(&self.config, &party.public_key_ed).is_err() {
            //     return Err(PVSSError::InvalidSignedProofError);
            // }

	        if contribution.decomp_proof.verify(&self.config).is_err() {
		        return Err(PVSSError::DecompositionInTranscriptError);
	        }

            //gs_total += contribution.decomp_proof.gs;
            gs_total.add_assign_mixed(&contribution.decomp_proof.gs);
	    }

	    if gs_total.into_affine() != point {   // if gs_total != point.into_affine()
	        return Err(PVSSError::AggregationReconstructionMismatchError);
	    }

	    for (participant_id, contribution) in agg_share.contributions.iter() {
           let party = self.participants.get(participant_id).unwrap();

           // Verify individual signed proof
           if contribution.clone().verify(&self.config, &party.public_key_ed).is_err() {
               return Err(PVSSError::EdDSAInvalidSignatureError);
           }
	    }

        Ok(())
    }

    // Method for handling a received PVSSShare instance.
    // The share is aggregated into the aggregator's currently aggregated transcript.
    pub fn receive_share<R: Rng>(
        &mut self,
        rng: &mut R,
        share: &mut PVSSShare<E>,
    ) -> Result<(), PVSSError<E>> {

        // Verify the PVSS share.
        self.share_verify(rng, share).unwrap();

        // Aggregate the PVSS share into the aggregator's internal aggregated transcript.
        self.aggregated_tx = self.aggregated_tx.aggregate_pvss_share(share)?;

        Ok(())
    }


    // Method for handling a received PVSSAggregatedShare instance.
    // The share is aggregated into the aggregator's currently aggregated transcript.
    pub fn receive_aggregated_share<R: Rng>(
        &mut self,
        rng: &mut R,
        agg_share: &PVSSAggregatedShare<E>,
    ) -> Result<(), PVSSError<E>> {

	// Verify aggregation
	self.aggregation_verify(rng, agg_share).unwrap();

	// Aggregate the received aggregated PVSS share into the aggregator's internal aggregated transcript.
	self.aggregated_tx = self.aggregated_tx.aggregate(agg_share).unwrap();

        Ok(())
    }

}
