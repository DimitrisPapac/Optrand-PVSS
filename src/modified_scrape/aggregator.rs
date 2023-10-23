use crate::{
    ComGroupP,
    EncGroup,
    EncGroupP,
    modified_scrape::{
	config::Config,
        decomp::DecompProof,
        errors::PVSSError,
        participant::Participant,
        poly::{ensure_degree, lagrange_interpolation_simple},
        pvss::PVSSCore,
        share::{PVSSAggregatedShare, PVSSShare},
    },
    Scalar,
    signature::scheme::BatchVerifiableSignatureScheme,
};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, Zero};
use ark_std::{collections::BTreeMap, UniformRand};


use rand::Rng;
use std::ops::Neg;


/* A PVSSAggregator is responsible for receiving PVSS shares, verifying them, and
   aggregating them to an aggregated transcript. */
pub struct PVSSAggregator<E, SSIG>
where
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = EncGroup<E>, Secret = Scalar<E>>,
{
    pub config: Config<E>,                                     // the "global" configuration parameters
    pub scheme_sig: SSIG,                                      // scheme for encryption
    pub participants: BTreeMap<usize, Participant<E, SSIG>>,   // maps ids to Participant instances (incl. their pks)
    pub aggregated_tx: PVSSAggregatedShare<E>,                 // aggregated transcript of PVSS shares
}


impl<E, SSIG> PVSSAggregator<E, SSIG>
where
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = EncGroup<E>, Secret = Scalar<E>>,
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
                &core.comms, self.config.degree as u64).unwrap();

	if point != decomp_proof.gs {
	        return Err(PVSSError::GSCheckError);
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

        Ok(())
    }


    // Method for verifying aggregation in a PVSSAggregatedShare instance.
    // Essentially performs the checks from "verify_aggregation".
    pub fn aggregation_verify<R: Rng>(
        &mut self,
        rng: &mut R,
        agg_share: &PVSSAggregatedShare<E>,
    ) -> Result<(), PVSSError<E>> 
    where
        Scalar<E>: From<u64> {

        // Check that the sizes of commitments and encryptions are correct.
        if agg_share.pvss_core.encs.len() != self.config.num_participants ||
           agg_share.pvss_core.comms.len() != self.config.num_participants {
	        return Err(PVSSError::MismatchedCommitsEncryptionsParticipantsError(
			    agg_share.pvss_core.encs.len(),
			    agg_share.pvss_core.comms.len(),
                            self.config.num_participants));
        }

	// Coding check for the commitments to ensure that they represent a
	// commitment to a degree t polynomial.
	if ensure_degree::<E, _>(rng, &agg_share.pvss_core.comms, self.config.degree as u64).is_err() {
            return Err(PVSSError::DualCodeError);
        }
	
	// Pairing check: e(pk_i, comm_i) = e(enc_i, g2), for all i in {0, ..., n-1}. Requires: 2n-pairings.
    /*
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
    */
    

    // Alternative pairing check: e(epsilon, g2) = prod_{i} e(pk_i, comm_i),
    // where: epsilon := prod_{i} enc_i^{r_i} for r_i <--$ F_q, for all i in {0, ..., n-1}.
    // Requires: n + 1 pairings.

    // Sample random field elements
    let r = vec![E::Fr::rand(rng); self.config.num_participants];

    // Compute epsilon and construct pairs
    let mut epsilon = EncGroupP::<E>::zero();
    let mut pairs = vec![(epsilon.into_affine().neg().into(), self.config.srs.g2.into())];
    for i in 0..self.config.num_participants {
        epsilon += agg_share.pvss_core.encs[i].mul(r[i]);
        pairs.push((self.participants.get(&i).unwrap().public_key_sig.mul(r[i]).into_affine().into(),
            agg_share.pvss_core.comms[i].into()));
    }

    // Evaluate pairing condition
    if !E::product_of_pairings(pairs.iter()).is_one() {
	    return Err(PVSSError::EncryptionCorrectnessError);
	}
    

	// Decomposition proof check:

	let point = lagrange_interpolation_simple::<E>(&agg_share.pvss_core.comms,
        self.config.degree as u64).unwrap();

	// let mut gs_total = ComGroup::<E>::zero();
        let mut gs_total = ComGroupP::<E>::zero();

	// Contributions are essentially signed decomposition proofs along with their weight.
	for (_participant_id, (contribution, weight)) in agg_share.contributions.iter() {
            // let party = self.participants.get(participant_id).unwrap();
            // if contribution.verify(&self.config, &party.public_key_ed).is_err() {
            //     return Err(PVSSError::InvalidSignedProofError);
            // }

	    if contribution.decomp_proof.verify(&self.config).is_err() {
		return Err(PVSSError::DecompositionInTranscriptError);
	    }

            gs_total += contribution.decomp_proof.gs.mul(Scalar::<E>::from(*weight));
	}

        // The point reconstructed from the aggregated share's commitment vector must be a
        // commitment to the evaluation of polynomial sum_{i} w_i * p_i(x) on point x = 0
        // i.e., a commitment to this polynomial's free term.
	if gs_total.into_affine() != point {
	    return Err(PVSSError::AggregationReconstructionMismatchError);
	}

	for (participant_id, (contribution, _weight)) in agg_share.contributions.iter() {
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
