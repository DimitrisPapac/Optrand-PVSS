/*
use crate::{
    dkg::{
        config::Config,
        errors::DKGError,
        participant::Participant,
        pvss::PVSSShare,
        share::{message_from_c_i, DKGShare, DKGTranscript, DKGTranscriptParticipant},
    },
    signature::scheme::BatchVerifiableSignatureScheme,
};
*/

use crate::modified_scrape::{poly::{Scalar, Polynomial, ensure_degree, lagrange_interpolation_simple, lagrange_interpolation}};

use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_std::collections::BTreeMap;


use rand::Rng;
use std::ops::Neg;

use super::config::Config;

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
        SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = Scalar<E>>,
    > PVSSAggregator<E, SSIG>   // <E, SPOK, SSIG>
{

    // Method for handling a received PVSSAugmentedShare instance.
    pub fn receive_share<R: Rng>(
        &mut self,
        rng: &mut R,
        share: &PVSSAugmentedShare<E, SSIG>,
    ) -> Result<(), PVSSError<E>> {
	// Verify augmented PVSS share
        self.share_verify(rng, share)?;

	// 
        let transcript = PVSSTranscript {
            degree: self.config.degree,
            num_participants: self.participants.len(),
            contributions: vec![(
                share.participant_id,
                PVSSTranscriptParticipant {
                    c_i: share.c_i,
                    signature_on_c_i: share.signature_on_c_i.clone(),
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


/*

    // TODO: REVISE
    pub fn receive_transcript<R: Rng>(
        &mut self,
        rng: &mut R,
        transcript: &DKGTranscript<E, SPOK, SSIG>,
    ) -> Result<(), DKGError<E>> {
        let mut c = E::G1Projective::zero();
        let mut public_keys_sig = vec![];
        let mut messages_sig = vec![];
        let mut signatures_sig = vec![];

        let mut public_keys_pok = vec![];
        let mut messages_pok = vec![];
        let mut signatures_pok = vec![];

        for (participant_id, contribution) in transcript.contributions.iter() {
            let participant = self
                .participants
                .get(participant_id)
                .ok_or(DKGError::<E>::InvalidParticipantId(*participant_id))?;
            let message = message_from_c_i(contribution.c_i)?;

            public_keys_sig.push(&participant.public_key_sig);
            messages_sig.push(message.clone());
            signatures_sig.push(&contribution.signature_on_c_i);

            public_keys_pok.push(&contribution.c_i);
            messages_pok.push(message);
            signatures_pok.push(&contribution.c_i_pok);

            c += &contribution
                .c_i
                .mul(<E::Fr as From<u64>>::from(contribution.weight));
        }
        let sig_timer = start_timer!(|| "Signature batch verify");
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

        let pok_timer = start_timer!(|| "POK batch verify");
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

        let pvss_timer = start_timer!(|| "PVSS share verify");
        self.pvss_share_verify(rng, c.into_affine(), &transcript.pvss_share)?;
        end_timer!(pvss_timer);
        Ok(())
    }

*/


    // Method for verifying individual PVSS shares.
    pub fn pvss_share_verify<R: Rng>(
        &self,
        rng: &mut R,
        share: &PVSSShare<E>,
    ) -> Result<(), PVSSError<E>> {

	// Check that the sizes are correct
	if share.encs.len() != self.config.num_replicas ||
           share.comms.len() != self.config.num_replicas {
	    return Err(PVSSError::MismatchedCommitsEncryptionsReplicasError(share.encs.len(),
			share.comms.len(), self.config.num_replicas));
	}

	// Coding check for the commitments
	if (!ensure_degree::<E, _>(rng, &share.comms, config.degree)) {
            return Err(PVSSError::DualCodeError());
        }

        // Check decomposition proof
	let point = lagrange_interpolation_simple(share.comms, config.degree())

	if point != share.decomp_proof.gs {
	    return Err(PVSSError::GSCheckError);
	}

	// TODO: CONTINUE FROM HERE...

        // Reminder: Com_generator := g_2
        if !share.decomp_proof.proof.verify(Com_generator, point);   // need to know the pk of the party who sent the proof

        Ok(())

	// REFERENCE CODE BEYOND THIS POINT:

        // Verify evaluations are correct probabilistically.
        let alpha = E::Fr::rand(rng);
        let domain = Radix2EvaluationDomain::<E::Fr>::new(self.participants.len())
            .ok_or(DKGError::<E>::EvaluationDomainError)?;
        let lagrange_coefficients = domain
            .evaluate_all_lagrange_coefficients(alpha)
            .into_iter()
            .map(|c| c.into_repr())
            .collect::<Vec<_>>();

        {
            let mut bases = vec![];
            let mut scalars = vec![];
            bases.extend_from_slice(&share.a_i);
            scalars.extend_from_slice(&lagrange_coefficients);
            let powers_of_alpha = {
                let mut current_alpha = E::Fr::one().neg();
                let mut powers = vec![];
                for _ in 0..=self.config.degree {
                    powers.push(current_alpha.into_repr());
                    current_alpha *= &alpha;
                }
                powers
            };
            bases.extend_from_slice(&[vec![c_i], share.f_i.clone()].concat());
            scalars.extend_from_slice(&powers_of_alpha);
            let product = VariableBaseMSM::multi_scalar_mul(&bases, &scalars);
            if !product.is_zero() {
                return Err(DKGError::EvaluationsCheckError(product.into()));
            }
        }

        // Verify same ratio. Need this for security proof.
        let pairs = [
            (c_i.into(), self.config.u_1.into()),
            (self.config.srs.g_g1.neg().into(), share.u_i_2.into()),
        ];
        if !E::product_of_pairings(pairs.iter()).is_one() {
            return Err(DKGError::RatioIncorrect);
        }

        let powers_of_alpha = {
            let mut current_alpha = E::Fr::one();
            let mut powers = vec![];
            for _ in 0..=self.participants.len() {
                powers.push(current_alpha.into_repr());
                current_alpha *= &alpha;
            }
            powers
        };
        let (batched_a_i, batched_g_1_neg) = {
            let g_1_neg = self.config.srs.g_g1.neg();
            let batched_a_i = share
                .a_i
                .iter()
                .zip(powers_of_alpha.iter())
                .map(|(a, power)| a.mul(*power))
                .collect::<Vec<_>>();
            let batched_g_1_neg = powers_of_alpha
                .iter()
                .map(|power| g_1_neg.mul(*power))
                .collect::<Vec<_>>();
            let mut batched_all = vec![];
            batched_all.extend_from_slice(&batched_a_i);
            batched_all.extend_from_slice(&batched_g_1_neg);
            let batched_all = E::G1Projective::batch_normalization_into_affine(&batched_all);
            let batched_a_i = batched_all[..batched_a_i.len()]
                .into_iter()
                .map(|x| x.clone())
                .collect::<Vec<_>>();
            let batched_g_1_neg = batched_all[batched_a_i.len()..]
                .into_iter()
                .map(|x| x.clone())
                .collect::<Vec<_>>();
            (batched_a_i, batched_g_1_neg)
        };
        // Verify evaluations are encrypted correctly.
        let pairs = batched_a_i
            .into_iter()
            .zip(share.y_i.iter())
            .zip(batched_g_1_neg.into_iter())
            .enumerate()
            .map::<Result<Vec<(E::G1Prepared, E::G2Prepared)>, DKGError<E>>, _>(
                |(i, ((a, y), g_1_neg))| {
                    let participant = self
                        .participants
                        .get(&i)
                        .ok_or(DKGError::<E>::InvalidParticipantId(i))?;
                    let pairs = vec![
                        (g_1_neg.into(), (*y).into()),
                        (a.into(), participant.public_key_sig.into()),
                    ];

                    Ok(pairs)
                },
            )
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<(E::G1Prepared, E::G2Prepared)>>();
        if !E::product_of_pairings(pairs.iter()).is_one() {
            return Err(DKGError::RatioIncorrect);
        }

        Ok(())
    }



*/

    pub fn share_verify<R: Rng>(
        &mut self,
        rng: &mut R,
        share: &PVSSAugmentedShare<E, SSIG>,
    ) -> Result<(), PVSSError<E>> {
        let participant_id = share.participant_id;

        let participant = self
            .participants
            .get(&participant_id)
            .ok_or(PVSSError::<E>::InvalidParticipantId(participant_id))?;

        self.pvss_share_verify(rng, share.c_i, &share.pvss_share)?;

        // Verify signature on C_i by participant i.
        self.scheme_sig.verify(
            &participant.public_key_sig,
            &message_from_c_i(share.c_i)?,
            &share.signature_on_c_i,
        )?;

        // Verify POK of C_i.
        // self.scheme_pok
        //     .verify(&share.c_i, &message_from_c_i(share.c_i)?, &share.c_i_pok)?;

        Ok(())
    }

}