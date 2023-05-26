use crate::{
    modified_scrape::{
        //aggregator::PVSSAggregator,
        config::Config,
        dealer::Dealer,
        errors::PVSSError,
        participant::{Participant, ParticipantState},
        pvss::{PVSSShare, PVSSShareSecrets},
        //share::{message_from_c_i, DKGShare, DKGTranscript},
    },
    signature::scheme::BatchVerifiableSignatureScheme,
};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, UniformRand};
//use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::Rng;
use std::collections::BTreeMap;

/*  */

pub struct Node<
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
> {
    // TODO: uncomment
    //pub aggregator: DKGAggregator<E, SPOK, SSIG>,   // the aggregator aspect of the node
    pub dealer: Dealer<E, SSIG>,                      // the dealer aspect of the node
}

impl<
        E: PairingEngine,
        SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = E::Fr>,
    > Node<E, SPOK, SSIG>
{

/*
    pub fn new(
        config: Config<E>,
        scheme_pok: SPOK,
        scheme_sig: SSIG,
        dealer: Dealer<E, SSIG>,
        participants: BTreeMap<usize, Participant<E, SSIG>>,
    ) -> Result<Self, PVSSError<E>> {
        let degree = config.degree;
        let num_participants = participants.len();
        let node = Node {
            aggregator: DKGAggregator {
                config,
                scheme_pok,
                scheme_sig,
                participants,
                transcript: DKGTranscript::empty(degree, num_participants),
            },
            dealer,
        };
        Ok(node)
    }
*/


    pub fn share_pvss<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(PVSSShare<E>, PVSSShareSecrets<E>), PVSSError<E>> {
	



        let mut f = (0..=self.aggregator.config.degree)
            .map(|_| E::Fr::rand(rng))
            .collect::<Vec<_>>();
        let domain = Radix2EvaluationDomain::<E::Fr>::new(self.aggregator.participants.len())
            .ok_or(DKGError::<E>::EvaluationDomainError)?;
        let y_eval_i = domain.fft(&mut f);

        let f_i = f[1..=self.aggregator.config.degree]
            .iter()
            .map(|a| {
                self.aggregator
                    .config
                    .srs
                    .g_g1
                    .mul(a.into_repr())
                    .into_affine()
            })
            .collect::<Vec<_>>();
        let u_i_2 = self
            .aggregator
            .config
            .u_1
            .mul(f[0].into_repr())
            .into_affine();
        let a_i = y_eval_i
            .iter()
            .map(|a| {
                self.aggregator
                    .config
                    .srs
                    .g_g1
                    .mul(a.into_repr())
                    .into_affine()
            })
            .collect::<Vec<_>>();
        let y_i = y_eval_i
            .iter()
            .enumerate()
            .map::<Result<E::G2Affine, DKGError<E>>, _>(|(i, a)| {
                Ok(self
                    .aggregator
                    .participants
                    .get(&i)
                    .ok_or(DKGError::<E>::InvalidParticipantId(i))?
                    .public_key_sig
                    .mul(a.into_repr())
                    .into_affine())
            })
            .collect::<Result<_, _>>()?;
        let pvss_share = PVSSShare {
            f_i,
            u_i_2,
            a_i,
            y_i,
        };

        let my_secret = self
            .aggregator
            .config
            .srs
            .h_g2
            .mul(y_eval_i[self.dealer.participant.id].into_repr())
            .into_affine();

        let pvss_share_secrets = PVSSShareSecrets {
            f_0: f[0],
            my_secret,
        };

        Ok((pvss_share, pvss_share_secrets))
    }

/*
    pub fn share<R: Rng>(&mut self, rng: &mut R) -> Result<DKGShare<E, SPOK, SSIG>, DKGError<E>> {
        let (pvss_share, pvss_share_secrets) = self.share_pvss(rng)?;
        let c_i = self
            .aggregator
            .config
            .srs
            .g_g1
            .mul(pvss_share_secrets.f_0.into_repr())
            .into_affine();

        let pok_keypair = self
            .aggregator
            .scheme_pok
            .from_sk(&pvss_share_secrets.f_0)?;
        let pok = self
            .aggregator
            .scheme_pok
            .sign(rng, &pok_keypair.0, &message_from_c_i(c_i)?)?;

        let signature_keypair = self
            .aggregator
            .scheme_sig
            .from_sk(&(self.dealer.private_key_sig))?;
        let signature =
            self.aggregator
                .scheme_sig
                .sign(rng, &signature_keypair.0, &message_from_c_i(c_i)?)?;

        let share = DKGShare {
            participant_id: self.dealer.participant.id,
            c_i,
            pvss_share,
            c_i_pok: pok,
            signature_on_c_i: signature,
        };

        self.dealer.participant.state = ParticipantState::DealerShared;
        Ok(share)
    }

    // Assumes that the participant id has been authenticated.
    pub fn receive_share_and_decrypt<R: Rng>(
        &mut self,
        rng: &mut R,
        share: DKGShare<E, SPOK, SSIG>,
    ) -> Result<(), DKGError<E>> {
        let participant_id = share.participant_id;

        match (|| -> Result<E::G2Affine, DKGError<E>> {
            self.aggregator.receive_share(rng, &share)?;

            let secret = share.pvss_share.y_i[self.dealer.participant.id]
                .mul(self.dealer.private_key_sig.inverse().unwrap().into_repr())
                .into_affine();

            Ok(secret)
        })() {
            Ok(secret) => {
                self.dealer.accumulated_secret = self.dealer.accumulated_secret + secret;
                let participant = self
                    .aggregator
                    .participants
                    .get_mut(&participant_id)
                    .ok_or(DKGError::<E>::InvalidParticipantId(participant_id))?;
                participant.state = ParticipantState::Verified;
            }
            Err(_) => {}
        };

        Ok(())
    }

    // Assumes that the participant id has been authenticated.
    pub fn receive_transcript_and_decrypt<R: Rng>(
        &mut self,
        rng: &mut R,
        transcript: DKGTranscript<E, SPOK, SSIG>,
    ) -> Result<(), DKGError<E>> {
        self.aggregator.receive_transcript(rng, &transcript)?;

        let secret = transcript.pvss_share.y_i[self.dealer.participant.id]
            .mul(self.dealer.private_key_sig.inverse().unwrap().into_repr())
            .into_affine();

        for (participant_id, _) in transcript.contributions {
            let participant = self
                .aggregator
                .participants
                .get_mut(&participant_id)
                .ok_or(DKGError::<E>::InvalidParticipantId(participant_id))?;
            participant.state = ParticipantState::Verified;
        }
        self.dealer.accumulated_secret = self.dealer.accumulated_secret + secret;

        Ok(())
    }
*/
}