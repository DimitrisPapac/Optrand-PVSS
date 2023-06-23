use crate::{
    modified_scrape::{
        aggregator::PVSSAggregator,
        config::Config,
        dealer::Dealer,
        errors::PVSSError,
        participant::{Participant, ParticipantState},
        pvss::{PVSSShare, PVSSShareSecrets},
	decomp::{Decomp, DecompProof, message_from_pi_i},
    },
    signature::scheme::BatchVerifiableSignatureScheme,
};
use crate::modified_scrape::share::{PVSSTranscript, PVSSAugmentedShare};
use super::poly::{Polynomial, lagrange_interpolation, lagrange_interpolation_simple, ensure_degree};
use super::decryption::DecryptedShare;
use crate::{GT, Scalar};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField, UniformRand};

use rand::Rng;
use std::collections::BTreeMap;


/* Struct Node models the individual nodes participating in the PVSS sharing
*  protocol. Nodes can act as both dealers, as well as aggregators of share
*  sent from other parties. Hence, they have characteristics from both.
*/

pub struct Node<
    E: PairingEngine,
    SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = Scalar<E>>,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = Scalar<E>>,
> {
    pub aggregator: DKGAggregator<E, SPOK, SSIG>,     // the aggregator aspect of the node
    pub dealer: Dealer<E, SSIG>,                      // the dealer aspect of the node
}

impl<
        E: PairingEngine,
        SPOK: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = Scalar<E>>,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G2Affine, Secret = Scalar<E>>,
    > Node<E, SPOK, SSIG>
{

    // Function for creating a new node in the PVSS sharing protocol.
    pub fn new(
        config: Config<E>,
        scheme_pok: SPOK,   // might be redundant
        scheme_sig: SSIG,
        dealer: Dealer<E, SSIG>,
        participants: BTreeMap<usize, Participant<E, SSIG>>,
    ) -> Result<Self, PVSSError<E>> {
        let degree = config.degree;
        let num_participants = participants.len();
        let node = Node {
            aggregator: PVSSAggregator {
                config,
                scheme_pok,   // might be redundant
                scheme_sig,
                participants,
                transcript: PVSSTranscript::empty(degree, num_participants),
            },
            dealer,
        };
        Ok(node)
    }


    // Method for generating a core PVSS share.
    pub fn share_pvss<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(PVSSShare<E>, PVSSShareSecrets<E>), PVSSError<E>> {
	let t = self.aggregator.config.degree;
	let n = self.aggregator.config.num_participants;

	// Sample a random degree t polynomial
	let poly = Polynomial::<E>::rand(t, rng);

	// Evaluate poly(j) for all j in {1, ..., n}
	let mut evals = (1..n+1)
	    .map(|j| poly.evaluate(&Scalar::<E>::from(j as u64)))
	    .collect::<Vec<_>>();

	// Compute commitments for all nodes in {0, ..., n-1}
	let mut comms = (0..n)
	    .map(|j| config.srs.g2.mul(evals[j].into_repr()))
	    .collect::<Vec<_>>();

	// Compute encryptions for all nodes in {0, ..., n-1}
	let mut encs = (0..n)
	    .map::<Result<E::G2Affine, PVSSError<E>>, _>(|j| {
                Ok(self
                    .aggregator
                    .participants
                    .get(&j)
                    .ok_or(PVSSError::<E>::InvalidParticipantId(j))?
                    .public_key_sig
                    .mul(evals[j].into_repr())
                    .into_affine())
            })
            .collect::<Result<_, _>>()?;

	// Compose PVSS share
	let pvss_share = PVSSShare {
            comms,
	    encs,
	    // decomp_proof,
	    // sig_of_knowledge
        };

	// Generate my_secret
        let my_secret = self
            .aggregator
            .config
            .srs
            .g1
            .mul(evals[self.dealer.participant.id].into_repr())
            .into_affine();

	// Create PVSSShareSecrets
        let pvss_share_secrets = PVSSShareSecrets {
            p_0: poly.coeffs[0],
            my_secret,
        };

	// Return the result (OK)
	Ok((pvss_share, pvss_share_secrets))
    }


    // Method for generating a PVSSAugmentedShare instance for secret sharing.
    pub fn share<R: Rng>(&mut self, rng: &mut R) -> Result<PVSSAugmentedShare<E, SSIG>, PVSSError<E>> {
	// Create the core PVSSShare first.
	let (pvss_share, pvss_share_secrets) = self.share_pvss(rng)?;

	// Generate decomposition proof.
	let decomp_proof = Decomp::<E>::generate(rng, &aggregator.config, &pvss_share_secrets.p_0).unwrap();

	// Use the (private) signing key contained in the dealer instance to also compute
	// the public key w.r.t. the signature scheme indicated by the aggregator instance.
	let signature_keypair = self
            .aggregator
            .scheme_sig
            .from_sk(&(self.dealer.private_key_sig))?;

	// Sign the decomposition proof.
	let signature_on_decomp =
            Some(self.aggregator
                .scheme_sig
                .sign(rng, &signature_keypair.0, &message_from_pi_i(decomp_proof)?)?);

	// Create the augmented PVSS share.
	let share = PVSSAugmentedShare {
            participant_id: self.dealer.participant.id,
            pvss_share,
	    decomp_proof,
            signature_on_decomp,
        };

	// Set dealer instance's state to DealerShared.
        self.dealer.participant.state = ParticipantState::DealerShared;

        Ok(share)
    }


    // Assumes that the participant id has been authenticated.
    pub fn receive_share_and_decrypt<R: Rng>(
        &mut self,
        rng: &mut R,
        share: PVSSAugmentedShare<E, SSIG>,
    ) -> Result<(), PVSSError<E>> {
	// Retrieve participant's id from the share
	let participant_id = share.participant_id;

	// Anonymous function for performing the decryption
	match (|| -> Result<DecryptedShare<E>, PVSSError<E>> {   // Result<E::G2Affine, PVSSError<E>>
            self.aggregator.receive_share(rng, &share)?;   // ................
	    
	    /*
	    // decryption occurs here
            let secret = share.pvss_share.encs[self.dealer.participant.id]
                .mul(self.dealer.private_key_sig.inverse().unwrap().into_repr())
                .into_affine();
	    */

	    // decrypt share
	    let secret = DecryptedShare::generate(share.pvss_share.encs[self.dealer.participant.id],
		self.dealer.private_key_sig,
		self.dealer.participant.id);

            Ok(secret)
        })() {
            Ok(secret) => {
                self.dealer.accumulated_secret = self.dealer.accumulated_secret + secret;   // ?????
                let participant = self
                    .aggregator
                    .participants
                    .get_mut(&participant_id)
                    .ok_or(PVSSError::<E>::InvalidParticipantId(participant_id))?;
                participant.state = ParticipantState::Verified;
            }
            Err(_) => {}
        };

	Ok(())
    }


/*
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


    // Method for reconstructing the shared secret and beacon value.
    pub fn reconstruct(
	&mut self,
	decryptions: &Vec<DecryptedShare<E>>
	) -> Result<(E::G1Affine, GT<E>), PVSSError<E>> {

	let degree = self.aggregator.config.degree as u64;

	if decryptions.len() <= degree {
	    return Err(PVSSError::InsufficientDecryptionsError(decryptions.size(), self.aggregator.config.degree));
	}

	// NOTE: Mind the +1 when extracting the origin
	let (points, evals): (Vec<_>, Vec<_>) = (0..decryptions.len())
	    .map(|i| (decryptions[i].origin + 1, decryptions[i].dec))
	    .unzip();

	// Lagrange interpolation over group G_1
	match (|| -> Result<E::G1Projective, PVSSError<E>> {
            let mut sum = E::G1Projective::zero();

    	    for j in 0..degree+1 {
                let x_j = points[j as usize];
	        let mut prod = Scalar::<E>::one();
	        for k in 0..degree+1 {
	            if j != k {
	                let x_k = points[k as usize];
	                prod *= x_k * (x_k - x_j).inverse().unwrap();
	            }
	        }

	        // Recovery formula
	        sum += evals[j as usize].mul(prod.into_repr());
            }

            Ok(sum)
        })() {
            Ok(sum) => {
                let point = sum.into_affine();
            }
            Err(_) => {}
        };

	// Compute the "beacon value"
	let S = E::pairing(point, self.aggregator.config.g2_prime);   // in <E as PairingEngine>::Fqk

	Ok((point, S))
    }

}
