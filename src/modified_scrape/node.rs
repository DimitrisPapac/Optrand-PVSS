use crate::{
    modified_scrape::{
        aggregator::PVSSAggregator,
        config::Config,
        dealer::Dealer,
        errors::PVSSError,
        participant::{Participant, ParticipantState},
        pvss::{PVSSCore, PVSSShareSecrets},
	share::{PVSSAggregatedShare, PVSSShare},
	decomp::{Decomp, DecompProof, message_from_pi_i},
    },
    signature::scheme::BatchVerifiableSignatureScheme,
};
use crate::modified_scrape::share::{PVSSAggregatedShare, PVSSShare};
use super::poly::{Polynomial, lagrange_interpolation, lagrange_interpolation_simple, ensure_degree};
use super::decryption::DecryptedShare;
use crate::{GT, Scalar, Signature};

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
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = Scalar<E>>,
> {
    pub aggregator: PVSSAggregator<E, SSIG>,    // the aggregator aspect of the node
    pub dealer: Dealer<E, SSIG>,                // the dealer aspect of the node
}

impl<
        E: PairingEngine,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = Scalar<E>>,
    > Node<E, SSIG>
{

    // Function for creating a new node in the PVSS sharing protocol.
    pub fn new(
        config: Config<E>,
        scheme_sig: SSIG,
        dealer: Dealer<E, SSIG>,
        participants: BTreeMap<usize, Participant<E, SSIG>>,
    ) -> Result<Self, PVSSError<E>> {
        let degree = config.degree;
        let num_participants = participants.len();
        let node = Node {
            aggregator: PVSSAggregator {
                config,
                scheme_sig,
                participants,
                aggregated_tx: PVSSAggregatedShare::empty(degree, num_participants),
            },
            dealer,
        };
        Ok(node)
    }


    // Utility method for generating a core of a PVSS share.
    pub fn share_pvss<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(PVSSCore<E>, PVSSShareSecrets<E>), PVSSError<E>> {
        let t = self.aggregator.config.degree;
	let n = self.aggregator.config.num_participants;

	// Sample a random degree t polynomial
	let poly = Polynomial::<E>::rand(t, rng);

	// Evaluate poly(j) for all j in {1, ..., n}
	let mut evals = (1..n+1)
	        .map(|j| poly.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

	// Compute commitments for all nodes in {0, ..., n-1}
        // Recall that G2 is the commitment group.
	let mut comms = (0..n)
	        .map(|j| config.srs.g2.mul(evals[j].into_repr()))
	        .collect::<Vec<_>>();

	// Compute encryptions for all nodes in {0, ..., n-1}
	let mut encs = (0..n)
	        .map::<Result<E::G1Affine, PVSSError<E>>, _>(|j| {
                    Ok(self
                        .aggregator
                        .participants
                        .get(&j)
                        .ok_or(PVSSError::<E>::InvalidParticipantId(j))?
                        .public_key_sig   // obtain participant's public (encryption) key
                        .mul(evals[j].into_repr())
                        .into_affine())
                    })
                .collect::<Result<_, _>>()?;

	// Compose PVSS core
	let pvss_share = PVSSCore {
            comms,
	    encs,
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

	// Return the result
	Ok((pvss_core, pvss_share_secrets))
    }


    // Method for creating a PVSSShare instance for secret sharing.
    pub fn share<R: Rng>(&mut self, rng: &mut R) -> Result<PVSSShare<E>, PVSSError<E>> {
        // Create the core PVSSCore first.
	let (pvss_core, pvss_share_secrets) = self.share_pvss(rng)?;

	// Generate decomposition proof.
	let decomp_proof = Decomp::<E>::generate(rng, &aggregator.config, &pvss_share_secrets.p_0).unwrap();

	// Use the (private) signing key contained in the dealer instance to also compute
	// the public key w.r.t. the signature scheme indicated by the aggregator instance.
	//let signature_keypair = self
        //        .aggregator
        //        .scheme_sig
        //        .from_sk(&(self.dealer.private_key_sig))?;

	// ISSUE: Need to compute digest from decomp_proof
        let digest = ...........................;

        // Sign the decomposition proof using EdDSA
	let signature_on_decomp = Some(Signature::new(&digest, &self.dealer.private_key_ed))?;   // internally retrieves the key pair

	// Create the PVSS share.
	let share = PVSSShare {
            participant_id: self.dealer.participant.id,
            pvss_core,
	    decomp_proof,
            signature_on_decomp,
        };

	// Set dealer instance's state to DealerShared.
        self.dealer.participant.state = ParticipantState::DealerShared;

        Ok(share)
    }


/*
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


/*
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
*/
    
}


/* Unit tests: */

#[cfg(test)]
mod test {
    use crate::{
        dkg::{
            aggregator::DKGAggregator,
            config::Config,
            dealer::Dealer,
            node::Node,
            participant::{Participant, ParticipantState},
            share::DKGTranscript,
            srs::SRS,
        },
        signature::{
            bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
            scheme::{BatchVerifiableSignatureScheme, SignatureScheme},
            schnorr::{srs::SRS as SchnorrSRS, SchnorrSignature},
        },
    };
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::ProjectiveCurve;
    use ark_ff::{UniformRand, Zero};
    use rand::thread_rng;

    use std::marker::PhantomData;

    #[test]
    fn test_one() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.h_g2,
                g_signature: srs.g_g1,
            },
        };
        let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.g_g1,
                g_signature: srs.h_g2,
            },
        };
        let dealer_keypair_sig = bls_sig.generate_keypair(rng).unwrap();
        let dealer = Dealer {
            private_key_sig: dealer_keypair_sig.0,
            accumulated_secret: G2Projective::zero().into_affine(),
            participant: Participant {
                pairing_type: PhantomData,
                id: 0,
                public_key_sig: dealer_keypair_sig.1,
                state: ParticipantState::Dealer,
            },
        };

        let u_1 = G2Projective::rand(rng).into_affine();
        let dkg_config = Config {
            srs: srs.clone(),
            u_1,
            degree: 10,
        };

        let participants = vec![dealer.participant.clone()];
        let degree = dkg_config.degree;
        let num_participants = participants.len();

        let mut node = Node {
            aggregator: DKGAggregator {
                config: dkg_config.clone(),
                scheme_pok: bls_pok.clone(),
                scheme_sig: bls_sig.clone(),
                participants: participants.clone().into_iter().enumerate().collect(),
                transcript: DKGTranscript::empty(degree, num_participants),
            },
            dealer,
        };

        node.share(rng).unwrap();
    }

    #[test]
    fn test_2_nodes_verify() {
        const NODES: usize = 4;

        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.h_g2,
                g_signature: srs.g_g1,
            },
        };
        let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.g_g1,
                g_signature: srs.h_g2,
            },
        };

        let u_1 = G2Projective::rand(rng).into_affine();
        let dkg_config = Config {
            srs: srs.clone(),
            u_1,
            degree: 2,
        };

        let mut dealers = vec![];
        for i in 0..NODES {
            let dealer_keypair_sig = bls_sig.generate_keypair(rng).unwrap();
            let participant = Participant {
                pairing_type: PhantomData,
                id: i,
                public_key_sig: dealer_keypair_sig.1,
                state: ParticipantState::Dealer,
            };
            let dealer = Dealer {
                private_key_sig: dealer_keypair_sig.0,
                accumulated_secret: G2Projective::zero().into_affine(),
                participant,
            };

            dealers.push(dealer);
        }

        let participants = dealers
            .iter()
            .map(|d| d.participant.clone())
            .collect::<Vec<_>>();
        let mut nodes = vec![];
        for i in 0..NODES {
            let degree = dkg_config.degree;
            let num_participants = participants.len();
            let node = Node {
                aggregator: DKGAggregator {
                    config: dkg_config.clone(),
                    scheme_pok: bls_pok.clone(),
                    scheme_sig: bls_sig.clone(),
                    participants: participants.clone().into_iter().enumerate().collect(),
                    transcript: DKGTranscript::empty(degree, num_participants),
                },
                dealer: dealers[i].clone(),
            };
            nodes.push(node);
        }
        for i in 0..NODES {
            let node = &mut nodes[i];
            let share = node.share(rng).unwrap();
            for j in 0..NODES {
                nodes[j]
                    .receive_share_and_decrypt(rng, share.clone())
                    .unwrap();
            }
        }
    }

    #[test]
    fn test_2_nodes_and_aggregator_bls() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let bls_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.h_g2,
                g_signature: srs.g_g1,
            },
        };
        let bls_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.g_g1,
                g_signature: srs.h_g2,
            },
        };
        test_2_nodes_and_aggregator_with_signature_scheme(srs, bls_pok, bls_sig);
    }
    #[test]
    fn test_2_nodes_and_aggregator_schnorr() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature::<G2Affine> {
            srs: SchnorrSRS {
                g_public_key: srs.h_g2,
            },
        };
        let schnorr_pok = SchnorrSignature::<G1Affine> {
            srs: SchnorrSRS {
                g_public_key: srs.g_g1,
            },
        };
        test_2_nodes_and_aggregator_with_signature_scheme(srs, schnorr_pok, schnorr_sig);
    }

    fn test_2_nodes_and_aggregator_with_signature_scheme<
        SPOK: BatchVerifiableSignatureScheme<PublicKey = G1Affine, Secret = Fr>,
        SSIG: BatchVerifiableSignatureScheme<PublicKey = G2Affine, Secret = Fr>,
    >(
        srs: SRS<Bls12_381>,
        spok: SPOK,
        ssig: SSIG,
    ) {
        const NODES: usize = 4;

        let rng = &mut thread_rng();

        let u_1 = G2Projective::rand(rng).into_affine();
        let dkg_config = Config {
            srs: srs.clone(),
            u_1,
            degree: 2,
        };

        let mut dealers = vec![];
        for i in 0..NODES {
            let dealer_keypair_sig = ssig.generate_keypair(rng).unwrap();
            let participant = Participant {
                pairing_type: PhantomData,
                id: i,
                public_key_sig: dealer_keypair_sig.1,
                state: ParticipantState::Dealer,
            };
            let dealer = Dealer {
                private_key_sig: dealer_keypair_sig.0,
                accumulated_secret: G2Projective::zero().into_affine(),
                participant,
            };

            dealers.push(dealer);
        }

        let participants = dealers
            .iter()
            .map(|d| d.participant.clone())
            .collect::<Vec<_>>();
        let num_participants = participants.len();

        let mut aggregator = DKGAggregator {
            config: dkg_config.clone(),
            scheme_pok: spok.clone(),
            scheme_sig: ssig.clone(),
            participants: participants.clone().into_iter().enumerate().collect(),
            transcript: DKGTranscript::empty(dkg_config.degree, num_participants),
        };

        let mut nodes = vec![];
        for i in 0..NODES {
            let degree = dkg_config.degree;
            let node = Node {
                aggregator: DKGAggregator {
                    config: dkg_config.clone(),
                    scheme_pok: spok.clone(),
                    scheme_sig: ssig.clone(),
                    participants: participants.clone().into_iter().enumerate().collect(),
                    transcript: DKGTranscript::empty(degree, num_participants),
                },
                dealer: dealers[i].clone(),
            };
            nodes.push(node);
        }
        // Make participant 0 have weight 2.
        // Should ignore participant 1, since we modify its share to be bad.
        for i in 0..NODES {
            let node = &mut nodes[i];
            let mut share = node.share(rng).unwrap();
            for j in 0..NODES {
                if i == 1 {
                    share.c_i = G1Projective::rand(rng).into_affine();
                }

                nodes[j]
                    .receive_share_and_decrypt(rng, share.clone())
                    .unwrap();
                if i == 0 {
                    nodes[j]
                        .receive_share_and_decrypt(rng, share.clone())
                        .unwrap();
                }
            }
            if i != 1 {
                aggregator.receive_share(rng, &share.clone()).unwrap();
                if i == 0 {
                    aggregator.receive_share(rng, &share.clone()).unwrap();
                }
            } else {
                aggregator.receive_share(rng, &share.clone()).unwrap_err();
            }
        }

        let transcript = aggregator.transcript;
        for i in 0..NODES {
            let degree = dkg_config.degree;
            let mut node = Node {
                aggregator: DKGAggregator {
                    config: dkg_config.clone(),
                    scheme_pok: spok.clone(),
                    scheme_sig: ssig.clone(),
                    participants: participants.clone().into_iter().enumerate().collect(),
                    transcript: DKGTranscript::empty(degree, num_participants),
                },
                dealer: dealers[i].clone(),
            };
            node.receive_transcript_and_decrypt(rng, transcript.clone())
                .unwrap();
            assert_eq!(
                node.dealer.accumulated_secret,
                nodes[i].dealer.accumulated_secret
            );
            if i == 0 {
                assert_eq!(transcript.contributions[&i].weight, 2);
            } else if i == 1 {
                assert!(transcript.contributions.get(&i).is_none());
            } else {
                assert_eq!(transcript.contributions[&i].weight, 1);
            }
        }
    }
}
