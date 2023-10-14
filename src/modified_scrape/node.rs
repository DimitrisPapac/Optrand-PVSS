use crate::{
    modified_scrape::{
        aggregator::PVSSAggregator,
        config::Config,
        dealer::Dealer,
        errors::PVSSError,
        participant::Participant,
        pvss::{PVSSCore, PVSSShareSecrets},
	    share::{PVSSAggregatedShare, PVSSShare, SignedProof},
        decomp::Decomp,
        poly::Polynomial as Poly,
    },
    Scalar,
    Signature,
    signature::scheme::BatchVerifiableSignatureScheme,
};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_poly::{Polynomial, UVPolynomial};
use ark_std::collections::BTreeMap;

use rand::Rng;


/* Struct Node models the individual nodes participating in the PVSS sharing
*  protocol. Nodes can act as both dealers, as well as aggregators of share
*  sent from other parties. Hence, they have characteristics from both.
*/

pub struct Node<E, SSIG>
where
    E: PairingEngine,
    //<E as PairingEngine>::G2Affine: AddAssign,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
{
    pub aggregator: PVSSAggregator<E, SSIG>,    // the aggregator aspect of the node
    pub dealer: Dealer<E, SSIG>,                // the dealer aspect of the node
}

impl<E, SSIG> Node<E, SSIG>
where
    E: PairingEngine,
    //<E as PairingEngine>::G2Affine: AddAssign,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = E::G1Affine, Secret = E::Fr>,
{

    // Function for initializing a new node in the PVSS sharing protocol.
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
	// Retrieve scheme parameters
        let t = self.aggregator.config.degree;
	let n = self.aggregator.config.num_participants;

	// Sample a random degree t polynomial
	let poly = Poly::<E>::rand(t, rng);

	// Evaluate poly(j) for all j in {1, ..., n}
	let evals = (1..=n)
	        .map(|j| poly.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

	// Compute commitments for all nodes in {0, ..., n-1}
        // Recall that G2 is the commitment group.
	let comms = (0..=(n-1))
	        .map(|j| self.aggregator.config.srs.g2.mul(evals[j].into_repr()).into_affine())
	        .collect::<Vec<_>>();

	// Compute encryptions for all nodes in {0, ..., n-1}
	let encs = (0..=(n-1))
	        .map::<Result<E::G1Affine, PVSSError<E>>, _>(|j| {
                    Ok(self
                        .aggregator
                        .participants
                        .get(&j)
                        .ok_or(PVSSError::<E>::InvalidParticipantId(j))?
                        .public_key_sig   // obtain participant's public (encryption) key
                        .mul(evals[j].into_repr())
                        .into_affine()
                        )
                    })
                .collect::<Result<_, _>>()?;

	// Compose PVSS core
	let pvss_core = PVSSCore {
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
	let mut decomp_proof = Decomp::<E>::generate(rng, &self.aggregator.config, &pvss_share_secrets.p_0).unwrap();

        let digest = decomp_proof.digest();

        println!("Party {} now signing NIZK proof:", self.dealer.participant.id);
        println!("\n");
        println!("NIZK proof's digest is:\n{:?}", digest);
        println!("\n");
        println!("Party {}'s EdDSA signing key is:\n{:?}", self.dealer.participant.id, self.dealer.private_key_ed);
        println!("\n");
        println!("Party {}'s EdDSA matching verification key is:\n{:?}", self.dealer.participant.id, self.dealer.participant.public_key_ed);
        println!("\n==========================================\n");

        // Sign the decomposition proof using EdDSA
	let signature_on_decomp = Signature::new(&digest, &self.dealer.private_key_ed);

    let signed_proof = SignedProof::<E> {
        decomp_proof,
        signature_on_decomp,
    };

	// Create the PVSS share.
	let share = PVSSShare {
            participant_id: self.dealer.participant.id,
            pvss_core,
	        signed_proof,
    };

	// Set dealer instance's state to DealerShared.
        // self.dealer.participant.state = ParticipantState::DealerShared;

        Ok(share)
    }
    
}


/* Unit tests: */


#[cfg(test)]
mod test {
    use crate::{
        modified_scrape::{
            aggregator::PVSSAggregator,
            config::Config,
            dealer::Dealer,
            participant::Participant,
	    share::PVSSAggregatedShare,
	    srs::SRS,
	    node::{Node, self},
        },
	signature::{
	    schnorr::{SchnorrSignature, srs::SRS as SCHSRS},
            scheme::SignatureScheme,
    	},
	generate_production_keypair,
    };

    use ark_bls12_381::{
	Bls12_381,                         // type Bls12_381 = Bls12<Parameters> (Bls12 implements PairingEngine)
    };
    use ark_ec::PairingEngine;
    use ark_std::collections::BTreeMap;
    use rand::thread_rng;

    use std::marker::PhantomData;

    #[test]
    fn test_one() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let schnorr_srs = SCHSRS::<<Bls12_381 as PairingEngine>::G1Affine>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // generate key pairs
        let dealer_keypair_sig = schnorr_sig.generate_keypair(rng).unwrap();   // (sk, pk)
        let eddsa_keypair = generate_production_keypair();                     // (pk, sk)

        // create the dealer instance
        let dealer: Dealer<Bls12_381,   //Bls12<ark_bls12_381::Parameters>,
			   SchnorrSignature<<Bls12_381 as PairingEngine>::G1Affine>> = Dealer {
            private_key_sig: dealer_keypair_sig.0,
    	    private_key_ed: eddsa_keypair.1,
            participant: Participant {
                pairing_type: PhantomData,
                id: 0,
                public_key_sig: dealer_keypair_sig.1,
		public_key_ed: eddsa_keypair.0,
            },
        };

        // set global configuration parameters
        let config = Config {
            srs: srs.clone(),
            degree: 1,
	    num_participants: 1,
        };

        let participants = vec![dealer.participant.clone()];
        let num_participants = participants.len();
        let degree = config.degree;

        // create the aggregator instance
        let aggregator: PVSSAggregator<Bls12_381,
			   SchnorrSignature<<Bls12_381 as PairingEngine>::G1Affine>> = PVSSAggregator {
                config: config.clone(),
                scheme_sig: schnorr_sig.clone(),
                participants: participants.clone().into_iter().enumerate().collect(),
                aggregated_tx: PVSSAggregatedShare::empty(degree, num_participants),
        };
        
        // create the node instance
        let mut node = Node {
            aggregator,
            dealer,
        };

        // invoke share to create a PVSS share
        node.share(rng).unwrap();
    }

    #[test]
    fn test_aggregation_with_4_nodes() {
        let rng = &mut thread_rng();

        // Global settings
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let schnorr_srs = SCHSRS::<<Bls12_381 as PairingEngine>::G1Affine>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // Set global configuration parameters
        let config = Config {
            srs: srs.clone(),
            degree: 2,
            num_participants: 4,
        };

        // Generate key pairs for party A
        let dealer_keypair_sig_a = schnorr_sig.generate_keypair(rng).unwrap();   // (sk, pk)
        let eddsa_keypair_a = generate_production_keypair();                     // (pk, sk)

        // Create the dealer instance for party A
        let dealer_a: Dealer<Bls12_381,   //Bls12<ark_bls12_381::Parameters>,
			   SchnorrSignature<<Bls12_381 as PairingEngine>::G1Affine>> = Dealer {
            private_key_sig: dealer_keypair_sig_a.0,
    	    private_key_ed: eddsa_keypair_a.1,
            participant: Participant {
                pairing_type: PhantomData,
                id: 0,
                public_key_sig: dealer_keypair_sig_a.1,
                public_key_ed: eddsa_keypair_a.0,
            },
        };

        // Generate key pairs for party B
        let dealer_keypair_sig_b = schnorr_sig.generate_keypair(rng).unwrap();   // (sk, pk)
        let eddsa_keypair_b = generate_production_keypair();                     // (pk, sk)

        // Create the dealer instance for party B
        let dealer_b: Dealer<Bls12_381,   //Bls12<ark_bls12_381::Parameters>,
			   SchnorrSignature<<Bls12_381 as PairingEngine>::G1Affine>> = Dealer {
            private_key_sig: dealer_keypair_sig_b.0,
    	    private_key_ed: eddsa_keypair_b.1,
            participant: Participant {
                pairing_type: PhantomData,
                id: 1,
                public_key_sig: dealer_keypair_sig_b.1,
                public_key_ed: eddsa_keypair_b.0,
            },
        };

        // Generate key pairs for party C
        let dealer_keypair_sig_c = schnorr_sig.generate_keypair(rng).unwrap();   // (sk, pk)
        let eddsa_keypair_c = generate_production_keypair();                     // (pk, sk)

        // Create the dealer instance for party C
        let dealer_c: Dealer<Bls12_381,   //Bls12<ark_bls12_381::Parameters>,
			   SchnorrSignature<<Bls12_381 as PairingEngine>::G1Affine>> = Dealer {
            private_key_sig: dealer_keypair_sig_c.0,
    	    private_key_ed: eddsa_keypair_c.1,
            participant: Participant {
                pairing_type: PhantomData,
                id: 2,
                public_key_sig: dealer_keypair_sig_c.1,
                public_key_ed: eddsa_keypair_c.0,
            },
        };

        // Generate key pairs for party D
        let dealer_keypair_sig_d = schnorr_sig.generate_keypair(rng).unwrap();   // (sk, pk)
        let eddsa_keypair_d = generate_production_keypair();                     // (pk, sk)

        // Create the dealer instance for party D
        let dealer_d: Dealer<Bls12_381,   //Bls12<ark_bls12_381::Parameters>,
			   SchnorrSignature<<Bls12_381 as PairingEngine>::G1Affine>> = Dealer {
            private_key_sig: dealer_keypair_sig_d.0,
    	    private_key_ed: eddsa_keypair_d.1,
            participant: Participant {
                pairing_type: PhantomData,
                id: 3,
                public_key_sig: dealer_keypair_sig_d.1,
                public_key_ed: eddsa_keypair_d.0,
            },
        };

        let participants_vec = vec![
            dealer_a.participant.clone(),
            dealer_b.participant.clone(),
            dealer_c.participant.clone(),
            dealer_d.participant.clone(),
        ];
        let num_participants = participants_vec.len();
        let _degree = config.degree;

        let mut participants = BTreeMap::new();
        for (id, party) in (0..num_participants).zip(participants_vec) {
            participants.insert(id, party);
        }
        
        // Create the node instance for party A
        let mut node_a = Node::new(
            config.clone(),
            schnorr_sig.clone(),
            dealer_a,
            participants.clone(),
        ).unwrap();
        
        // Create the node instance for party B
        let mut node_b = Node::new(
            config.clone(),
            schnorr_sig.clone(),
            dealer_b,
            participants.clone(),
        ).unwrap();
        
        // Create the node instance for party C
        let mut node_c = Node::new(
            config.clone(),
            schnorr_sig.clone(),
            dealer_c,
            participants.clone(),
        ).unwrap();
        
        // Create the node instance for party D
        let mut node_d = Node::new(
            config.clone(),
            schnorr_sig.clone(),
            dealer_d,
            participants.clone(),
        ).unwrap();

        // Nodes generate their PVSSShares:
        let mut pvss_a = node_a.share(rng).unwrap();
        let mut pvss_b = node_b.share(rng).unwrap();
        let mut pvss_c = node_c.share(rng).unwrap();
        let mut pvss_d = node_d.share(rng).unwrap();

        println!("LEVEL 1:\n");

        // Party A aggregates its own share
        node_a.aggregator.receive_share(rng, &mut pvss_a).unwrap();   // works
        // Party A gets party B's share through communication
        node_a.aggregator.receive_share(rng, &mut pvss_b).unwrap();   // works

        // Party B aggregates its own share
        node_b.aggregator.receive_share(rng, &mut pvss_b).unwrap();   // works
        // Party B gets party A's share through communication
        node_b.aggregator.receive_share(rng, &mut pvss_a).unwrap();   // works

        // Party C aggregates its own share
        node_c.aggregator.receive_share(rng, &mut pvss_c).unwrap();   // works
        // Party C gets party D's share through communication
        node_c.aggregator.receive_share(rng, &mut pvss_d).unwrap();   // works

        // Party D aggregates its own share
        node_d.aggregator.receive_share(rng, &mut pvss_d).unwrap();   // works
        // Party D gets party C's share through communication
        node_d.aggregator.receive_share(rng, &mut pvss_c).unwrap();   // works

        // Parties A and B should at this point hold the same aggregated transcript
        assert_eq!(node_a.aggregator.aggregated_tx, node_b.aggregator.aggregated_tx);

        // Parties C and D should at this point hold the same aggregated transcript
        assert_eq!(node_c.aggregator.aggregated_tx, node_d.aggregator.aggregated_tx);

        // Aggregated share of the left subcommittee
        let agg_share_ab = node_a.aggregator.aggregated_tx.clone();
        // Aggregated share of the right subcommittee
        let agg_share_cd = node_c.aggregator.aggregated_tx.clone();

        println!("LEVEL 2:\n");

        // Right subcommittee receives the left subcommittee's aggregated share
        node_c.aggregator.receive_aggregated_share(rng, &agg_share_ab).unwrap();   // EdDSAInvalidSignatureBatchError
        node_d.aggregator.receive_aggregated_share(rng, &agg_share_ab).unwrap();

        // Left subcommittee receives the right subcommittee's aggregated share
        node_a.aggregator.receive_aggregated_share(rng, &agg_share_cd).unwrap();
        node_b.aggregator.receive_aggregated_share(rng, &agg_share_cd).unwrap();

        // All nodes should now hold the exact same aggregated transcript
        assert_eq!(node_a.aggregator.aggregated_tx, node_b.aggregator.aggregated_tx);
        assert_eq!(node_b.aggregator.aggregated_tx, node_c.aggregator.aggregated_tx);
        assert_eq!(node_c.aggregator.aggregated_tx, node_d.aggregator.aggregated_tx);
    }


    /*
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
                //state: ParticipantState::Dealer,
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
*/
}
