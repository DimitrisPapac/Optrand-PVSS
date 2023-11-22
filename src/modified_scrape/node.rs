use crate::{
    EncGroup,
    modified_scrape::{
        aggregator::PVSSAggregator,
        config::Config,
        dealer::Dealer,
        errors::PVSSError,
        participant::Participant,
        pvss::{PVSSCore, PVSSShareSecrets},
	    share::{PVSSShare, SignedProof},
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
    SSIG: BatchVerifiableSignatureScheme<PublicKey = EncGroup<E>, Secret = Scalar<E>>,
{
    pub aggregator: PVSSAggregator<E, SSIG>,    // the aggregator aspect of the node
    pub dealer: Dealer<E, SSIG>,                // the dealer aspect of the node
}

impl<E, SSIG> Node<E, SSIG>
where
    E: PairingEngine,
    SSIG: BatchVerifiableSignatureScheme<PublicKey = EncGroup<E>, Secret = Scalar<E>>,
{
    // Function for initializing a new node in the PVSS sharing protocol.
    pub fn new(
        config: Config<E>,
        scheme_sig: SSIG,
        dealer: Dealer<E, SSIG>,
        participants: BTreeMap<usize, Participant<E, SSIG>>,
    ) -> Result<Self, PVSSError<E>> {
        let node = Node {
            aggregator: PVSSAggregator::<E, SSIG>::new(
                config,
                scheme_sig,
                participants).unwrap(),
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
	// i.e., evals = {p(1), p(2), ..., p(n)}
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
	        .map::<Result<EncGroup<E>, PVSSError<E>>, _>(|j| {
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

        // println!("Received digest: {:?}", digest.0);   // Matches computation inside decomp.rs

        // Sign the decomposition proof using EdDSA
	let signature_on_decomp = Signature::new(&digest, &self.dealer.private_key_ed);

        let signed_proof = SignedProof::<E> {
            decomp_proof,
            signature_on_decomp,
        };

        // println!("{:?}", signed_proof.decomp_proof);

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
	ComGroup,
        EncGroup,
        modified_scrape::{
            aggregator::PVSSAggregator,
            config::Config,
            dealer::Dealer,
	    decryption::DecryptedShare,
            participant::Participant,
	    share::PVSSAggregatedShare,
	    srs::SRS,
	    node::Node,
        },
	signature::{
	    schnorr::{SchnorrSignature, srs::SRS as SCHSRS},
            scheme::SignatureScheme,
    	},
	generate_production_keypair,
    };
    use crate::ark_std::UniformRand;

    use ark_bls12_381::Bls12_381;   // type Bls12_381 = Bls12<Parameters> (Bls12 implements PairingEngine)
    use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
    use ark_ff::{One, PrimeField};
    use ark_std::collections::BTreeMap;
    use rand::thread_rng;

    use std::marker::PhantomData;
    use std::ops::Neg;

    #[test]
    fn test_one() {
        let rng = &mut thread_rng();
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let schnorr_srs = SCHSRS::<EncGroup::<Bls12_381>>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // generate key pairs
        let dealer_keypair_sig = schnorr_sig.generate_keypair(rng).unwrap();   // (sk, pk)
        let eddsa_keypair = generate_production_keypair();                     // (pk, sk)

        // create the dealer instance
        let dealer: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
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
			   SchnorrSignature<EncGroup<Bls12_381>>> = PVSSAggregator {
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
        let schnorr_srs = SCHSRS::<EncGroup::<Bls12_381>>::from_generator(srs.g1).unwrap(); // SCHSRS::<EncGroup::<Bls12_381>>::setup(rng).unwrap();
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
        let dealer_a: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
            private_key_sig: dealer_keypair_sig_a.0,
    	    private_key_ed: eddsa_keypair_a.1,
            participant: Participant {
                pairing_type: PhantomData,
                id: 0,
                public_key_sig: dealer_keypair_sig_a.1,
                public_key_ed: eddsa_keypair_a.0,
            },
        };

        // assert_eq!(dealer_a.participant.public_key_sig.mul(dealer_a.private_key_sig.inverse().unwrap().into_repr()).into_affine(), schnorr_srs.g_public_key);

        // Generate key pairs for party B
        let dealer_keypair_sig_b = schnorr_sig.generate_keypair(rng).unwrap();   // (sk, pk)
        let eddsa_keypair_b = generate_production_keypair();                     // (pk, sk)

        // Create the dealer instance for party B
        let dealer_b: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
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
        let dealer_c: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
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
        let dealer_d: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
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

        // Party A aggregates its own share
        node_a.aggregator.receive_share(rng, &mut pvss_a).unwrap();
        // Party A gets party B's share through communication
        node_a.aggregator.receive_share(rng, &mut pvss_b).unwrap();

        // Party B aggregates its own share
        node_b.aggregator.receive_share(rng, &mut pvss_b).unwrap();
        // Party B gets party A's share through communication
        node_b.aggregator.receive_share(rng, &mut pvss_a).unwrap();

        // Party C aggregates its own share
        node_c.aggregator.receive_share(rng, &mut pvss_c).unwrap();
        // Party C gets party D's share through communication
        node_c.aggregator.receive_share(rng, &mut pvss_d).unwrap();

        // Party D aggregates its own share
        node_d.aggregator.receive_share(rng, &mut pvss_d).unwrap();
        // Party D gets party C's share through communication
        node_d.aggregator.receive_share(rng, &mut pvss_c).unwrap();

        // Parties A and B should at this point hold the same aggregated transcript
        assert_eq!(node_a.aggregator.aggregated_tx, node_b.aggregator.aggregated_tx);

        // Parties C and D should at this point hold the same aggregated transcript
        assert_eq!(node_c.aggregator.aggregated_tx, node_d.aggregator.aggregated_tx);

        // Aggregated share of the left subcommittee
        let mut agg_share_ab = node_a.aggregator.aggregated_tx.clone();
        // Aggregated share of the right subcommittee
        let mut agg_share_cd = node_c.aggregator.aggregated_tx.clone();

        // Right subcommittee receives the left subcommittee's aggregated share
        node_c.aggregator.receive_aggregated_share(rng, &mut agg_share_ab).unwrap();
        node_d.aggregator.receive_aggregated_share(rng, &mut agg_share_ab).unwrap();

        // Left subcommittee receives the right subcommittee's aggregated share
        node_a.aggregator.receive_aggregated_share(rng, &mut agg_share_cd).unwrap();
        node_b.aggregator.receive_aggregated_share(rng, &mut agg_share_cd).unwrap();

        // All nodes should now hold the exact same aggregated transcript
        assert_eq!(node_a.aggregator.aggregated_tx, node_b.aggregator.aggregated_tx);
        assert_eq!(node_b.aggregator.aggregated_tx, node_c.aggregator.aggregated_tx);
        assert_eq!(node_c.aggregator.aggregated_tx, node_d.aggregator.aggregated_tx);

	    // Let comms denote the shared commitments vector (PK in the paper)
	    let comms = node_a.aggregator.aggregated_tx.pvss_core.comms.clone();

	    // Party A computes its decrypted share
	    let dec_a = DecryptedShare::<Bls12_381>::generate(&node_a.aggregator.aggregated_tx.pvss_core.encs,
			&node_a.dealer.private_key_sig, 
			node_a.dealer.participant.id);

	    // Party A computes its commitment vector
	    let r_a = <Bls12_381 as PairingEngine>::Fr::rand(rng);

	    let cm_a: (ComGroup<Bls12_381>, EncGroup<Bls12_381>) = (node_a.aggregator.config.srs.g2.mul(r_a.into_repr()).into_affine(),
			dec_a.dec + node_a.aggregator.config.srs.g1.mul(r_a.into_repr()).neg().into_affine());

	    // A party that receives Party A's cm vector computes the following:
	    let pairs = [
		     (node_a.aggregator.config.srs.g1.neg().into(), comms[dec_a.origin].into()), 
                     (node_a.aggregator.config.srs.g1.into(), cm_a.0.into()),
                     (cm_a.1.into(), node_a.aggregator.config.srs.g2.into()),
                    ];

	    let prod = <Bls12_381 as PairingEngine>::product_of_pairings(pairs.iter());

	    assert!(prod.is_one());
    }


    #[test]
    fn test_double_aggregation() {
        let rng = &mut thread_rng();

        // Global settings
        let srs = SRS::<Bls12_381>::setup(rng).unwrap();
        let schnorr_srs = SCHSRS::<EncGroup::<Bls12_381>>::setup(rng).unwrap();
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
        let dealer_a: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
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
        let dealer_b: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
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
        let dealer_c: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
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
        let dealer_d: Dealer<Bls12_381, SchnorrSignature<EncGroup<Bls12_381>>> = Dealer {
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
        let mut _node_c = Node::new(
            config.clone(),
            schnorr_sig.clone(),
            dealer_c,
            participants.clone(),
        ).unwrap();
        
        // Create the node instance for party D
        let mut _node_d = Node::new(
            config.clone(),
            schnorr_sig.clone(),
            dealer_d,
            participants.clone(),
        ).unwrap();

        // Node generates its PVSSShare:
        let mut pvss_a = node_a.share(rng).unwrap();

        // A duplicate of A's share:
        let mut dup_pvss_a = pvss_a.clone();

        // println!("Node's aggregated_tx is initially:\n\n{:?}", node_a.aggregator.aggregated_tx);

        // Party A aggregates its original share
        node_a.aggregator.receive_share(rng, &mut pvss_a).unwrap();

        // println!("Node's aggregated_tx is now:\n\n{:?}", node_a.aggregator.aggregated_tx);
        let res1 = node_a.aggregator.aggregated_tx.clone();

        // Party A attempts to aggregate the same share again
        node_a.aggregator.receive_share(rng, &mut dup_pvss_a).unwrap();
        let res2 = node_a.aggregator.aggregated_tx.clone();

        // Originally, as in this scenario, the pvss_core would "desync" with the gs values found within
        // the aggregated_tx's contributions map.
        // Introducing weights remedies this issue.
        assert_eq!(res1.num_participants, res2.num_participants);
        assert_eq!(res1.degree, res2.degree);
        assert!(res1.pvss_core != res2.pvss_core);
        assert!(res1.contributions.get(&0).unwrap().0 == res2.contributions.get(&0).unwrap().0);
        assert!(res1.contributions.get(&0).unwrap().1 == 1);
        assert!(res2.contributions.get(&0).unwrap().1 == 2);

        // Also, if node B were to receive this aggregated share, aggregation_verify() wouldn't panic.
        node_b.aggregator.receive_aggregated_share(rng, &mut node_a.aggregator.aggregated_tx.clone()).unwrap();

        // println!("Node's aggregated_tx is now:\n\n{:?}", node_a.aggregator.aggregated_tx);
    }
}
