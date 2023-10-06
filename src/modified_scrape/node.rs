use crate::{
    modified_scrape::{
        aggregator::PVSSAggregator,
        config::Config,
        dealer::Dealer,
        errors::PVSSError,
        participant::Participant,
        pvss::{PVSSCore, PVSSShareSecrets},
	share::{PVSSAggregatedShare, PVSSShare},
	decomp::Decomp,
	poly::{Polynomial as Poly}
    },
    Scalar,
    Signature,
    signature::scheme::BatchVerifiableSignatureScheme,
};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_poly::{Polynomial, UVPolynomial};

use rand::Rng;
use std::collections::BTreeMap;


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
	let poly = Poly::<E>::rand(t, rng);

	// Evaluate poly(j) for all j in {1, ..., n}
	let evals = (1..n+1)
	        .map(|j| poly.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

	// Compute commitments for all nodes in {0, ..., n-1}
        // Recall that G2 is the commitment group.
	let comms = (0..n)
	        .map(|j| self.aggregator.config.srs.g2.mul(evals[j].into_repr()))
	        .collect::<Vec<_>>();

	// Compute encryptions for all nodes in {0, ..., n-1}
	let encs = (0..n)
	        .map::<Result<E::G1Projective, PVSSError<E>>, _>(|j| {
                    Ok(self
                        .aggregator
                        .participants
                        .get(&j)
                        .ok_or(PVSSError::<E>::InvalidParticipantId(j))?
                        .public_key_sig   // obtain participant's public (encryption) key
                        .mul(evals[j].into_repr())
                        )   // .into_affine()
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

        // Sign the decomposition proof using EdDSA
	let signature_on_decomp = Signature::new(&digest, &self.dealer.private_key_ed);

	// Create the PVSS share.
	let share = PVSSShare {
            participant_id: self.dealer.participant.id,
            pvss_core,
	    decomp_proof,
            signature_on_decomp,
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
	    node::Node,
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
}
