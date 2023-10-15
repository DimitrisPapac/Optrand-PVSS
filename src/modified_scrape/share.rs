use crate::{
    modified_scrape::{
        config::Config,
        errors::PVSSError,
        pvss::PVSSCore,
        decomp::DecompProof,
    },
    PublicKey,
    Signature,
};

use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Read, Write};
use ark_std::collections::BTreeMap;

use std::io::Cursor;


/* Struct SignedProof represents a pair consisting of a decomposition proof along with
   a signature on it. */
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct SignedProof<E>
where
    E: PairingEngine,
{
    pub decomp_proof: DecompProof<E>,     // proof of knowledge of shared secret
    pub signature_on_decomp: Signature,   // EdDSA-signed knowledge proof
}


impl<E: PairingEngine> SignedProof<E> {
    // Method enabling verification of individual signed proofs instances (FOR TESTING ONLY).
    fn verify(&mut self, conf: &Config<E>, pk_sig: &PublicKey) -> Result<(), PVSSError<E>> {
        // Verify the NIZK proof
        self.decomp_proof.verify(&conf).unwrap();

        // Verify the signature on the NIZK proof
        self.signature_on_decomp.verify(&mut self.decomp_proof.digest(), &pk_sig).unwrap();

        Ok(())
    }
}


/* PVSSShare represents a PVSSCore instance that has been augmented to include the origin's id,
   as well as a signature on the decomposition proof included in the core PVSS share. */
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct PVSSShare<E>
where
    E: PairingEngine,
{
    pub participant_id: usize,            // issuer of this PVSS share
    pub pvss_core: PVSSCore<E>,           // "core" of the PVSS share
    pub signed_proof: SignedProof<E>,     // signed proof of decomposition
}

/* Struct PVSSAggregatedShare represents an aggregation of PVSS shares. */
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct PVSSAggregatedShare<E>
where
    E: PairingEngine,
{
    pub num_participants: usize,
    pub degree: usize,
    pub pvss_core: PVSSCore<E>,                           // "core" of the aggregated PVSS sharing
    pub contributions: BTreeMap<usize, SignedProof<E>>,   // combination of the three following fields

    // Using a BTreeMap saves us from having to manually manage three vectors instead:
    // pub id_vec: Vec<usize>,                     // vector of participant ids whose shares have been pooled together
    // pub decomp_proofs: Vec<DecompProof<E>>,     // accumulation of decomposition proofs
    // pub signatures_on_decomps: Vec<Signature>,  // accumulation of signatures on decomposition proofs
}


// Utility function for buffering a decomposition proof into a buffer and obtaining a reference
// to said buffer.
pub fn message_from_pi_i<E: PairingEngine>(pi_i: DecompProof<E>) -> Result<Vec<u8>, PVSSError<E>> {
    let mut message_writer = Cursor::new(vec![]);
    pi_i.serialize(&mut message_writer)?;
    Ok(message_writer.get_ref().to_vec())
}


impl<E: PairingEngine> PVSSAggregatedShare<E>
{
    // Function for generating a new (empty) PVSSAggregatedShare instance.
    pub fn empty(degree: usize, num_participants: usize) -> Self {
        Self {
	        num_participants,
	        degree,
	        pvss_core: PVSSCore::empty(num_participants),
	        contributions: BTreeMap::new(),
        }
    }

    // Method for aggregating two PVSS aggregated shares.
    // Returns the resulting aggregated PVSS share.
    pub fn aggregate(&self, other: &Self) -> Result<Self, PVSSError<E>> {
        // Ensure that both PVSS aggregated shares are under a common configuration.
        if self.degree != other.degree || self.num_participants != other.num_participants {
            return Err(PVSSError::TranscriptDifferentConfig(
                self.degree,
                other.degree,
                self.num_participants,
                other.num_participants,
            ));
        }

        // Combine contributions of self and other into a single BTreeMap.
        let contributions = (0..self.num_participants)   // this is: n x amortized O(1)
            .map(
                |i| match (self.contributions.get(&i), other.contributions.get(&i)) {
                    (Some(a), Some(b)) => {
                        if a.decomp_proof.gs != b.decomp_proof.gs {
                            return Err(PVSSError::TranscriptDifferentCommitments);
                        }
                        // Only keep a's signed proof
                        let signed_proof = SignedProof {
                            decomp_proof: a.decomp_proof,
                            signature_on_decomp: a.signature_on_decomp.clone(),
                        };
                        Ok(Some((i, signed_proof)))
                    }
                    (Some(a), None) => Ok(Some((i, a.clone()))),
                    (None, Some(b)) => Ok(Some((i, b.clone()))),
                    (None, None) => Ok(None),
                },
            )
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|e| e)
            .collect::<Vec<_>>();

        let aggregated_share = Self {
            num_participants: self.num_participants,
            degree: self.degree,
            pvss_core: self.pvss_core.aggregate(&other.pvss_core).unwrap(),   // aggregate the two cores of PVSS shares
            contributions: contributions.into_iter().collect(),
        };

        // Return the aggregate of the two aggregated PVSS shares.
        Ok(aggregated_share)
    }

    // Method for aggregating a PVSS share to an aggregated PVSS share.
    // Returns the resulting aggregated PVSS share.
    pub fn aggregate_pvss_share(&self, other: &PVSSShare<E>) -> Result<Self, PVSSError<E>> {
	    // Convert other from a PVSSShare instance into a PVSSAggregatedShare instance.
	    let mut contribs = BTreeMap::new();
	    contribs.insert(other.participant_id, SignedProof{ decomp_proof: other.signed_proof.decomp_proof,
							   signature_on_decomp: other.signed_proof.signature_on_decomp });

	    let other_agg_share = Self {
            num_participants: self.num_participants,
            degree: self.degree,
            pvss_core: other.pvss_core.clone(),
            contributions: contribs,
        };

	    // Return the aggregate of the two aggregated PVSS shares.
	    self.aggregate(&other_agg_share)
    }
}



/* Unit tests: */

#[cfg(test)]
mod test {

    use crate::{
        generate_production_keypair,
        modified_scrape::{
            config::Config,
            decomp::Decomp,
            poly::Polynomial as Poly,
            pvss::PVSSCore,
            share::{PVSSAggregatedShare, PVSSShare, SignedProof},
            srs::SRS,
        },
        signature::{
            scheme::SignatureScheme,
            schnorr::{SchnorrSignature, srs::SRS as SCHSRS},
            utils::tests::check_serialization,
        },
        Scalar,
        Signature,
    };

    use ark_bls12_381::{
	    Bls12_381 as E,   // type Bls12_381 = Bls12<Parameters> (Bls12 implements PairingEngine)
    };
    use ark_ec::{PairingEngine, AffineCurve, ProjectiveCurve};
    use ark_ff::{PrimeField, Zero};
    use ark_poly::{Polynomial, UVPolynomial};
    use ark_std::{collections::BTreeMap, UniformRand};

    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    
    use rand::thread_rng;
    

    #[test]
    fn test_generate_valid_signed_proof() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        let p_0 = Scalar::<E>::from(10 as u64);

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let conf = Config { srs, degree: t, num_participants: n };

        // EdDSA setup
        let (pk_sig, sk_sig) = generate_production_keypair();

        // generate decomposition proof
        let mut dproof = Decomp::<E>::generate(rng, &conf, &p_0).unwrap();

        // sign the proof
        let sig = Signature::new(&mut dproof.digest(), &sk_sig);

        let mut sproof = SignedProof {decomp_proof: dproof, signature_on_decomp: sig};

        // Verify SignedProof instance
        sproof.verify(&conf, &pk_sig).unwrap();
    }


    #[test]
    fn test_create_empty_aggregated_pvss_share() {
        let t = 3;
        let n = 10;

        // Create an empty PVSSAggregated share.
        let empty_share = PVSSAggregatedShare::<E>::empty(t, n);

        // The expected result.
        let exp_result = PVSSAggregatedShare {
            num_participants: n,
            degree: t,
            pvss_core: PVSSCore {
                encs:  vec![<E as PairingEngine>::G1Affine::zero(); n],
                comms: vec![<E as PairingEngine>::G2Affine::zero(); n],
            },
            contributions: BTreeMap::new(),
        };

        assert!(empty_share == exp_result);
    }


    #[test]
    fn test_create_pvss_share() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        let id = 5_usize;

        // Sample a random degree t polynomial.
	    let poly = Poly::<E>::rand(t, rng);
        let p_0 = poly[0];   // the free term

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let conf = Config { srs, degree: t, num_participants: n };

        // Schnorr SRS (over group G1)
        let schnorr_srs = SCHSRS::<<E as PairingEngine>::G1Affine>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // Schnorr setup
        let (_schorr_sk, schnorr_pk) = schnorr_sig.generate_keypair(rng).unwrap();

        // EdDSA setup
        let (_pk_sig, sk_sig) = generate_production_keypair();

        // Generate decomposition proof.
        let mut dproof = Decomp::<E>::generate(rng, &conf, &p_0).unwrap();

        // Sign the proof.
        let sig = Signature::new(&mut dproof.digest(), &sk_sig);

        let sproof = SignedProof {decomp_proof: dproof, signature_on_decomp: sig};

        // Evaluate poly(j) for all j in {1, ..., n}.
        let evals = (1..=n)
	        .map(|j| poly.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

        // Compute commitments for all nodes in {0, ..., n-1}.
        // Recall that G2 is the commitment group.
        let comms = (0..=(n-1))
	        .map(|j| conf.srs.g2.mul(evals[j].into_repr()).into_affine())
	        .collect::<Vec<_>>();

        // Dummy vector of random Schnorr public keys.
        let mut schnorr_pks = vec![<E as PairingEngine>::G1Projective::rand(rng); n];
        // For this test case, we only care about party "id"'s pk being genuine.
        schnorr_pks[id] = schnorr_pk.into_projective();

        // Compute encryptions for all nodes in {0, ..., n-1}.
        let encs: Vec<_> = (0..=(n-1))
	        .map(|j| {
                schnorr_pks[j]
                    //.into_affine()
                    .mul(evals[j].into_repr())
                    .into_affine()
                    })
            .collect::<_>();

        // Compose PVSS core.
        let pvss_core = PVSSCore::<E> {comms, encs};

        // Create PVSSShare.
        let _pvss_share = PVSSShare::<E> {
            participant_id: id, 
            pvss_core, 
            signed_proof: sproof,
        };
    }


    #[test]
    fn test_aggregation_of_pvss_share() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        let id = 5_usize;

        // Sample a random degree t polynomial.
	    let poly = Poly::<E>::rand(t, rng);
        let p_0 = poly[0];   // the free term

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let conf = Config { srs, degree: t, num_participants: n };

        // Schnorr SRS (over group G1)
        let schnorr_srs = SCHSRS::<<E as PairingEngine>::G1Affine>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // Schnorr setup
        let (_schorr_sk, schnorr_pk) = schnorr_sig.generate_keypair(rng).unwrap();

        // EdDSA setup
        let (_pk_sig, sk_sig) = generate_production_keypair();

        // Generate decomposition proof.
        let mut dproof = Decomp::<E>::generate(rng, &conf, &p_0).unwrap();

        // Sign the proof.
        let sig = Signature::new(&mut dproof.digest(), &sk_sig);

        let sproof = SignedProof {decomp_proof: dproof, signature_on_decomp: sig};

        // Evaluate poly(j) for all j in {1, ..., n}.
        let evals = (1..=n)
	        .map(|j| poly.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

        // Compute commitments for all nodes in {0, ..., n-1}.
        // Recall that G2 is the commitment group.
        let comms = (0..=(n-1))
	        .map(|j| conf.srs.g2.mul(evals[j].into_repr()).into_affine())
	        .collect::<Vec<_>>();

        // Dummy vector of Schnorr public keys.
        let mut schnorr_pks = vec![<E as PairingEngine>::G1Projective::rand(rng).into_affine(); n];
        // We only care about party "id"'s pk being genuine.
        schnorr_pks[id] = schnorr_pk;

        // Compute encryptions for all nodes in {0, ..., n-1}.
        let encs: Vec<_> = (0..=(n-1))
	        .map(|j| {
                schnorr_pks[j]
                    //.into_affine()
                    .mul(evals[j].into_repr())
                    .into_affine()
                    })
            .collect::<_>();

        // Compose PVSS core.
        let pvss_core = PVSSCore::<E> {comms: comms.clone(), encs: encs.clone()};

        // Create PVSSShare.
        let pvss_share = PVSSShare::<E> {
            participant_id: id,
            pvss_core: pvss_core.clone(),
            signed_proof: sproof.clone(),
        };

        // Create an AggregatedPVSSShare to hold the result.
        let mut aggr_share = PVSSAggregatedShare::<E>::empty(t, n);

        // Aggregate pvss_share into aggr_share.
        aggr_share = aggr_share.aggregate_pvss_share(&pvss_share).unwrap();

        // Create a BTreeMap containing only the party's signed proof.
        let mut contribs = BTreeMap::new();
	    contribs.insert(id, sproof);

        // The expected result.
        let exp_result = PVSSAggregatedShare {
            num_participants: n,
            degree: t,
            pvss_core,
            contributions: contribs,
        };

        assert!(aggr_share == exp_result);
    }


    #[test]
    fn test_aggregation_of_two_pvss_shares() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        let id_a = 2_usize;
        let id_b = 3_usize;

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let conf = Config { srs, degree: t, num_participants: n };

        // Schnorr SRS (over group G1)
        let schnorr_srs = SCHSRS::<<E as PairingEngine>::G1Affine>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // Sample a random degree t polynomial for party A.
	    let poly_a = Poly::<E>::rand(t, rng);
        let p_0_a = poly_a[0];   // the free term

        // Sample a random degree t polynomial for party B.
        let poly_b = Poly::<E>::rand(t, rng);
        let p_0_b = poly_b[0];   // the free term

        // Schnorr setup for party A
        let (_schorr_sk_a, schnorr_pk_a) = schnorr_sig.generate_keypair(rng).unwrap();

        // Schnorr setup for party B
        let (_schorr_sk_b,schnorr_pk_b) = schnorr_sig.generate_keypair(rng).unwrap();

        // EdDSA setup for party A
        let (_pk_sig_a, sk_sig_a) = generate_production_keypair();

        // EdDSA setup for party B
        let (_pk_sig_b, sk_sig_b) = generate_production_keypair();

        // Generate decomposition proof for party A.
        let mut dproof_a = Decomp::<E>::generate(rng, &conf, &p_0_a).unwrap();

        // Generate decomposition proof for party B.
        let mut dproof_b = Decomp::<E>::generate(rng, &conf, &p_0_b).unwrap();

        // Sign party A's proof.
        let sig_a = Signature::new(&mut dproof_a.digest(), &sk_sig_a);

        // Sign party B's proof.
        let sig_b = Signature::new(&mut dproof_b.digest(), &sk_sig_b);

        // Compose party A's signed proof.
        let sproof_a = SignedProof {decomp_proof: dproof_a, signature_on_decomp: sig_a};

        // Compose party B's signed proof.
        let sproof_b = SignedProof {decomp_proof: dproof_b, signature_on_decomp: sig_b};

        // Evaluate polyA(j) for all j in {1, ..., n}.
        let evals_a = (1..=n)
	        .map(|j| poly_a.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

        // Evaluate polyB(j) for all j in {1, ..., n}.
        let evals_b = (1..=n)
	        .map(|j| poly_b.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

        // Compute party A's commitments for all nodes in {0, ..., n-1}.
        // Recall that G2 is the commitment group.
        let comms_a = (0..=(n-1))
	        .map(|j| conf.srs.g2.mul(evals_a[j].into_repr()).into_affine())
	        .collect::<Vec<_>>();

        // Compute party B's commitments for all nodes in {0, ..., n-1}.
        // Recall that G2 is the commitment group.
        let comms_b = (0..=(n-1))
	        .map(|j| conf.srs.g2.mul(evals_b[j].into_repr()).into_affine())
	        .collect::<Vec<_>>();

        // Dummy vector of Schnorr public keys.
        let mut schnorr_pks = vec![<E as PairingEngine>::G1Projective::rand(rng).into_affine(); n];
        // We only care about party A and B's public keys being genuine.
        schnorr_pks[id_a] = schnorr_pk_a;
        schnorr_pks[id_b] = schnorr_pk_b;

        // Compute party A's encryptions for all nodes in {0, ..., n-1}.
        let encs_a: Vec<_> = (0..=(n-1))
	        .map(|j| {
                    schnorr_pks[j]
                        //.into_affine()
                        .mul(evals_a[j].into_repr())
                        .into_affine()
                    })
                .collect::<_>();

        // Compute party B's encryptions for all nodes in {0, ..., n-1}.
        let encs_b: Vec<_> = (0..=(n-1))
	        .map(|j| {
                schnorr_pks[j]
                    //.into_affine()
                    .mul(evals_b[j].into_repr())
                    .into_affine()
                    })
            .collect::<_>();

        // Compose A's PVSS core.
        let pvss_core_a = PVSSCore::<E> {comms: comms_a.clone(), encs: encs_a.clone()};

        // Compose B's PVSS core.
        let pvss_core_b = PVSSCore::<E> {comms: comms_b.clone(), encs: encs_b.clone()};

        // Create A's PVSSShare.
        let pvss_share_a = PVSSShare::<E> {
            participant_id: id_a,
            pvss_core: pvss_core_a.clone(),
            signed_proof: sproof_a.clone(),
        };

        // Create B's PVSSShare.
        let pvss_share_b = PVSSShare::<E> {
            participant_id: id_b,
            pvss_core: pvss_core_b.clone(),
            signed_proof: sproof_b.clone(),
        };

        // Create an AggregatedPVSSShare to hold the result.
        let mut aggr_share = PVSSAggregatedShare::<E>::empty(t, n);

        // Aggregate pvss_shares into aggr_share.
        // Note: Order of aggregation is irrelevant.
        aggr_share = aggr_share.aggregate_pvss_share(&pvss_share_a).unwrap();
        aggr_share = aggr_share.aggregate_pvss_share(&pvss_share_b).unwrap();

        let pvss_core = PVSSCore::empty(n)
            .aggregate(&pvss_core_a)
            .unwrap()
            .aggregate(&pvss_core_b)
            .unwrap();

        // Create a BTreeMap containing party A and party B's signed proofs.
        // Note: Order of insertion is irrelevant.
        let mut contribs = BTreeMap::new();
        contribs.insert(id_a, sproof_a);
        contribs.insert(id_b, sproof_b);

        // The expected result.
        let exp_result = PVSSAggregatedShare {
            num_participants: n,
            degree: t,
            pvss_core,
            contributions: contribs,
        };

        assert!(aggr_share == exp_result);
    }


    #[test]
    fn test_serialization_pvss_share() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        let id = 5_usize;

        // Sample a random degree t polynomial.
	    let poly = Poly::<E>::rand(t, rng);
        let p_0 = poly[0];   // the free term

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let conf = Config { srs, degree: t, num_participants: n };

        // Schnorr SRS (over group G1)
        let schnorr_srs = SCHSRS::<<E as PairingEngine>::G1Affine>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // Schnorr setup
        let (_schorr_sk, schnorr_pk) = schnorr_sig.generate_keypair(rng).unwrap();

        // EdDSA setup
        let (_pk_sig, sk_sig) = generate_production_keypair();

        // Generate decomposition proof.
        let mut dproof = Decomp::<E>::generate(rng, &conf, &p_0).unwrap();

        // Sign the proof.
        let sig = Signature::new(&mut dproof.digest(), &sk_sig);

        let sproof = SignedProof {decomp_proof: dproof, signature_on_decomp: sig};

        // Evaluate poly(j) for all j in {1, ..., n}.
        let evals = (1..=n)
	        .map(|j| poly.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

        // Compute commitments for all nodes in {0, ..., n-1}.
        // Recall that G2 is the commitment group.
        let comms = (0..=(n-1))
	        .map(|j| conf.srs.g2.mul(evals[j].into_repr()).into_affine())
	        .collect::<Vec<_>>();

        // Dummy vector of random Schnorr public keys.
        let mut schnorr_pks = vec![<E as PairingEngine>::G1Projective::rand(rng).into_affine(); n];
        // For this test case, we only care about party "id"'s pk being genuine.
        schnorr_pks[id] = schnorr_pk;

        // Compute encryptions for all nodes in {0, ..., n-1}.
        let encs: Vec<_> = (0..=(n-1))
	        .map(|j| {
                schnorr_pks[j]
                    //.into_affine()
                    .mul(evals[j].into_repr())
                    .into_affine()
                    })
            .collect::<_>();

        // Compose PVSS core.
        let pvss_core = PVSSCore::<E> {comms, encs};

        // Create PVSSShare.
        let pvss_share = PVSSShare::<E> {
            participant_id: id, 
            pvss_core, 
            signed_proof: sproof,
        };

	    // println!("pvss_share: {:?}", pvss_share);

        check_serialization(pvss_share);
    }

    #[test]
    fn test_serialization_deserialization_aggregated_share() {
        let rng = &mut thread_rng();
        let t = 3;
        let n = 10;

        let id_a = 2_usize;
        let id_b = 3_usize;

        // PVSS setup
        let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let conf = Config { srs, degree: t, num_participants: n };

        // Schnorr SRS (over group G1)
        let schnorr_srs = SCHSRS::<<E as PairingEngine>::G1Affine>::setup(rng).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        // Sample a random degree t polynomial for party A.
	    let poly_a = Poly::<E>::rand(t, rng);
        let p_0_a = poly_a[0];   // the free term

        // Sample a random degree t polynomial for party B.
        let poly_b = Poly::<E>::rand(t, rng);
        let p_0_b = poly_b[0];   // the free term

        // Schnorr setup for party A
        let (_schorr_sk_a, schnorr_pk_a) = schnorr_sig.generate_keypair(rng).unwrap();

        // Schnorr setup for party B
        let (_schorr_sk_b,schnorr_pk_b) = schnorr_sig.generate_keypair(rng).unwrap();

        // EdDSA setup for party A
        let (_pk_sig_a, sk_sig_a) = generate_production_keypair();

        // EdDSA setup for party B
        let (_pk_sig_b, sk_sig_b) = generate_production_keypair();

        // Generate decomposition proof for party A.
        let mut dproof_a = Decomp::<E>::generate(rng, &conf, &p_0_a).unwrap();

        // Generate decomposition proof for party B.
        let mut dproof_b = Decomp::<E>::generate(rng, &conf, &p_0_b).unwrap();

        // Sign party A's proof.
        let sig_a = Signature::new(&mut dproof_a.digest(), &sk_sig_a);

        // Sign party B's proof.
        let sig_b = Signature::new(&mut dproof_b.digest(), &sk_sig_b);

        // Compose party A's signed proof.
        let sproof_a = SignedProof {decomp_proof: dproof_a, signature_on_decomp: sig_a};

        // Compose party B's signed proof.
        let sproof_b = SignedProof {decomp_proof: dproof_b, signature_on_decomp: sig_b};

        // Evaluate polyA(j) for all j in {1, ..., n}.
        let evals_a = (1..=n)
	        .map(|j| poly_a.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

        // Evaluate polyB(j) for all j in {1, ..., n}.
        let evals_b = (1..=n)
	        .map(|j| poly_b.evaluate(&Scalar::<E>::from(j as u64)))
	        .collect::<Vec<_>>();

        // Compute party A's commitments for all nodes in {0, ..., n-1}.
        // Recall that G2 is the commitment group.
        let comms_a = (0..=(n-1))
	        .map(|j| conf.srs.g2.mul(evals_a[j].into_repr()).into_affine())
	        .collect::<Vec<_>>();

        // Compute party B's commitments for all nodes in {0, ..., n-1}.
        // Recall that G2 is the commitment group.
        let comms_b = (0..=(n-1))
	        .map(|j| conf.srs.g2.mul(evals_b[j].into_repr()).into_affine())
	        .collect::<Vec<_>>();

        // Dummy vector of Schnorr public keys.
        let mut schnorr_pks = vec![<E as PairingEngine>::G1Projective::rand(rng).into_affine(); n];
        // We only care about party A and B's public keys being genuine.
        schnorr_pks[id_a] = schnorr_pk_a;
        schnorr_pks[id_b] = schnorr_pk_b;

        // Compute party A's encryptions for all nodes in {0, ..., n-1}.
        let encs_a: Vec<_> = (0..=(n-1))
	        .map(|j| {
                    schnorr_pks[j]
                        //.into_affine()
                        .mul(evals_a[j].into_repr())
                        .into_affine()
                    })
                .collect::<_>();

        // Compute party B's encryptions for all nodes in {0, ..., n-1}.
        let encs_b: Vec<_> = (0..=(n-1))
	        .map(|j| {
                schnorr_pks[j]
                    //.into_affine()
                    .mul(evals_b[j].into_repr())
                    .into_affine()
                    })
            .collect::<_>();

        // Compose A's PVSS core.
        let pvss_core_a = PVSSCore::<E> {comms: comms_a.clone(), encs: encs_a.clone()};

        // Compose B's PVSS core.
        let pvss_core_b = PVSSCore::<E> {comms: comms_b.clone(), encs: encs_b.clone()};

        // Create A's PVSSShare.
        let pvss_share_a = PVSSShare::<E> {
            participant_id: id_a,
            pvss_core: pvss_core_a.clone(),
            signed_proof: sproof_a.clone(),
        };

        // Create B's PVSSShare.
        let pvss_share_b = PVSSShare::<E> {
            participant_id: id_b,
            pvss_core: pvss_core_b.clone(),
            signed_proof: sproof_b.clone(),
        };

        // Create an AggregatedPVSSShare to hold the result.
        let mut aggr_share = PVSSAggregatedShare::<E>::empty(t, n);

        // Aggregate pvss_shares into aggr_share.
        // Note: Order of aggregation is irrelevant.
        aggr_share = aggr_share.aggregate_pvss_share(&pvss_share_a).unwrap();
        aggr_share = aggr_share.aggregate_pvss_share(&pvss_share_b).unwrap();

        let mut compressed_bytes = Vec::new();
        aggr_share.serialize(&mut compressed_bytes).unwrap();

        let recon_share: PVSSAggregatedShare<E>= PVSSAggregatedShare::deserialize(&compressed_bytes[..]).unwrap();

        assert_eq!(aggr_share, recon_share);
    }

}
