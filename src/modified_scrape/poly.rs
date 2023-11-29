use crate::{
    ComGroup,
    ComGroupP,
    EncGroup,
    EncGroupP,
    GT,
    modified_scrape::errors::PVSSError,
    Scalar,
};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, Zero, One, PrimeField};
use ark_poly::{UVPolynomial, Polynomial as Poly, polynomial::univariate::DensePolynomial};

use rand::Rng;


// A polynomial with the various coefficients in the Scalar Group
pub type Polynomial<E> = DensePolynomial<Scalar<E>>;


// Function for ensuring that the commitment vector evals is
// also a commitment to a polynomial of specified degree.
pub fn ensure_degree<E, R>(rng: &mut R,
                           evaluations: &Vec<ComGroup<E>>,
                           degree: u64) -> Result<(), PVSSError<E>>
where
	E: PairingEngine,
	R: Rng
{
    let num = evaluations.len() as u64;

    if num < degree {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    // Sample a random polynomial of appropriate degree
    let poly = Polynomial::<E>::rand((num-degree-2) as usize, rng);

    let mut sum = ComGroupP::<E>::zero();

    for i in 1..=num {
        let scalar_i = Scalar::<E>::from(i);
        let mut cperp = poly.evaluate(&scalar_i);
        for j in 1..=num {
                let scalar_j = Scalar::<E>::from(j);
                if i != j {
                    cperp *= (scalar_i - scalar_j).inverse().unwrap();
                }
            }
        //sum += evaluations[(i-1) as usize].mul(cperp.into_repr());   // .into_affine();
        sum.add_assign_mixed(&evaluations[(i-1) as usize].mul(cperp.into_repr()).into_affine());
    }

    if sum != ComGroupP::<E>::zero() {
	    return Err(PVSSError::DualCodeError);
    }

    Ok(())
}


// Utility function for Lagrange interpolation from a given list of evaluations.
pub fn lagrange_interpolation_simple<E>(
    evals: &Vec<ComGroup<E>>,
    degree: u64
) -> Result<ComGroup<E>, PVSSError<E>> 
where
	E: PairingEngine,
	Scalar<E>: From<u64>,
{
    if evals.len() < (degree + 1) as usize {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    let mut sum = ComGroupP::<E>::zero();
    
    for j in 0..=degree {
        let x_j = Scalar::<E>::from(j + 1);
        let mut prod = Scalar::<E>::one();
        for k in 0..=degree {
            if j != k {
                let x_k = Scalar::<E>::from(k + 1);
                prod *= x_k * (x_k - x_j).inverse().unwrap();
            }
        }

        // Recovery formula
        sum += evals[j as usize].mul(prod.into_repr());
    }

    Ok(sum.into_affine())
}


// Utility function for Lagrange interpolation from a given list of points
// and evaluations.
pub fn lagrange_interpolation_g1<E>(
    evals: &Vec<EncGroup<E>>,
    points: &Vec<Scalar<E>>,
    degree: u64
) -> Result<EncGroup<E>, PVSSError<E>> 
where
	E: PairingEngine,
	Scalar<E>: From<u64>
{
    if evals.len() < (degree + 1) as usize {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    if evals.len() != points.len() {
	    return Err(PVSSError::DifferentPointsEvalsError);
    }

    let mut sum = EncGroupP::<E>::zero();

    for j in 0..=degree {
        let x_j = points[j as usize];
        let mut prod = Scalar::<E>::one();
        for k in 0..=degree {
            if j != k {
                let x_k = points[k as usize];
                prod *= x_k * (x_k - x_j).inverse().unwrap();
            }
        }

        // Recovery formula
        sum += evals[j as usize].mul(prod.into_repr());
    }

    Ok(sum.into_affine())
}


// Utility function for Lagrange interpolation from a given list of points
// and evaluations.
pub fn lagrange_interpolation_g2<E>(
    evals: &Vec<ComGroup<E>>,
    points: &Vec<Scalar<E>>,
    degree: u64
) -> Result<ComGroup<E>, PVSSError<E>> 
where
	E: PairingEngine,
	Scalar<E>: From<u64>
{
    if evals.len() < (degree + 1) as usize {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    if evals.len() != points.len() {
	    return Err(PVSSError::DifferentPointsEvalsError);
    }

    let mut sum = ComGroupP::<E>::zero();

    for j in 0..=degree {
        let x_j = points[j as usize];
        let mut prod = Scalar::<E>::one();
        for k in 0..=degree {
            if j != k {
                let x_k = points[k as usize];
                prod *= x_k * (x_k - x_j).inverse().unwrap();
            }
        }

        // Recovery formula
        sum += evals[j as usize].mul(prod.into_repr());
    }

    Ok(sum.into_affine())
}


// Utility function for Lagrange interpolation from a given list of points
// and evaluations.
pub fn lagrange_interpolation_gt<E>(
    evals: &Vec<GT<E>>,
    points: &Vec<u64>,
    degree: u64
) -> Result<GT<E>, PVSSError<E>> 
where
    E: PairingEngine,
    Scalar<E>: From<u64>,
{
    if evals.len() < (degree + 1) as usize {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    if evals.len() != points.len() {
        return Err(PVSSError::DifferentPointsEvalsError);
    }

    let mut result = GT::<E>::one();

    for j in 0..=degree {
        // points must be a subset of {1, ..., n}
        let x_j = Scalar::<E>::from(points[j as usize]); // <GT::<E> as Field>::BasePrimeField::from(points[j as usize]);  // 1
        let mut prod = Scalar::<E>::one(); // <GT::<E> as Field>::BasePrimeField::one();  // 2
        for k in 0..=degree {
            if j != k {
                let x_k = Scalar::<E>::from(points[k as usize]); // <GT::<E> as Field>::BasePrimeField::from(points[k as usize]);  // 3
                prod *= x_k * (x_k - x_j).inverse().unwrap();
            }
        }

        // Recovery formula
        result *= evals[j as usize].pow(prod.into_repr());
    }

    Ok(result)
}



/* Unit tests: */


#[cfg(test)]
mod test {
    use std::{marker::PhantomData, collections::BTreeMap};

    use crate::{
        ComGroup,
        ComGroupP,
        EncGroup,
        modified_scrape::{
            config::Config,
            dealer::Dealer,
            decryption::DecryptedShare,
            errors::PVSSError,
            node::Node,
            poly::{
                Polynomial,
                ensure_degree,
                lagrange_interpolation_simple,
                lagrange_interpolation_g2,
                lagrange_interpolation_gt,
            },
            participant::Participant,
            pvss::PVSSCore,
            srs::SRS,
        },
        Scalar,
        signature::{
            scheme::SignatureScheme,
            schnorr::srs::SRS as SCHSRS,
            schnorr::SchnorrSignature
        }, generate_production_keypair, nizk::utils::hash::hash_to_group,
    };

    use ark_bls12_381::{Bls12_381 as E, G1Affine};   // implements PairingEngine
    use ark_ec::{PairingEngine, AffineCurve, ProjectiveCurve};
    use ark_ff::PrimeField;
    use ark_poly::{UVPolynomial, Polynomial as Poly};
    use ark_std::UniformRand;

    use rand::{Rng, thread_rng};

    // cargo test -- --nocapture


    const MIN_DEGREE: usize = 3;
    const MAX_DEGREE: usize = 100;


    #[test]
    fn test_sample_poly() {
        let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE);

        // generate a random polynomial
        let _p = Polynomial::<E>::rand(deg, rng);
        // println!("Sampled degree: {}\n", deg);
        // println!("Sampled polynomial:\n {:?}", p);

        // retrieve its free term
        // println!("Its free term is: {:?}", p.coeffs[0]);

        // evaluate polynomial at some given point
        // println!("0 * p(3) = {:?}", Scalar::<E>::from(0u64) * p.evaluate(&Scalar::<E>::from(3u64)));

        assert_eq!(2+2, 4);
    }


    #[test]
    fn test_ensure_degree() {
        let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

        // we use random group elemements from G_2 since it doesn't matter here.
        let evals = vec![ComGroupP::<E>::rand(rng).into_affine(); (deg+4) as usize];
        assert_eq!(ensure_degree::<E, _>(rng, &evals, deg).unwrap(), ());
    }


    #[test]
    #[should_panic]
    fn test_ensure_degree_insufficient_evals() {
        let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

        // we use random group elemements from G_2 since it doesn't matter here.
        let evals = vec![ComGroupP::<E>::rand(rng).into_affine(); (deg-1) as usize];
        ensure_degree::<E, _>(rng, &evals, deg).unwrap();
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_simple_insufficient_evals() {
        let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

        // we use random group elemements from G_2 since it doesn't matter here.
        let evals = vec![ComGroupP::<E>::rand(rng).into_affine(); (deg-1) as usize];

        _ = lagrange_interpolation_simple::<E>(&evals, deg).unwrap();
    }


    #[test]
    fn test_lagrange_interpolation_simple() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
	let generator = srs.g2;

	let p = Polynomial::<E>::rand(deg as usize, rng);
	let secret = p.coeffs[0];
	let shared_secret = generator.mul(secret.into_repr());

	let evals = (1..(deg+2))
		.map(|x| generator.mul(p.evaluate(&Scalar::<E>::from(x as u64)).into_repr()).into_affine())
		.collect::<Vec<_>>();

	let reconstructed_secret = lagrange_interpolation_simple::<E>(&evals, deg).unwrap();

	assert_eq!(reconstructed_secret, shared_secret);
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_insufficient_evals() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	// we use random elements since it doesn't matter here
        let evals = vec![ComGroupP::<E>::rand(rng).into_affine(); (deg-1) as usize];
	let points = vec![Scalar::<E>::rand(rng); (deg-1) as usize];

	_ = lagrange_interpolation_g2::<E>(&evals, &points, deg).unwrap();
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_different_points_evals() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	// we use random elements since it doesn't matter here
        let evals = vec![ComGroupP::<E>::rand(rng).into_affine(); (deg+1) as usize];
	let points = vec![Scalar::<E>::rand(rng); (deg+2) as usize];

	_ = lagrange_interpolation_g2::<E>(&evals, &points, deg).unwrap();
    }


    #[test]
    fn test_lagrange_interpolation() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
	let generator = srs.g2;

	let p = Polynomial::<E>::rand(deg as usize, rng);
	let secret = p.coeffs[0];
	let shared_secret = generator.mul(secret.into_repr());

	let points = (1..(deg+2))
		.map(|j| Scalar::<E>::from(j as u64))
		.collect::<Vec<_>>();
	let evals = (1..(deg+2))
		.map(|j| generator.mul(p.evaluate(&points[(j-1) as usize]).into_repr()).into_affine())
		.collect::<Vec<_>>();

	let reconstructed_secret = lagrange_interpolation_g2::<E>(&evals, &points, deg).unwrap();

	assert_eq!(reconstructed_secret, shared_secret);
    }

    
    #[test]
    fn test_reconstruction_over_target_group() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let g1 = srs.g1;
	let epoch_generator = srs.g2;   // assume that g2 is the epoch generator in G2

        // let x = GT::<E>::rand(rng);
        
        // random points in G1 representing the decrypted shares
        let sks: Vec<G1Affine>= (1..=(deg+1))
                        .map(|_| g1.mul(Scalar::<E>::rand(rng).into_repr()).into_affine())
                        .collect();

        // sigma_{j, 2} := e(SK_j, g_r)
        let evals = (0..sks.len())
                             .map(|i| E::pairing::<EncGroup::<E>, ComGroup::<E>>(sks[i].into(), epoch_generator.into()))
                             .collect::<Vec<_>>();

        // Assume for simplicity that the shares come from the first t+1 parties
        let points = (0..=deg)
                         .map(|j| (j + 1) as u64)
                         .collect::<Vec<_>>();

        let _reconstructed_secret = lagrange_interpolation_gt::<E>(&evals, &points, deg).unwrap();

	// println!("Reconstructed secret: {:?}", reconstructed_secret);

	assert_eq!(2+2, 4);
    }


    #[test]
    fn test_lagrange_interpolation_target_group_different_sets() {
	    let rng = &mut thread_rng();
        let num_participants: usize = 8;   // number of nodes n
        let degree: usize = 3;             // degree t

        // Generate new PVSS srs and config
        let srs = SRS::<E>::setup(rng).unwrap();

        // Set global configuration parameters
        let conf = Config::<E> {
            srs: srs.clone(),
            degree,
            num_participants,
        };

        // Setup Schnorr signature scheme
        let schnorr_srs = SCHSRS::<EncGroup<E>>::from_generator(conf.srs.g1).unwrap();
        let schnorr_sig = SchnorrSignature { srs: schnorr_srs };

        let mut dealers = vec![];
        let mut nodes = vec![];

        for id in 0..num_participants {   // IMPORTANT: Notice that here I use ids in {0, ..., n-1}
            // Generate key pairs for party
            let dealer_keypair_sig = schnorr_sig.generate_keypair(rng).unwrap(); // (sk, pk)
            let eddsa_keypair = generate_production_keypair(); // (pk, sk)

            // Create the dealer instance for party
            let dealer: Dealer<E, SchnorrSignature<EncGroup<E>>> = Dealer {
                private_key_sig: dealer_keypair_sig.0,
                private_key_ed: eddsa_keypair.1,
                participant: Participant {
                    pairing_type: PhantomData,
                    id,
                    public_key_sig: dealer_keypair_sig.1,
                    public_key_ed: eddsa_keypair.0,
                },
            };

            dealers.push(dealer);
        }

        let participants_vec = (0..num_participants)
            .map(|i| dealers[i].participant.clone())
            .collect::<Vec<_>>();

        let mut participants = BTreeMap::new();
        for (id, party) in (0..num_participants).zip(participants_vec) {
            participants.insert(id, party);
        }

        for i in 0..num_participants {
            // Create the node instance for party
            let node = Node::new(
                conf.clone(),
                schnorr_sig.clone(),
                dealers[i].clone(),
                participants.clone(),
            )
            .unwrap();

            nodes.push(node);
        }

        // Sample a random polynomial of degree t
        let f = Polynomial::<E>::rand(degree, rng);

        // Evaluate polynomial at points 1, ..., n.
        let s = (1..=num_participants)
            .map(|i| f.evaluate(&Scalar::<E>::from(i as u64)))
            .collect::<Vec<_>>();

        let pvss_core = PVSSCore::<E> {
            encs: (0..num_participants)
                .map(|i| {
                    nodes[i]
                        .aggregator
                        .participants
                        .get(&i)
                        .ok_or(PVSSError::<E>::InvalidParticipantId(i))
                        .unwrap()
                        .public_key_sig
                        .mul(s[i])
                        .into_affine()
                })
                .collect::<Vec<EncGroup<E>>>(),
            comms: (0..num_participants)
                .map(|i| conf.srs.g2.mul(s[i]).into_affine())
                .collect::<Vec<ComGroup<E>>>(), // PKs
        };

        // Compute "secret key shares" for all nodes
        let sks = (0..num_participants)
            .map(|i| {
                DecryptedShare::<E>::generate(
                    &pvss_core.encs,
                    &nodes[i].dealer.private_key_sig,
                    nodes[i].dealer.participant.id,
                )
                .dec
            })
            .collect::<Vec<_>>();

        let persona = b"OnePiece";
        let current_epoch: u128 = 2;

        // Compute new epoch generator
        let epoch_generator =
            hash_to_group::<ComGroup<E>>(persona, &current_epoch.to_le_bytes())
                .unwrap()
                .into_affine();

	    // Create two sets of evaluation points
	    let points1 = (1..=degree+1)           // 1, 2, 3, 4
		    .map(|i| i as u64)
		    .collect::<Vec<_>>();

	    let evals1 = (0..points1.len())
		    .map(|j| <E as PairingEngine>::pairing(sks[points1[j] as usize - 1], epoch_generator))   // random points won't work
		    .collect::<Vec<_>>();

        let rec1 = lagrange_interpolation_gt::<E>(&evals1, &points1, degree as u64).unwrap();

        println!("rec1 = {:?}\n", rec1);

        let points2 = (degree+2..=(2*degree+2))           // 5, 6, 7, 8
		    .map(|i| i as u64)
		    .collect::<Vec<_>>();

	    let evals2 = (0..points2.len())
		    .map(|j| <E as PairingEngine>::pairing(sks[points2[j] as usize - 1], epoch_generator))   // random points won't work
		    .collect::<Vec<_>>();

        let rec2 = lagrange_interpolation_gt::<E>(&evals2, &points2, degree as u64).unwrap();

        println!("rec2 = {:?}\n", rec2);

        let points3: Vec<u64> = vec![3, 5, 1, 7];

        let evals3 = (0..points3.len())
		    .map(|j| <E as PairingEngine>::pairing(sks[points3[j] as usize - 1], epoch_generator))   // random points won't work
		    .collect::<Vec<_>>();

        let rec3 = lagrange_interpolation_gt::<E>(&evals3, &points3, degree as u64).unwrap();

        println!("rec3 = {:?}\n", rec3);

	// Trial with a larger set of points
        let points4: Vec<u64> = (1..=num_participants)
            .map(|i| i as u64)
            .collect::<Vec<_>>();

        let evals4 = (0..points4.len())
		    .map(|j| <E as PairingEngine>::pairing(sks[points4[j] as usize - 1], epoch_generator))   // random points won't work
		    .collect::<Vec<_>>();

        let rec4 = lagrange_interpolation_gt::<E>(&evals4, &points4, degree as u64).unwrap();

        println!("rec4 = {:?}\n", rec3);

        assert_eq!(rec1, rec2);
        assert_eq!(rec2, rec3);
        assert_eq!(rec3, rec4);
    }

}
