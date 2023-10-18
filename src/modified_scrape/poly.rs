use crate::{
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
                           evaluations: &Vec<E::G2Affine>,   // G2 is the group of commitments
                           degree: u64) -> Result<(), PVSSError<E>>
where
	E: PairingEngine,
	//E::G2Projective: AddAssign,
	R: Rng
{
    let num = evaluations.len() as u64;

    if num < degree {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    // Sample a random polynomial of appropriate degree
    let poly = Polynomial::<E>::rand((num-degree-2) as usize, rng);

    let mut sum = E::G2Projective::zero();

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

    if sum != E::G2Projective::zero() {
	    return Err(PVSSError::DualCodeError);
    }

    Ok(())
}


// Utility function for Lagrange interpolation from a given list of evaluations.
pub fn lagrange_interpolation_simple<E>(evals: &Vec<E::G2Affine>,
					degree: u64) -> Result<E::G2Affine, PVSSError<E>> 
where
	E: PairingEngine,
	Scalar<E>: From<u64>,
	//E::G2Projective: AddAssign,
{
    if evals.len() < (degree + 1) as usize {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    let mut sum = E::G2Projective::zero();
    
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
pub fn lagrange_interpolation_g1<E>(evals: &Vec<E::G1Affine>,
				 points: &Vec<Scalar<E>>,
				 degree: u64) -> Result<E::G1Affine, PVSSError<E>> 
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

    let mut sum = E::G1Projective::zero();

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
pub fn lagrange_interpolation_g2<E>(evals: &Vec<E::G2Affine>,
				 points: &Vec<Scalar<E>>,
				 degree: u64) -> Result<E::G2Affine, PVSSError<E>> 
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

    let mut sum = E::G2Projective::zero();

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
pub fn lagrange_interpolation_gt<E>(evals: &Vec<<E as PairingEngine>::Fqk>,
    points: &Vec<u64>,   // &Vec<Scalar<E>>,
    degree: u64) -> Result<<E as PairingEngine>::Fqk, PVSSError<E>> 
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

    let mut result = E::Fqk::one(); //E::Fqk::zero();

    for j in 0..=degree {
        let x_j = <<E as PairingEngine>::Fqk as Field>::BasePrimeField::from(points[j as usize]);
        let mut prod = <<E as PairingEngine>::Fqk as Field>::BasePrimeField::one();
        for k in 0..=degree {
            if j != k {
                let x_k = <<E as PairingEngine>::Fqk as Field>::BasePrimeField::from(points[k as usize]);
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
    use crate::{
        modified_scrape::{
            poly::{
                Polynomial,
                ensure_degree,
                lagrange_interpolation_simple,
                lagrange_interpolation_g2,
                lagrange_interpolation_gt,
            },
            srs::SRS,
        },
        Scalar,
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
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng).into_affine(); (deg+4) as usize];
        assert_eq!(ensure_degree::<E, _>(rng, &evals, deg).unwrap(), ());
    }


    #[test]
    #[should_panic]
    fn test_ensure_degree_insufficient_evals() {
        let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

        // we use random group elemements from G_2 since it doesn't matter here.
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng).into_affine(); (deg-1) as usize];
        ensure_degree::<E, _>(rng, &evals, deg).unwrap();
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_simple_insufficient_evals() {
        let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

        // we use random group elemements from G_2 since it doesn't matter here.
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng).into_affine(); (deg-1) as usize];

        _ = lagrange_interpolation_simple::<E>(&evals, deg).unwrap();
    }


    #[test]
    fn test_lagrange_interpolation_simple() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
	let generator = srs.g2;   // affine

	let p = Polynomial::<E>::rand(deg as usize, rng);
	let secret = p.coeffs[0];
	let shared_secret = generator.mul(secret.into_repr());

	let evals = (1..(deg+2))
		.map(|x| generator.mul(p.evaluate(&Scalar::<E>::from(x as u64)).into_repr()).into_affine())
		.collect::<Vec<_>>();

	let reconstructed_secret = lagrange_interpolation_simple::<E>(&evals, deg).unwrap();   // G2Projective

	assert_eq!(reconstructed_secret, shared_secret);
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_insufficient_evals() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	// we use random elements since it doesn't matter here
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng).into_affine(); (deg-1) as usize];
	let points = vec![Scalar::<E>::rand(rng); (deg-1) as usize];

	_ = lagrange_interpolation_g2::<E>(&evals, &points, deg).unwrap();
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_different_points_evals() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	// we use random elements since it doesn't matter here
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng).into_affine(); (deg+1) as usize];
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
    fn test_lagrange_interpolation_target_group() {
	    let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	    let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
        let g1 = srs.g1;
	    let epoch_generator = srs.g2;   // assume that g2 is the epoch generator in G2

        // let x = <E as PairingEngine>::Fqk::rand(rng);
        
        // random points in G1 representing the decrypted shares
        let sks: Vec<G1Affine>= (1..=(deg+1))
                        .map(|_| g1.mul(<E as PairingEngine>::Fr::rand(rng).into_repr()).into_affine())
                        .collect();

        // sigma_{j, 2} := e(SK_j, g_r)
        let evals = (0..sks.len())
                             .map(|i| E::pairing::<<E as PairingEngine>::G1Affine, <E as PairingEngine>::G2Affine>(sks[i].into(), epoch_generator.into()))
                             .collect::<Vec<_>>();

        // Assume for simplicity that the shares come from the first t+1 parties
        let points = (0..=deg)
                                                    .map(|j| (j + 1) as u64)
                                                    .collect::<Vec<_>>();

	    let _reconstructed_secret = lagrange_interpolation_gt::<E>(&evals, &points, deg).unwrap();

        // println!("Reconstructed secret: {:?}", reconstructed_secret);

        assert_eq!(2+2, 4);
    }

}
