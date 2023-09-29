use super::errors::PVSSError;
use crate::Scalar;

use ark_ff::{Field, Zero, One, PrimeField};
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_poly::{UVPolynomial, Polynomial as Poly, polynomial::univariate::DensePolynomial};
use ark_std::ops::AddAssign;
// use ark_std::ops::{Add, Mul};

use rand::Rng;


// A polynomial with the various coefficients in the Scalar Group
pub type Polynomial<E> = DensePolynomial<Scalar<E>>;



// Function for ensuring that the commitment vector evals is
// also a commitment to a polynomial of specified degree.
pub fn ensure_degree<E, R>(rng: &mut R,
                           evaluations: &Vec<E::G2Projective>,
                           degree: u64) -> Result<(), PVSSError<E>>
where
	E: PairingEngine,
	E::G2Projective: AddAssign,
	R: Rng
	//Scalar<E>: AsRef<[u64]>,
	//Scalar<E>: AddAssign<<E as PairingEngine>::G2Affine>,
	//Scalar<E>: From<u64>,
	//Scalar<E>: Add<Output = Scalar<E>>,
	//Scalar<E>: Mul<Output = Scalar<E>>,
{
    let num = evaluations.len() as u64;

    if num < degree {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    // sample a random polynomial of appropriate degree
    let poly = Polynomial::<E>::rand((num-degree-2) as usize, rng);

    let mut v = E::G2Projective::zero();

    for i in 1..num+1 {
        let scalar_i = Scalar::<E>::from(i);
	let mut cperp = poly.evaluate(&scalar_i);
	for j in 1..num+1 {
            let scalar_j = Scalar::<E>::from(j);
            if i != j {
                cperp *= (scalar_i - scalar_j).inverse().unwrap();
            }
        }
	v += evaluations[(i-1) as usize].mul(cperp.into_repr());   // .into_affine();
    }

    if v.into_affine() != E::G2Affine::zero() {
	return Err(PVSSError::DualCodeError);
    }

    Ok(())

}



// Utility function for Lagrange interpolation from a given list of evaluations.
pub fn lagrange_interpolation_simple<E>(evals: &Vec<E::G2Projective>,
					degree: u64) -> Result<E::G2Projective, PVSSError<E>> 
where
	E: PairingEngine,
	Scalar<E>: From<u64>,
	//E::G2Projective: AddAssign,
{
    if evals.len() < (degree + 1) as usize {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    let mut sum = E::G2Projective::zero();
    
    for j in 0..degree+1 {
        let x_j = Scalar::<E>::from(j + 1);
	let mut prod = Scalar::<E>::one();
	for k in 0..degree+1 {
	    if j != k {
	        let x_k = Scalar::<E>::from(k + 1);
	        prod *= x_k * (x_k - x_j).inverse().unwrap();
	    }
	}

	// Recovery formula
	sum += evals[j as usize].mul(prod.into_repr());
    }

    Ok(sum)
}



// Utility function for Lagrange interpolation from a given list of points
// and evaluations.
pub fn lagrange_interpolation<E>(evals: &Vec<E::G2Projective>,
				 points: &Vec<Scalar<E>>,
				 degree: u64) -> Result<E::G2Projective, PVSSError<E>> 
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
}


/* Unit tests: */



#[cfg(test)]
mod test {
    use rand::{Rng, thread_rng};
    use crate::ark_std::UniformRand;
    use ark_ff::PrimeField;
    use ark_poly::{UVPolynomial, Polynomial as Poly};
    use ark_ec::{PairingEngine, ProjectiveCurve, AffineCurve};
    use ark_bls12_381::{Bls12_381 as E};   // implements PairingEngine


    use crate::modified_scrape::{poly::{Polynomial, ensure_degree, lagrange_interpolation_simple, lagrange_interpolation}};
    use crate::modified_scrape::{srs::SRS};
    use crate::Scalar;


    // cargo test -- --nocapture


    const MIN_DEGREE: usize = 3;
    const MAX_DEGREE: usize = 100;


    #[test]
    fn test_sample_poly() {
        let rng = &mut thread_rng();
	let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE);

	// generate a random polynomial
	let _p = Polynomial::<E>::rand(deg, rng);
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
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng); (deg+4) as usize];
        assert_eq!(ensure_degree::<E, _>(rng, &evals, deg).unwrap(), ());
    }


    #[test]
    #[should_panic]
    fn test_ensure_degree_insufficient_evals() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	// we use random group elemements from G_2 since it doesn't matter here.
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng); (deg-1) as usize];
        ensure_degree::<E, _>(rng, &evals, deg).unwrap();
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_simple_insufficient_evals() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	// we use random group elemements from G_2 since it doesn't matter here.
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng); (deg-1) as usize];

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
		.map(|x| generator.mul(p.evaluate(&Scalar::<E>::from(x as u64)).into_repr()))
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
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng); (deg-1) as usize];
	let points = vec![Scalar::<E>::rand(rng); (deg-1) as usize];

	_ = lagrange_interpolation::<E>(&evals, &points, deg).unwrap();
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_different_points_evals() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	// we use random elements since it doesn't matter here
        let evals = vec![<E as PairingEngine>::G2Projective::rand(rng); (deg+1) as usize];
	let points = vec![Scalar::<E>::rand(rng); (deg+2) as usize];

	_ = lagrange_interpolation::<E>(&evals, &points, deg).unwrap();
    }


    #[test]
    fn test_lagrange_interpolation() {
	let rng = &mut thread_rng();
        let deg = rng.gen_range(MIN_DEGREE, MAX_DEGREE) as u64;

	let srs = SRS::<E>::setup(rng).unwrap();   // setup PVSS scheme's SRS
	let generator = srs.g2;   // affine

	let p = Polynomial::<E>::rand(deg as usize, rng);
	let secret = p.coeffs[0];
	let shared_secret = generator.mul(secret.into_repr());

	let points = (1..(deg+2))
		.map(|j| Scalar::<E>::from(j as u64))
		.collect::<Vec<_>>();
	let evals = (1..(deg+2))
		.map(|j| generator.mul(p.evaluate(&points[(j-1) as usize]).into_repr()))
		.collect::<Vec<_>>();

	let reconstructed_secret = lagrange_interpolation::<E>(&evals, &points, deg).unwrap();

	assert_eq!(reconstructed_secret, shared_secret);
    }

}
