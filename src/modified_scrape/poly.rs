use super::errors::PVSSError;

use ark_poly::polynomial::univariate::DensePolynomial;
use ark_ff::{Field, Zero, One};
use ark_ec::{PairingEngine};   // AffineCurve
use ark_poly::{UVPolynomial, Polynomial as Poly};
use ark_std::fmt::Debug;
use ark_std::ops::{Add, Mul};

use std::str::FromStr;
use rand::Rng;

// The scalar field of the pairing groups
pub type Scalar<E> = <E as PairingEngine>::Fr;   // undesirable since it binds us to a pairing engine

// A polynomial with the various coefficients in the Scalar Group
pub type Polynomial<E> = DensePolynomial<Scalar<E>>;



// 
pub fn ensure_degree<E: PairingEngine,
                     R: Rng>(rng: &mut R,
                             evaluations: &Vec<Scalar<E>>,
                             degree: u64) -> bool
where
	<E as PairingEngine>::Fr: From<u64>,
	<<E as PairingEngine>::Fr as FromStr>::Err: Debug,
	<E as PairingEngine>::Fr: Add<Output = <E as PairingEngine>::Fr>,
	<E as PairingEngine>::Fr: Mul<Output = <E as PairingEngine>::Fr>,
{
    let num = evaluations.len() as u64;

    if num < degree {
        return false;
    }

    // sample a random polynomial of appropriate degree
    let poly = Polynomial::<E>::rand((num-degree-2) as usize, rng);

    let mut v = Scalar::<E>::zero();

    for i in 1..num+1 {
        let scalar_i = Scalar::<E>::from_str(&i.to_string()).unwrap();       // simplify if possible
	let mut cperp = poly.evaluate(&scalar_i);
	for j in 1..num+1 {
            let scalar_j = Scalar::<E>::from_str(&j.to_string()).unwrap();   // simplify if possible
            if i != j {
                cperp *= (scalar_i - scalar_j).inverse().unwrap();
            }
        }
	v += cperp * evaluations[(i-1) as usize];
    }

    v == Scalar::<E>::zero()
}



// 
pub fn lagrange_interpolation_simple<E: PairingEngine>(evals: &Vec<Scalar<E>>,
						       degree: u64) -> Result<Scalar<E>, PVSSError<E>> 
where
	<E as PairingEngine>::Fr: From<u64>
{
    if evals.len() < (degree + 1) as usize {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    let mut sum = Scalar::<E>::zero();
    
    for j in 0..degree+1 {
        let x_j = Scalar::<E>::from(j + 1);
	// ell
	let mut prod = Scalar::<E>::one();
	for k in 0..degree+1 {
	    if j != k {
	        let x_k = Scalar::<E>::from(k + 1);
	        prod *= x_k * (x_k - x_j).inverse().unwrap();   //prod = prod * (x_k * ((x_k - x_j).inverse().unwrap()));
	    }
	}
	sum += prod * evals[j as usize];
    }

    Ok(sum)
}



// 
pub fn lagrange_interpolation<E: PairingEngine>(evals: &Vec<Scalar<E>>,
						points: &Vec<Scalar<E>>,
						degree: u64) -> Result<Scalar<E>, PVSSError<E>> 
where <E as PairingEngine>::Fr: From<u64>
{
    if evals.len() < (degree + 1) as usize {
        return Err(PVSSError::InsufficientEvaluationsError);
    }

    if evals.len() != points.len() {
	return Err(PVSSError::DifferentPointsEvalsError);
    }

    // with imperative programming: 

    let mut sum = Scalar::<E>::zero();

    for j in 0..degree+1 {
        let x_j = points[j as usize];
	let mut prod = Scalar::<E>::one();
	for k in 0..degree+1 {
	    if j != k {
	        let x_k = points[k as usize];
	        prod *= x_k * (x_k - x_j).inverse().unwrap();
	    }
	}
	sum += prod * evals[j as usize];
    }


    // with functional programming:
    /*
    for j in 0..degree+1 {
	let x_j = points[j as usize];
	let mut nums = (0..degree+1).iter().filter(|k| k != j).map(|k| points[k as usize]);
	let mut denoms = (0..degree+1).iter().filter(|k| k != j).map(|k| (points[k as usize] - x_j).inverse().unwrap());
	let prod = nums.zip(denoms).fold(Scalar::<E>::one(), |acc, (x, y)| acc * x * y);
	sum += prod * evals[j as usize];
    }
    */

    // Return the result
    Ok(sum)
}


/* Unit tests: */



#[cfg(test)]
mod test {
    use rand::thread_rng;
    use crate::ark_std::UniformRand;
    use ark_poly::UVPolynomial;
    use ark_poly::{Polynomial as Poly};

    use ark_bls12_381::{Bls12_381 as E};   // implements PairingEngine


    use crate::modified_scrape::{poly::{Scalar, Polynomial, ensure_degree, lagrange_interpolation_simple, lagrange_interpolation}};


    // cargo test -- --nocapture


    #[test]
    fn test_poly() {
        let rng = &mut thread_rng();

	// generate a random polynomial
	let p = Polynomial::<E>::rand(3, rng);
	println!("Sampled polynomial:\n {:?}", p);

	// retrieve its free term
	println!("Its free term is: {:?}", p.coeffs[0]);

	// evaluate polynomial at some given point
	//println!("0 * p(3) = {:?}", Scalar::<E>::from(0 as u64) * p.evaluate(&Scalar::<E>::from(3 as u64)));

	assert_eq!(2+2, 4);
    }


    #[test]
    fn test_ensure_degree() {
	let rng = &mut thread_rng();
        let t = 3u64;
        let evals = vec![Scalar::<E>::rand(rng); (t+4) as usize];
        assert_eq!(ensure_degree::<E, _>(rng, &evals, t), true);
    }


    #[test]
    fn test_ensure_degree_insufficient_evals() {
	let rng = &mut thread_rng();
        let t = 3u64;
        let evals = vec![Scalar::<E>::rand(rng); (t-1) as usize];
        assert_eq!(ensure_degree::<E, _>(rng, &evals, t), false);
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_simple_insufficient_evals() {
	let rng = &mut thread_rng();
        let t = 3u64;
        let evals = vec![Scalar::<E>::rand(rng); (t-1) as usize];

	_ = lagrange_interpolation_simple::<E>(&evals, t).unwrap();
    }


    #[test]
    fn test_lagrange_interpolation_simple() {
	let rng = &mut thread_rng();
        let deg = 3u64;

	let p = Polynomial::<E>::rand(deg as usize, rng);
	let secret = p.coeffs[0];

	let evals = (1..(deg+2)).map(|x| p.evaluate(&Scalar::<E>::from(x as u64))).collect::<Vec<_>>();

	let sum = lagrange_interpolation_simple::<E>(&evals, deg).unwrap();

	assert_eq!(sum, secret);
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_insufficient_evals() {
	let rng = &mut thread_rng();
        let t = 3u64;
        let evals = vec![Scalar::<E>::rand(rng); (t-1) as usize];
	let points = vec![Scalar::<E>::rand(rng); (t-1) as usize];

	_ = lagrange_interpolation::<E>(&evals, &points, t).unwrap();
    }


    #[test]
    #[should_panic]
    fn test_lagrange_interpolation_different_points_evals() {
	let rng = &mut thread_rng();
        let t = 3u64;
        let evals = vec![Scalar::<E>::rand(rng); (t+1) as usize];
	let points = vec![Scalar::<E>::rand(rng); (t+2) as usize];

	_ = lagrange_interpolation::<E>(&evals, &points, t).unwrap();
    }


    #[test]
    fn test_lagrange_interpolation() {
	let rng = &mut thread_rng();
        let deg = 3u64;

	let p = Polynomial::<E>::rand(deg as usize, rng);
	let secret = p.coeffs[0];

	let points = (1..(deg+2)).map(|j| Scalar::<E>::from(j as u64)).collect::<Vec<_>>();
	let evals = (1..(deg+2)).map(|j| p.evaluate(&points[(j-1) as usize])).collect::<Vec<_>>();

	let sum = lagrange_interpolation::<E>(&evals, &points, deg).unwrap();

	assert_eq!(sum, secret);
    }

}
