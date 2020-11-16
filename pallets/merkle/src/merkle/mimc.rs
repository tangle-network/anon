use super::constants::{MIMC_CONSTANTS, MIMC_ROUNDS};
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination};
use curve25519_dalek::scalar::Scalar;

pub fn mimc(xl: Scalar, xr: Scalar) -> Scalar {
	assert_eq!(MIMC_CONSTANTS.len(), MIMC_ROUNDS);

	let mut xl = xl.clone();
	let mut xr = xr.clone();

	for i in 0..MIMC_ROUNDS {
		let tmp1 = xl + Scalar::from_canonical_bytes(MIMC_CONSTANTS[i]).unwrap();
		let mut tmp2 = (tmp1 * tmp1) * tmp1;
		tmp2 += xr;
		xr = xl;
		xl = tmp2;
	}

	xl
}

pub fn mimc_constraints<CS: ConstraintSystem>(
	cs: &mut CS,
	xl: &LinearCombination,
	xr: &LinearCombination,
	constants: &[Scalar],
) -> LinearCombination {
	assert_eq!(constants.len(), MIMC_ROUNDS);

	let mut xl = xl.clone();
	let mut xr = xr.clone();

	for i in 0..MIMC_ROUNDS {
		let tmp1 = xl.clone() + constants[i];
		let (_, _, tmp2_m) = cs.multiply(tmp1.clone(), tmp1.clone());
		let (_, _, tmp2) = cs.multiply(tmp2_m.into(), tmp1);
		let tmp2 = tmp2 + xr;
		xr = xl;
		xl = tmp2;
	}

	xl
}
