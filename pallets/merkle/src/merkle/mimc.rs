use super::constants::{MIMC_CONSTANTS, MIMC_ROUNDS};
use super::hasher::Hasher;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, Verifier};
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;

pub struct Mimc {
	rounds: usize,
	constants: [[u8; 32]; 10],
}

impl Mimc {
	pub fn new() -> Self {
		Self {
			rounds: MIMC_ROUNDS,
			constants: MIMC_CONSTANTS,
		}
	}
	pub fn mimc(&self, xl: Scalar, xr: Scalar) -> Scalar {
		assert_eq!(self.constants.len(), self.rounds);

		let mut xl = xl.clone();
		let mut xr = xr.clone();

		for i in 0..self.rounds {
			let tmp1 = xl + Scalar::from_bytes_mod_order(self.constants[i]);
			let mut tmp2 = (tmp1 * tmp1) * tmp1;
			tmp2 += xr;
			xr = xl;
			xl = tmp2;
		}

		xl
	}

	pub fn mimc_constraints<CS: ConstraintSystem>(
		&self,
		cs: &mut CS,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination {
		assert_eq!(self.constants.len(), self.rounds);

		let mut xln = xl.clone();
		let mut xrn = xr.clone();

		for i in 0..self.rounds {
			let tmp1 = xln.clone() + Scalar::from_bytes_mod_order(self.constants[i]);
			let (_, _, tmp2_m) = cs.multiply(tmp1.clone(), tmp1.clone());
			let (_, _, tmp2) = cs.multiply(tmp2_m.into(), tmp1);
			let tmp2 = tmp2 + xrn;
			xrn = xln;
			xln = tmp2;
		}

		xln
	}
}

impl Hasher for Mimc {
	fn hash(&self, xl: Scalar, xr: Scalar) -> Scalar {
		self.mimc(xl, xr)
	}

	fn constrain_prover(
		&self,
		cs: &mut Prover,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination {
		self.mimc_constraints(cs, xl, xr)
	}

	fn constrain_verifier(
		&self,
		cs: &mut Verifier,
		_: &PedersenGens,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination {
		self.mimc_constraints(cs, xl, xr)
	}
}
