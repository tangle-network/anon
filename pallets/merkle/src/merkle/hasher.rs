use bulletproofs::{
	r1cs::{LinearCombination, Prover, Verifier},
	PedersenGens,
};
use curve25519_dalek::scalar::Scalar;

pub trait Hasher {
	fn hash(&self, xl: Scalar, xr: Scalar) -> Scalar;
	fn constrain_prover(&self, cs: &mut Prover, xl: LinearCombination, xr: LinearCombination) -> LinearCombination;
	fn constrain_verifier(
		&self,
		cs: &mut Verifier,
		pc_gens: &PedersenGens,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination;
}
