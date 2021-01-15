use super::{
	constants::{MDS_ENTRIES, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS, ROUND_CONSTS},
	hasher::Hasher,
};
use bulletproofs::{
	r1cs::{ConstraintSystem, LinearCombination, Prover, Verifier},
	PedersenGens,
};
use curve25519_dalek::scalar::Scalar;
use sp_std::prelude::*;

#[derive(Eq, PartialEq, Clone, Default, Debug)]
pub struct Poseidon {
	pub width: usize,
	// Number of full SBox rounds
	pub full_rounds: usize,
	// Number of partial SBox rounds
	pub partial_rounds: usize,
	pub round_keys: Vec<Scalar>,
	pub mds_matrix: Vec<Vec<Scalar>>,
}

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

impl Poseidon {
	pub fn new(width: usize) -> Self {
		let full_rounds = POSEIDON_FULL_ROUNDS;
		let partial_rounds = POSEIDON_PARTIAL_ROUNDS;
		let total_rounds = full_rounds + partial_rounds;
		let round_keys = Self::gen_round_keys(width, total_rounds);
		let matrix_2 = Self::gen_mds_matrix(width);
		Self {
			width,
			full_rounds,
			partial_rounds,
			round_keys,
			mds_matrix: matrix_2,
		}
	}

	fn gen_round_keys(width: usize, total_rounds: usize) -> Vec<Scalar> {
		let cap = total_rounds * width;
		if ROUND_CONSTS.len() < cap {
			panic!(
				"Not enough round constants, need {}, found {}",
				cap,
				ROUND_CONSTS.len()
			);
		}
		let mut rc = vec![];
		for i in 0..cap {
			let c = get_scalar_from_hex(ROUND_CONSTS[i]);
			rc.push(c);
		}
		rc
	}

	fn gen_mds_matrix(width: usize) -> Vec<Vec<Scalar>> {
		let mut mds: Vec<Vec<Scalar>> = vec![vec![Scalar::zero(); width]; width];
		for i in 0..width {
			for j in 0..width {
				mds[i][j] = get_scalar_from_hex(MDS_ENTRIES[i][j]);
			}
		}
		mds
	}

	pub fn mix(&self, state: &Vec<Scalar>) -> Vec<Scalar> {
		let mut new_state: Vec<Scalar> = Vec::new();
		for i in 0..state.len() {
			let mut sc = Scalar::zero();
			for j in 0..state.len() {
				let mij = self.mds_matrix[j][i];
				sc += mij * state[j];
			}
			new_state.push(sc);
		}
		new_state
	}

	pub fn mix_lc(&self, state: &Vec<LinearCombination>) -> Vec<LinearCombination> {
		let mut new_state: Vec<LinearCombination> = Vec::new();
		let mut simp_state: Vec<LinearCombination> = Vec::new();
		for i in 0..state.len() {
			simp_state.push(state[i].clone().simplify());
		}
		for i in 0..state.len() {
			let mut lc = LinearCombination::default();
			for j in 0..state.len() {
				let mij = self.mds_matrix[j][i];
				lc = lc.clone() + (simp_state[j].clone() * mij);
			}
			new_state.push(lc);
		}
		new_state
	}

	pub fn apply_sbox(&self, elem: Scalar) -> Scalar {
		(elem * elem) * elem
	}

	pub fn synthesize_sbox<CS: ConstraintSystem>(
		&self,
		cs: &mut CS,
		input_var: LinearCombination,
	) -> LinearCombination
	{
		let (i, _, sqr) = cs.multiply(input_var.clone(), input_var);
		let (_, _, cube) = cs.multiply(sqr.into(), i.into());
		cube.into()
	}

	pub fn permute(&self, inputs: &[Scalar]) -> Vec<Scalar> {
		assert_eq!(inputs.len(), self.width);

		let rounds = self.full_rounds + self.partial_rounds;
		assert!(
			self.full_rounds % 2 == 0,
			"asymmetric permutation configuration"
		);
		let full_rounds_per_side = self.full_rounds / 2;
		let mut current = inputs.to_vec();
		let mut const_num = 0;
		for round in 0..rounds {
			let full = round < full_rounds_per_side || round >= rounds - full_rounds_per_side;
			// Ark transformation
			current = current
				.iter()
				.map(|exp| {
					let new_exp = exp + self.round_keys[const_num];
					const_num += 1;
					new_exp
				})
				.collect();
			if full {
				// Full layer
				current = current.iter().map(|exp| self.apply_sbox(*exp)).collect();
			} else {
				// Partial layer, only one input is passed to sbox,
				// The choice is arbitrary
				current[0] = self.apply_sbox(current[0]);
			}

			// Mix layer.
			current = self.mix(&current);
		}
		current
	}

	pub fn permute_constraints<CS: ConstraintSystem>(
		&self,
		cs: &mut CS,
		inputs: Vec<LinearCombination>,
	) -> Vec<LinearCombination>
	{
		assert_eq!(inputs.len(), self.width);

		let rounds = self.full_rounds + self.partial_rounds;
		assert!(
			self.full_rounds % 2 == 0,
			"asymmetric permutation configuration"
		);
		let full_rounds_per_side = self.full_rounds / 2;
		let mut current = inputs.to_vec();
		let mut const_num = 0;
		for round in 0..rounds {
			let full = round < full_rounds_per_side || round >= rounds - full_rounds_per_side;
			// Ark transformation
			current = current
				.iter()
				.map(|exp| {
					let new_exp = exp.clone() + self.round_keys[const_num];
					const_num += 1;
					new_exp
				})
				.collect();
			if full {
				// Full layer
				current = current
					.into_iter()
					.map(|exp| self.synthesize_sbox(cs, exp))
					.collect();
			} else {
				// Partial layer, only one input is passed to sbox,
				// The choice is arbitrary
				current[0] = self.synthesize_sbox(cs, current[0].clone().into());
			}

			// Mix layer.
			current = self.mix_lc(&current);
		}
		current
	}

	pub fn constrain<CS: ConstraintSystem>(
		&self,
		cs: &mut CS,
		inputs: Vec<LinearCombination>,
	) -> LinearCombination
	{
		let permutation_output = self.permute_constraints::<CS>(cs, inputs);
		permutation_output[1].clone()
	}

	pub fn hash_2(&self, xl: Scalar, xr: Scalar) -> Scalar {
		let input = vec![
			Scalar::from(ZERO_CONST),
			xl,
			xr,
			Scalar::from(PADDING_CONST),
		];
		let res = self.permute(&input);
		res[1]
	}

	pub fn hash_4(&self, x1: Scalar, x2: Scalar, x3: Scalar, x4: Scalar) -> Scalar {
		let input = vec![
			Scalar::from(ZERO_CONST),
			x1,
			x2,
			x3,
			x4,
			Scalar::from(PADDING_CONST),
		];

		self.permute(&input)[1]
	}

	pub fn prover_constrain_inputs(
		prover: &mut Prover,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> Vec<LinearCombination>
	{
		let (_, var1) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
		let (_, var4) = prover.commit(Scalar::from(PADDING_CONST), Scalar::zero());
		let inputs = vec![var1.into(), xl, xr, var4.into()];
		inputs
	}

	pub fn verifier_constrain_inputs(
		verifier: &mut Verifier,
		pc_gens: &PedersenGens,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> Vec<LinearCombination>
	{
		// TODO use passed commitments instead odd committing again in runtime
		let com_zero = pc_gens
			.commit(Scalar::from(ZERO_CONST), Scalar::zero())
			.compress();
		let com_pad = pc_gens
			.commit(Scalar::from(PADDING_CONST), Scalar::zero())
			.compress();
		let var1 = verifier.commit(com_zero);
		let var4 = verifier.commit(com_pad);
		let inputs = vec![var1.into(), xl, xr, var4.into()];
		inputs
	}
}

pub fn decode_hex(s: &str) -> Vec<u8> {
	let s = &s[2..];
	let vec: Vec<u8> = (0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
		.collect();

	vec
}

pub fn get_scalar_from_hex(hex_str: &str) -> Scalar {
	let bytes = decode_hex(hex_str);
	let mut result: [u8; 32] = [0; 32];
	result.copy_from_slice(&bytes);
	Scalar::from_bytes_mod_order(result)
}

impl Hasher for Poseidon {
	fn hash(&self, xl: Scalar, xr: Scalar) -> Scalar {
		self.hash_2(xl, xr)
	}

	fn constrain_prover(
		&self,
		prover: &mut Prover,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination
	{
		let inputs = Poseidon::prover_constrain_inputs(prover, xl, xr);
		self.constrain(prover, inputs)
	}

	fn constrain_verifier(
		&self,
		verifier: &mut Verifier,
		pc_gens: &PedersenGens,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination
	{
		let inputs = Poseidon::verifier_constrain_inputs(verifier, pc_gens, xl, xr);
		self.constrain(verifier, inputs)
	}
}
