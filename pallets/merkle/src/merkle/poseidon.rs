use super::constants::{MDS_ENTRIES, ROUND_CONSTS};
use super::hasher::Hasher;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::prelude::*;

pub fn simplify(lc: LinearCombination) -> LinearCombination {
	// Build hashmap to hold unique variables with their values.
	let mut vars: BTreeMap<Variable, Scalar> = BTreeMap::new();

	let terms: Vec<(Variable, Scalar)> = lc.get_terms().to_vec();
	for (var, val) in terms {
		*vars.entry(var).or_insert(Scalar::zero()) += val;
	}

	let mut new_lc_terms = vec![];
	for (var, val) in vars {
		new_lc_terms.push((var, val));
	}
	new_lc_terms.iter().collect()
}

#[derive(Eq, PartialEq, Clone, Default, Debug)]
pub struct Poseidon {
	pub width: usize,
	// Number of full SBox rounds in beginning
	pub full_rounds_beginning: usize,
	// Number of full SBox rounds in end
	pub full_rounds_end: usize,
	// Number of partial SBox rounds in beginning
	pub partial_rounds: usize,
	pub round_keys: Vec<Scalar>,
	pub mds_matrix: Vec<Vec<Scalar>>,
}

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

impl Poseidon {
	pub fn new(
		width: usize,
		full_rounds_beginning: usize,
		full_rounds_end: usize,
		partial_rounds: usize,
	) -> Self {
		let total_rounds = full_rounds_beginning + partial_rounds + full_rounds_end;
		let round_keys = Self::gen_round_keys(width, total_rounds);
		let matrix_2 = Self::gen_mds_matrix(width);
		Self {
			width,
			full_rounds_beginning,
			full_rounds_end,
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
		if MDS_ENTRIES.len() != width {
			panic!("Incorrect width, only width {} is supported now", width);
		}
		let mut mds: Vec<Vec<Scalar>> = vec![vec![Scalar::zero(); width]; width];
		for i in 0..width {
			if MDS_ENTRIES[i].len() != width {
				panic!("Incorrect width, only width {} is supported now", width);
			}
			for j in 0..width {
				mds[i][j] = get_scalar_from_hex(MDS_ENTRIES[i][j]);
			}
		}
		mds
	}

	pub fn apply_sbox(&self, elem: &Scalar) -> Scalar {
		(elem * elem) * elem
	}

	pub fn synthesize_sbox<CS: ConstraintSystem>(
		&self,
		cs: &mut CS,
		input_var: LinearCombination,
	) -> Variable {
		let (i, _, sqr) = cs.multiply(input_var.clone(), input_var);
		let (_, _, cube) = cs.multiply(sqr.into(), i.into());
		cube
	}

	pub fn get_total_rounds(&self) -> usize {
		self.full_rounds_beginning + self.partial_rounds + self.full_rounds_end
	}

	pub fn permute(&self, input: &[Scalar]) -> Vec<Scalar> {
		let width = self.width;
		assert_eq!(input.len(), width);

		let full_rounds_beginning = self.full_rounds_beginning;
		let partial_rounds = self.partial_rounds;
		let full_rounds_end = self.full_rounds_end;

		let mut current_state = input.to_vec();
		let mut current_state_temp = vec![Scalar::zero(); width];

		let mut round_keys_offset = 0;

		for _ in 0..full_rounds_beginning {
			for i in 0..width {
				current_state[i] += self.round_keys[round_keys_offset];
				current_state[i] = self.apply_sbox(&current_state[i]);
				round_keys_offset += 1;
			}

			for j in 0..width {
				for i in 0..width {
					current_state_temp[i] += current_state[j] * self.mds_matrix[i][j];
				}
			}

			for i in 0..width {
				current_state[i] = current_state_temp[i];
				current_state_temp[i] = Scalar::zero();
			}
		}

		for _ in full_rounds_beginning..(full_rounds_beginning + partial_rounds) {
			for i in 0..width {
				current_state[i] += &self.round_keys[round_keys_offset];
				round_keys_offset += 1;
			}
			current_state[width - 1] = self.apply_sbox(&current_state[width - 1]);

			for j in 0..width {
				for i in 0..width {
					current_state_temp[i] += current_state[j] * self.mds_matrix[i][j];
				}
			}

			for i in 0..width {
				current_state[i] = current_state_temp[i];
				current_state_temp[i] = Scalar::zero();
			}
		}

		for _ in full_rounds_beginning + partial_rounds
			..(full_rounds_beginning + partial_rounds + full_rounds_end)
		{
			for i in 0..width {
				current_state[i] += self.round_keys[round_keys_offset];
				current_state[i] = self.apply_sbox(&current_state[i]);
				round_keys_offset += 1;
			}

			for j in 0..width {
				for i in 0..width {
					current_state_temp[i] += current_state[j] * self.mds_matrix[i][j];
				}
			}

			for i in 0..width {
				current_state[i] = current_state_temp[i];
				current_state_temp[i] = Scalar::zero();
			}
		}

		current_state
	}

	pub fn permute_constraints<CS: ConstraintSystem>(
		&self,
		cs: &mut CS,
		inputs: Vec<LinearCombination>,
	) -> Vec<LinearCombination> {
		let width = self.width;
		assert_eq!(inputs.len(), width);
		let mut round_keys_offset = 0;

		let full_rounds_beginning = self.full_rounds_beginning;
		let partial_rounds = self.partial_rounds;
		let full_rounds_end = self.full_rounds_end;

		let mut current_state = inputs.clone();
		let mut current_state_temp = vec![LinearCombination::default(); width];

		for _ in 0..full_rounds_beginning {
			for i in 0..width {
				let inp = current_state[i].clone() + self.round_keys[round_keys_offset];
				current_state[i] = self.synthesize_sbox(cs, inp).into();

				round_keys_offset += 1;
			}

			for j in 0..width {
				for i in 0..width {
					current_state_temp[i] = current_state_temp[i].clone()
						+ current_state[j].clone() * self.mds_matrix[i][j];
				}
			}
			for i in 0..width {
				current_state[i] = simplify(current_state_temp[i].clone());
				current_state_temp[i] = LinearCombination::default();
			}
		}

		for _ in full_rounds_beginning..(full_rounds_beginning + partial_rounds) {
			for i in 0..width {
				current_state[i] = current_state[i].clone() + self.round_keys[round_keys_offset];
				round_keys_offset += 1;
			}
			current_state[width - 1] = self
				.synthesize_sbox(cs, current_state[width - 1].clone())
				.into();

			for j in 0..width {
				for i in 0..width {
					current_state_temp[i] = current_state_temp[i].clone()
						+ current_state[j].clone() * self.mds_matrix[i][j];
				}
			}

			for i in 0..width {
				current_state[i] = simplify(current_state_temp[i].clone());
				current_state_temp[i] = LinearCombination::default();
			}
		}

		for _ in (full_rounds_beginning + partial_rounds)
			..(full_rounds_beginning + partial_rounds + full_rounds_end)
		{
			for i in 0..width {
				let inp = current_state[i].clone() + self.round_keys[round_keys_offset];
				current_state[i] = self.synthesize_sbox(cs, inp).into();
				round_keys_offset += 1;
			}

			for j in 0..width {
				for i in 0..width {
					current_state[i] = current_state[i].clone()
						+ current_state_temp[j].clone() * self.mds_matrix[i][j];
				}
			}

			for i in 0..width {
				current_state[i] = simplify(current_state[i].clone());
			}
		}

		current_state
	}

	pub fn constrain<CS: ConstraintSystem>(
		&self,
		cs: &mut CS,
		inputs: Vec<LinearCombination>,
	) -> LinearCombination {
		let permutation_output = self.permute_constraints::<CS>(cs, inputs);
		permutation_output[1].clone()
	}

	pub fn hash_2(&self, xl: Scalar, xr: Scalar) -> Scalar {
		let input = vec![
			Scalar::from(ZERO_CONST),
			xl,
			xr,
			Scalar::from(PADDING_CONST),
			Scalar::from(ZERO_CONST),
			Scalar::from(ZERO_CONST),
		];
		self.permute(&input)[1]
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
	) -> Vec<LinearCombination> {
		let (_, var1) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
		let (_, var4) = prover.commit(Scalar::from(PADDING_CONST), Scalar::zero());
		let (_, var5) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
		let (_, var6) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
		let inputs = vec![var1.into(), xl, xr, var4.into(), var5.into(), var6.into()];
		inputs
	}

	pub fn verifier_constrain_inputs(
		verifier: &mut Verifier,
		pc_gens: &PedersenGens,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> Vec<LinearCombination> {
		// TODO use passed commitments instead odd committing again in runtime
		let com_zero = pc_gens
			.commit(Scalar::from(ZERO_CONST), Scalar::zero())
			.compress();
		let com_pad = pc_gens
			.commit(Scalar::from(PADDING_CONST), Scalar::zero())
			.compress();
		let var1 = verifier.commit(com_zero);
		let var4 = verifier.commit(com_pad);
		let var5 = verifier.commit(com_zero);
		let var6 = verifier.commit(com_zero);
		let inputs = vec![var1.into(), xl, xr, var4.into(), var5.into(), var6.into()];
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
	) -> LinearCombination {
		let inputs = Poseidon::prover_constrain_inputs(prover, xl, xr);
		self.constrain(prover, inputs)
	}

	fn constrain_verifier(
		&self,
		verifier: &mut Verifier,
		pc_gens: &PedersenGens,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination {
		let inputs = Poseidon::verifier_constrain_inputs(verifier, pc_gens, xl, xr);
		self.constrain(verifier, inputs)
	}
}
