use super::constants::{MDS_ENTRIES, ROUND_CONSTS};
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Variable};
use curve25519_dalek::scalar::Scalar;
use sp_std::prelude::*;

#[derive(Clone)]
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

	// TODO: Write logic to generate correct round keys.
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
			// TODO: Remove unwrap, handle error
			let c = get_scalar_from_hex(ROUND_CONSTS[i]);
			rc.push(c);
		}
		rc
	}

	// TODO: Write logic to generate correct MDS matrix. Currently loading hardcoded constants.
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
				// TODO: Remove unwrap, handle error
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
		round_key: Scalar,
	) -> Variable {
		let inp_plus_const: LinearCombination = input_var + round_key;
		let (i, _, sqr) = cs.multiply(inp_plus_const.clone(), inp_plus_const);
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
		input: Vec<LinearCombination>,
	) -> Vec<LinearCombination> {
		let width = self.width;
		assert_eq!(input.len(), width);
		let mut input_vars: Vec<LinearCombination> = input;

		let mut round_keys_offset = 0;

		let full_rounds_beginning = self.full_rounds_beginning;
		let partial_rounds = self.partial_rounds;
		let full_rounds_end = self.full_rounds_end;

		for _ in 0..full_rounds_beginning {
			let mut sbox_outputs: Vec<LinearCombination> =
				vec![LinearCombination::default(); width];

			for i in 0..width {
				let round_key = self.round_keys[round_keys_offset];
				sbox_outputs[i] = self
					.synthesize_sbox(cs, input_vars[i].clone(), round_key)
					.into();

				round_keys_offset += 1;
			}

			let mut next_input_vars: Vec<LinearCombination> =
				vec![LinearCombination::default(); width];

			for j in 0..width {
				for i in 0..width {
					next_input_vars[i] = next_input_vars[i].clone()
						+ sbox_outputs[j].clone() * self.mds_matrix[i][j];
				}
			}
			for i in 0..width {
				input_vars[i] = next_input_vars.remove(0);
			}
		}

		for _ in full_rounds_beginning..(full_rounds_beginning + partial_rounds) {
			let mut sbox_outputs: Vec<LinearCombination> =
				vec![LinearCombination::default(); width];
			for i in 0..width {
				let round_key = self.round_keys[round_keys_offset];
				if i == width - 1 {
					sbox_outputs[i] = self
						.synthesize_sbox(cs, input_vars[i].clone(), round_key)
						.into();
				} else {
					sbox_outputs[i] = input_vars[i].clone() + LinearCombination::from(round_key);
				}

				round_keys_offset += 1;
			}

			let mut next_input_vars: Vec<LinearCombination> =
				vec![LinearCombination::default(); width];

			for j in 0..width {
				for i in 0..width {
					next_input_vars[i] = next_input_vars[i].clone()
						+ sbox_outputs[j].clone() * self.mds_matrix[i][j];
				}
			}

			for i in 0..width {
				input_vars[i] = next_input_vars.remove(0);
			}
		}

		for _ in (full_rounds_beginning + partial_rounds)
			..(full_rounds_beginning + partial_rounds + full_rounds_end)
		{
			let mut sbox_outputs: Vec<LinearCombination> =
				vec![LinearCombination::default(); width];
			for i in 0..width {
				let round_key = self.round_keys[round_keys_offset];
				sbox_outputs[i] = self
					.synthesize_sbox(cs, input_vars[i].clone(), round_key)
					.into();

				round_keys_offset += 1;
			}

			let mut next_input_vars: Vec<LinearCombination> =
				vec![LinearCombination::default(); width];

			for j in 0..width {
				for i in 0..width {
					next_input_vars[i] = next_input_vars[i].clone()
						+ sbox_outputs[j].clone() * self.mds_matrix[i][j];
				}
			}

			for i in 0..width {
				input_vars[i] = next_input_vars.remove(0);
			}
		}

		input_vars
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

	pub fn hash_4(&self, inputs: [Scalar; 4]) -> Scalar {
		let input = vec![
			Scalar::from(ZERO_CONST),
			inputs[0],
			inputs[1],
			inputs[2],
			inputs[3],
			Scalar::from(PADDING_CONST),
		];

		self.permute(&input)[1]
	}
}

pub fn decode_hex(s: &str) -> Vec<u8> {
	let s = if s[0..2] == *"0x" || s[0..2] == *"0X" {
		match s.char_indices().skip(2).next() {
			Some((pos, _)) => &s[pos..],
			None => "",
		}
	} else {
		s
	};
	if s.len() % 2 != 0 {
		panic!("Odd length");
	} else {
		let vec: Vec<u8> = (0..s.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
			.collect();

		vec
	}
}

pub fn get_scalar_from_hex(hex_str: &str) -> Scalar {
	let bytes = decode_hex(hex_str);
	let mut result: [u8; 32] = [0; 32];
	result.copy_from_slice(&bytes);
	Scalar::from_bytes_mod_order(result)
}
