use alloc::vec::Vec;
use bulletproofs::r1cs::LinearCombination;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable};
use core::fmt;
use curve25519_dalek::scalar::Scalar;

pub type ScalarBytes = [u8; 32];

/// Represents a variable for quantity, along with its assignment.
#[derive(Copy, Clone, Debug)]
pub struct AllocatedQuantity {
	pub variable: Variable,
	pub assignment: Option<u64>,
}

#[derive(Copy, Clone, Debug)]
pub struct AllocatedScalar {
	pub variable: Variable,
	pub assignment: Option<Scalar>,
}

pub fn decode_hex(s: &str) -> Vec<u8> {
	let s = &s[2..];
	let vec: Vec<u8> = (0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
		.collect();

	vec
}

pub fn get_bits(scalar: &Scalar, process_bits: usize) -> Vec<u8> {
	let mut bits = vec![0u8; process_bits];
	let bytes = scalar.as_bytes();
	for i in 0..process_bits {
		// As i runs from 0..256, the bottom 3 bits index the bit,
		// while the upper bits index the byte.
		bits[i] = ((bytes[i >> 3] >> (i & 7)) & 1u8) as u8;
	}
	bits
}

pub fn get_scalar_from_hex(hex_str: &str) -> Scalar {
	let bytes = decode_hex(hex_str);
	let mut result: [u8; 32] = [0; 32];
	result.copy_from_slice(&bytes);
	Scalar::from_bytes_mod_order(result)
}

/// Enforces that the quantity of v is in the range [0, 2^n).
pub fn positive_no_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	v: AllocatedQuantity,
	bit_size: usize,
) -> Result<(), R1CSError> {
	let mut constraint_v = vec![(v.variable, -Scalar::one())];
	let mut exp_2 = Scalar::one();
	for i in 0..bit_size {
		// Create low-level variables and add them to constraints

		let (a, b, o) = cs.allocate_multiplier(v.assignment.map(|q| {
			let bit: u64 = (q >> i) & 1;
			((1 - bit).into(), bit.into())
		}))?;

		// Enforce a * b = 0, so one of (a,b) is zero
		cs.constrain(o.into());

		// Enforce that a = 1 - b, so they both are 1 or 0.
		cs.constrain(a + (b - 1u64));

		constraint_v.push((b, exp_2));
		exp_2 = exp_2 + exp_2;
	}

	// Enforce that -v + Sum(b_i * 2^i, i = 0..n-1) = 0 => Sum(b_i * 2^i, i = 0..n-1) = v
	cs.constrain(constraint_v.iter().collect());

	Ok(())
}

/// Constrain a linear combination to be equal to a scalar
pub fn constrain_lc_with_scalar<CS: ConstraintSystem>(
	cs: &mut CS,
	lc: LinearCombination,
	scalar: &Scalar,
) {
	cs.constrain(lc - LinearCombination::from(*scalar));
}

/// Get a bit array of this scalar, LSB is first element of this array
#[derive(Clone)]
pub struct ScalarBits {
	pub bit_array: Vec<u8>,
}

impl fmt::Debug for ScalarBits {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:?}", self.bit_array)
	}
}

impl ScalarBits {
	pub fn from_scalar(scalar: &Scalar, process_bits: usize) -> Self {
		let s = scalar.reduce();
		Self {
			bit_array: get_bits(&s, process_bits),
		}
	}

	pub fn to_scalar(&self) -> Scalar {
		self.to_non_reduced_scalar().reduce()
	}

	pub fn to_non_reduced_scalar(&self) -> Scalar {
		let mut bytes: [u8; 32] = [0; 32];
		let powers_of_2: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
		let mut i = 0;
		let mut current_byte = 0u8;
		for b in self.bit_array.iter() {
			if *b == 1 {
				current_byte += powers_of_2[i % 8];
			}
			i += 1;
			if (i % 8) == 0 {
				bytes[(i / 8) - 1] = current_byte;
				current_byte = 0;
			}
		}
		bytes[31] = current_byte;
		Scalar::from_bits(bytes)
	}

	/// Shift left by 1 bit
	pub fn shl(&mut self) {
		for i in (1..self.bit_array.len()).rev() {
			self.bit_array[i] = self.bit_array[i - 1];
		}
		self.bit_array[0] = 0;
	}

	/// Shift right by 1 bit
	pub fn shr(&mut self) {
		let size = self.bit_array.len();
		for i in 1..size {
			self.bit_array[i - 1] = self.bit_array[i];
		}
		self.bit_array[size - 1] = 0;
	}

	/// Return a new bit-array shifted to the left with 1 bit
	pub fn new_left_shifted(&self) -> Self {
		// Not using the above method `shl` to avoid copying
		let size = self.bit_array.len();
		let mut new_array = vec![0; size];
		for i in (1..size).rev() {
			new_array[i] = self.bit_array[i - 1];
		}
		new_array[0] = 0;
		Self {
			bit_array: new_array,
		}
	}

	/// Return a new bit-array shifted to the right with 1 bit
	pub fn new_right_shifted(&self) -> Self {
		// Not using the above method `shr` to avoid copying
		let size = self.bit_array.len();
		let mut new_array = vec![0; size];
		for i in 1..size {
			new_array[i - 1] = self.bit_array[i];
		}
		new_array[size - 1] = 0;
		Self {
			bit_array: new_array,
		}
	}

	/// Check if most significant bit is set
	pub fn is_msb_set(&self) -> bool {
		self.bit_array[self.bit_array.len() - 1] == 1
	}

	/// Check if least significant bit is set
	pub fn is_lsb_set(&self) -> bool {
		self.bit_array[0] == 1
	}
}
