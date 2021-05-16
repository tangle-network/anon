//! Type definitions used in merkle pallet
use sp_std::prelude::*;

pub type ScalarBytes = Vec<u8>;

pub fn slice_to_bytes_32(vec: &[u8]) -> [u8; 32] {
	let mut bytes_array = [0u8; 32];
	bytes_array
		.iter_mut()
		.enumerate()
		.for_each(|(i, x)| *x = *vec.get(i).unwrap_or(&0u8));
	bytes_array
}
