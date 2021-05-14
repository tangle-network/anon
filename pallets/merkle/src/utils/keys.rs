//! Type definitions used in merkle pallet

pub type ScalarBytes = Vec<u8>;

pub fn slice_to_bytes_32(vec: &[u8]) -> [u8; 32] {
	let mut bytes_array = [0u8; 32];
	bytes_array.iter_mut().enumerate().for_each(|(i, x)| *x = vec[i]);
	bytes_array
}
