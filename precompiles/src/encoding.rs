use sp_std::prelude::Vec;

pub trait Decode: Sized {
	/// Attempt to deserialise the value from input.
	fn decode(from: &mut Vec<u8>) -> Result<Self, String>;
}

impl Decode for [u8; 32] {
	fn decode(from: &mut Vec<u8>) -> Result<Self, String> {
		let size = 32;
		if size > from.len() {
			return Err("Not enough bytes to fill the buffer".into());
		}
		let mut into = [0u8; 32];
		into.copy_from_slice(&from[..size]);
		from.drain(..size);
		Ok(into)
	}
}

impl Decode for Vec<u8> {
	fn decode(from: &mut Vec<u8>) -> Result<Self, String> {
		let mut into = Vec::new();
		let len = from.len();
		into.extend(&from[..len]);
		from.clear();
		Ok(into)
	}
}

impl Decode for u8 {
	fn decode(from: &mut Vec<u8>) -> Result<Self, String> {
		if from.len() == 0 {
			return Err("Not enough bytes to fill the buffer".into());
		}
		let item = from[0];
		from.drain(..1);
		Ok(item)
	}
}

pub trait Encode: Sized {
	fn size_hint(&self) -> usize;
	fn encode(&self) -> Vec<u8>;
}

#[cfg(test)]
mod test {
	use super::*;
	#[test]
	fn should_decode() {
		let mut value = vec![0u8; 42];
		let decoded = <[u8; 32] as Decode>::decode(&mut value).unwrap();
		assert_eq!(value.len(), 10);
		assert_eq!(decoded.len(), 32);
	}
}
