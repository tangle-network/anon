//! Type definitions used in merkle pallet

use sha2::Sha512;
use sp_std::prelude::*;

use codec::{Decode, Encode, EncodeLike, Input};
use curve25519_dalek::{
	ristretto::{CompressedRistretto, RistrettoPoint},
	scalar::Scalar,
};
use bulletproofs::{
	BulletproofGens
};
use sp_std::vec::Vec;

#[derive(Eq, PartialEq, Clone, Default, Debug, Copy)]
pub struct Commitment(pub CompressedRistretto);
#[derive(Eq, PartialEq, Clone, Default, Debug, Copy)]
pub struct PrivateKey(pub Scalar);
#[derive(Eq, PartialEq, Clone, Default, Debug, Copy, Hash)]
pub struct ScalarData(pub Scalar);

pub const SIZE: usize = 32;

impl Encode for Commitment {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		(self.0).0.using_encoded(f)
	}
}

impl EncodeLike for Commitment {}

impl Decode for Commitment {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		match <[u8; SIZE] as Decode>::decode(input).map(CompressedRistretto) {
			Ok(elt) => Ok(Commitment(elt)),
			Err(e) => Err(e),
		}
	}
}

impl Encode for PrivateKey {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		(self.0).as_bytes().using_encoded(f)
	}
}

impl EncodeLike for PrivateKey {}

impl Decode for PrivateKey {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		match <[u8; SIZE] as Decode>::decode(input) {
			Ok(elt) => Ok(PrivateKey(Scalar::from_canonical_bytes(elt).unwrap_or(Scalar::zero()))),
			Err(e) => Err(e),
		}
	}
}

impl Commitment {
	/// Constructor from bytes
	pub fn new(bytes: &[u8]) -> Self {
		let point: RistrettoPoint = RistrettoPoint::hash_from_bytes::<Sha512>(bytes);
		Commitment(point.compress())
	}

	/// Serialize this public key to 32 bytes
	pub fn as_bytes(&self) -> Vec<u8> {
		(&self.0.as_bytes()).to_vec()
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		self.as_bytes()
	}

	pub fn to_exact_bytes(&self) -> [u8; 32] {
		(self.0).0
	}

	// TODO: Make this more robust
	/// Deserialize this public key from 32 bytes
	pub fn from_bytes(bytes: &[u8]) -> Option<Commitment> {
		if bytes.len() != 32 {
			return None;
		}
		let mut arr = [0u8; 32];
		arr.copy_from_slice(bytes);
		let c = CompressedRistretto(arr);
		Some(Commitment(c))
	}

	pub fn from_ristretto(pt: RistrettoPoint) -> Self {
		Commitment(pt.compress())
	}

	pub fn hash_points(a: Self, b: Self) -> Self {
		Self::new(&[&a.0.to_bytes()[..], &b.0.to_bytes()[..]].concat()[..])
	}
}

impl Encode for ScalarData {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		(self.0).as_bytes().using_encoded(f)
	}
}

impl EncodeLike for ScalarData {}

impl Decode for ScalarData {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		match <[u8; SIZE] as Decode>::decode(input) {
			Ok(elt) => Ok(ScalarData(Scalar::from_canonical_bytes(elt).unwrap_or(Scalar::zero()))),
			Err(e) => Err(e),
		}
	}
}

impl ScalarData {
	pub fn from(b: [u8; 32]) -> Self {
		ScalarData(Scalar::from_bytes_mod_order(b))
	}

	pub fn from_slice(b: &[u8]) -> Self {
		let mut buf: [u8; 32] = [0u8; 32];
		let length = if b.len() < 32 { b.len() } else { 32 };
		for i in 0..length {
			buf[i] = b[i]
		}
		Self::from(buf)
	}

	pub fn zero() -> Self {
		ScalarData(Scalar::zero())
	}

	pub fn to_scalar(&self) -> Scalar {
		self.0
	}
}

pub enum VerifyingKeyData {
	Poseidon(PoseidonVerifyingKey),
}

pub struct PoseidonVerifyingKey {
	bp_gens: BulletproofGens,
}

// pub struct BulletproofGens {
// 	/// The maximum number of usable generators for each party.
// 	pub gens_capacity: usize,
// 	/// Number of values or parties
// 	pub party_capacity: usize,
// 	/// Precomputed \\(\mathbf G\\) generators for each party.
// 	G_vec: Vec<Vec<RistrettoPoint>>,
// 	/// Precomputed \\(\mathbf H\\) generators for each party.
// 	H_vec: Vec<Vec<RistrettoPoint>>,
// }

impl Encode for PoseidonVerifyingKey {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		let g_vec_bytes = self.bp_gens.G_vec.iter().map(|vec| {
			vec.iter().map(|pt| pt.compress().as_bytes()).fold(vec![], |acc, curr| {
				// inside inner len (except this should always be 32 bytes so we can drop the length)
				// NOT_NEEDED - acc.append(&mut curr.to_vec().len().to_be_bytes().to_vec());
				// inside inner data
				acc.append(&mut curr.to_vec());
				acc
			})
		}).fold(vec![], |acc, curr| {
			// inner len
			acc.append(&mut curr.to_vec().len().to_be_bytes().to_vec());
			// inner data
			acc.append(&mut curr);
			acc
		});

		let h_vec_bytes = self.bp_gens.H_vec.iter().map(|vec| {
			vec.iter().map(|pt| pt.compress().as_bytes()).fold(vec![], |acc, curr| {
				// inside inner len (except this should always be 32 bytes so we can drop the length)
				// NOT_NEEDED - acc.append(&mut curr.to_vec().len().to_be_bytes().to_vec());
				// inside inner data
				acc.append(&mut curr.to_vec());
				acc
			})
		}).fold(vec![], |acc, curr| {
			// inner len
			acc.append(&mut curr.to_vec().len().to_be_bytes().to_vec());
			// inner data
			acc.append(&mut curr);
			acc
		});

		let bytes = vec![];
		// bytes.extend_from_slice(&transform_u32_to_array_of_u8(self.bp_gens.gens_capacity as u32));
		bytes.extend_from_slice(&self.bp_gens.gens_capacity.to_be_bytes());
		bytes.extend_from_slice(&self.bp_gens.party_capacity.to_be_bytes());
		bytes.extend_from_slice(&(g_vec_bytes.len() as u32).to_be_bytes());
		bytes.extend_from_slice(&g_vec_bytes);
		bytes.extend_from_slice(&(h_vec_bytes.len() as u32).to_be_bytes());
		bytes.extend_from_slice(&h_vec_bytes);
		bytes.using_encoded(f)
	}
}

impl Decode for PoseidonVerifyingKey {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		let mut gens_capacity_bytes = [0u8; 4];
		input.read(&mut gens_capacity_bytes);
		let gens_capacity: usize = u32::from_be_bytes(gens_capacity_bytes) as usize;

		let mut party_capacity_bytes = [0u8; 4];
		input.read(&mut party_capacity_bytes);
		let party_capacity: usize = u32::from_be_bytes(party_capacity_bytes) as usize;

		let mut g_vec_len_bytes = [0u8; 4];
		input.read(&mut g_vec_len_bytes);
		let g_vec_len: usize = u32::from_be_bytes(g_vec_len_bytes) as usize;

		let g_vec = Vec::with_capacity(g_vec_len);
		input.read(&mut g_vec);
		let mut g_slice = g_vec.as_slice();
		let vec_of_vecs_g = vec![];
		while g_slice.len() > 0 {
			let inner_vec_len = [0u8; 4];
			g_slice.read(&mut inner_vec_len);
			let inner_vec_len_u32 = u32::from_be_bytes(inner_vec_len);
			let inner_vec = Vec::with_capacity(g_vec_len);
			g_slice.read(&mut inner_vec);
			let mut inner_g_slice = inner_vec.as_slice();
			let vec_of_points = vec![];
			while inner_g_slice.len() > 0 {
				let mut inside_inner_g_slice = [0u8; 32];
				inner_g_slice.read(&mut inside_inner_g_slice);
				vec_of_points.push(CompressedRistretto(inside_inner_g_slice).decompress().unwrap());
			}
			vec_of_vecs_g.push(vec_of_points);
		}


		let mut h_vec_len_bytes = [0u8; 4];
		input.read(&mut g_vec_len_bytes);
		let h_vec_len: usize = u32::from_be_bytes(g_vec_len_bytes) as usize;

		let h_vec = Vec::with_capacity(h_vec_len);
		input.read(&mut h_vec);
		let mut h_slice = h_vec.as_slice();
		let vec_of_vecs_h = vec![];
		while h_slice.len() > 0 {
			let inner_vec_len = [0u8; 4];
			h_slice.read(&mut inner_vec_len);
			let inner_vec_len_u32 = u32::from_be_bytes(inner_vec_len);
			let inner_vec = Vec::with_capacity(h_vec_len);
			h_slice.read(&mut inner_vec);
			let mut inner_h_slice = inner_vec.as_slice();
			let vec_of_points = vec![];
			while inner_h_slice.len() > 0 {
				let mut inside_inner_h_slice = [0u8; 32];
				inner_h_slice.read(&mut inside_inner_h_slice);
				vec_of_points.push(CompressedRistretto(inside_inner_h_slice).decompress().unwrap());
			}
			vec_of_vecs_h.push(vec_of_points);
		}
		
		Ok(PoseidonVerifyingKey {
			bp_gens: BulletproofGens {
				gens_capacity,
				party_capacity, 
				G_vec: vec_of_vecs_g,
				H_vec: vec_of_vecs_h,
			}
		})
	}
}
