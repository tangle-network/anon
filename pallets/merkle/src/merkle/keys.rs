use sha2::Sha512;
use sp_std::prelude::*;

use super::mimc::{mimc, mimc_constraints};
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination};
use codec::{Decode, Encode, EncodeLike, Input};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

#[derive(Eq, PartialEq, Clone, Default, Debug, Copy)]
pub struct PublicKey(pub CompressedRistretto);
#[derive(Eq, PartialEq, Clone, Default, Debug, Copy)]
pub struct PrivateKey(pub Scalar);

pub const SIZE: usize = 32;

impl Encode for PublicKey {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		(self.0).0.using_encoded(f)
	}
}

impl EncodeLike for PublicKey {}

impl Decode for PublicKey {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		match <[u8; SIZE] as Decode>::decode(input).map(CompressedRistretto) {
			Ok(elt) => Ok(PublicKey(elt)),
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
			Ok(elt) => Ok(PrivateKey(
				Scalar::from_canonical_bytes(elt).unwrap_or(Scalar::zero()),
			)),
			Err(e) => Err(e),
		}
	}
}

impl PublicKey {
	/// Constructor from bytes
	pub fn new(bytes: &[u8]) -> Self {
		let point: RistrettoPoint = RistrettoPoint::hash_from_bytes::<Sha512>(bytes);
		PublicKey(point.compress())
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
	pub fn from_bytes(bytes: &[u8]) -> Option<PublicKey> {
		if bytes.len() != 32 {
			return None;
		}
		let mut arr = [0u8; 32];
		arr.copy_from_slice(bytes);
		let c = CompressedRistretto(arr);
		Some(PublicKey(c))
	}

	pub fn from_ristretto(pt: RistrettoPoint) -> Self {
		PublicKey(pt.compress())
	}

	pub fn hash_points(a: Self, b: Self) -> Self {
		Self::new(&[&a.0.to_bytes()[..], &b.0.to_bytes()[..]].concat()[..])
	}

	pub fn hash_points_mimc(xl: Self, xr: Self) -> Self {
		// not sure if we could convert RistrettoPoint to a Scalar this way
		let xl_scalar = Scalar::from_bytes_mod_order(xl.0.to_bytes());
		let xr_scalar = Scalar::from_bytes_mod_order(xr.0.to_bytes());
		let res = mimc(xl_scalar, xr_scalar);
		PublicKey(CompressedRistretto::from_slice(res.as_bytes()))
	}

	pub fn constrain_points_mimc<CS: ConstraintSystem>(
		cs: &mut CS,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination {
		mimc_constraints(cs, xl, xr)
	}
}
