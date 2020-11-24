use sha2::Sha512;
use sp_std::prelude::*;

use super::mimc::{mimc, mimc_constraints};
use super::poseidon::{Poseidon, PADDING_CONST, ZERO_CONST};
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};
use codec::{Decode, Encode, EncodeLike, Input};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

#[derive(Eq, PartialEq, Clone, Default, Debug, Copy)]
pub struct Commitment(pub CompressedRistretto);
#[derive(Eq, PartialEq, Clone, Default, Debug, Copy)]
pub struct PrivateKey(pub Scalar);
#[derive(Eq, PartialEq, Clone, Default, Debug, Copy)]
pub struct Data(pub Scalar);

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
			Ok(elt) => Ok(PrivateKey(
				Scalar::from_canonical_bytes(elt).unwrap_or(Scalar::zero()),
			)),
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

impl Encode for Data {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		(self.0).as_bytes().using_encoded(f)
	}
}

impl EncodeLike for Data {}

impl Decode for Data {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		match <[u8; SIZE] as Decode>::decode(input) {
			Ok(elt) => Ok(Data(
				Scalar::from_canonical_bytes(elt).unwrap_or(Scalar::zero()),
			)),
			Err(e) => Err(e),
		}
	}
}

impl Data {
	pub fn new(b: [u8; 32]) -> Self {
		Data(Scalar::from_bytes_mod_order(b))
	}

	pub fn zero() -> Self {
		Data(Scalar::zero())
	}
	pub fn hash_mimc(xl: Self, xr: Self) -> Self {
		Data(mimc(xl.0, xr.0))
	}

	pub fn hash_poseidon(xl: Self, xr: Self, poseidon: &Poseidon) -> Self {
		Data(poseidon.hash_2(xl.0, xr.0))
	}

	pub fn constrain_poseidon_prover(
		prover: &mut Prover,
		xl: LinearCombination,
		xr: LinearCombination,
		poseidon: &Poseidon,
	) -> LinearCombination {
		let (_, var1) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
		let (_, var4) = prover.commit(Scalar::from(PADDING_CONST), Scalar::zero());
		let (_, var5) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
		let (_, var6) = prover.commit(Scalar::from(ZERO_CONST), Scalar::zero());
		let inputs = vec![var1.into(), xl, xr, var4.into(), var5.into(), var6.into()];
		poseidon.constrain(prover, inputs)
	}

	pub fn constrain_poseidon_verifier(
		verifier: &mut Verifier,
		com1: CompressedRistretto,
		xl: Variable,
		xr: Variable,
		com4: CompressedRistretto,
		com5: CompressedRistretto,
		com6: CompressedRistretto,
		poseidon: &Poseidon,
	) -> LinearCombination {
		let var1 = verifier.commit(com1);
		let var4 = verifier.commit(com4);
		let var5 = verifier.commit(com5);
		let var6 = verifier.commit(com6);
		let inputs = vec![
			var1.into(),
			xl.into(),
			xr.into(),
			var4.into(),
			var5.into(),
			var6.into(),
		];
		poseidon.constrain(verifier, inputs)
	}

	pub fn constrain_mimc<CS: ConstraintSystem>(
		cs: &mut CS,
		xl: LinearCombination,
		xr: LinearCombination,
	) -> LinearCombination {
		mimc_constraints(cs, xl, xr)
	}
}
