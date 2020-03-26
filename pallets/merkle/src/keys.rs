use crate::constants::BASEPOINT;
use sha2::Sha512;
use sp_std::prelude::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use codec::{Encode, Decode, Input, EncodeLike};
use curve25519_dalek::ristretto::{
	CompressedRistretto,
	// RistrettoPoint
};
use curve25519_dalek::scalar::Scalar;


#[derive(Eq, PartialEq, Clone, Default, Debug)]
pub struct PublicKey(pub CompressedRistretto);
#[derive(Eq, PartialEq, Clone, Default, Debug)]
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
            Ok(elt) => Ok(PrivateKey(Scalar::from_canonical_bytes(elt).unwrap_or(Scalar::zero()))),
            Err(e) => Err(e),
        }
    }
}

impl PublicKey {
	/// Constructor from bytes
	pub fn new(bytes: [u8; 32]) -> Self {
		PublicKey(CompressedRistretto(bytes))
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
}
