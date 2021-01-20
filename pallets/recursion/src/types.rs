use ark_std::io::{Result as IoResult, Write};
use sp_std::prelude::*;
use ark_ff::{PrimeField, ToBytes, BigInteger};

use codec::{Decode, Encode, EncodeLike, Input};

#[derive(Eq, PartialEq, Clone, Default, Debug, Copy)]
pub struct Element<PF: PrimeField>(pub PF);

pub const SIZE: usize = 32;

impl<PF: PrimeField> ToBytes for Element<PF> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.0.write(&mut writer)?;
        Ok(())
    }
}


impl<PF: PrimeField> Encode for Element<PF> {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		(self.0).into_repr().to_bytes_le().using_encoded(f)
	}
}

impl<PF: PrimeField> EncodeLike for Element<PF> {}

impl<PF: PrimeField> Decode for Element<PF> {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		match <[u8; SIZE] as Decode>::decode(input) {
			Ok(elt) => Ok(Element(
				PF::from_le_bytes_mod_order(&elt),
			)),
			Err(e) => Err(e),
		}
	}
}
