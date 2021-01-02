use crate::poseidon::gen_mds_matrix;
use crate::poseidon::gen_round_keys;
use crate::poseidon::PoseidonBuilder;
use crate::poseidon::sbox::PoseidonSbox;
use crate::poseidon::builder::Poseidon;

#[derive(Clone)]
pub struct TransactionGadget {
	hash_params: Poseidon,
}

pub struct TransactionGadgetBuilder {
	hash_params: Option<Poseidon>,
}

impl TransactionGadgetBuilder {
	pub fn new() -> Self {
		Self {
			hash_params: None,
		}
	}

	pub fn hash_params(&mut self, hash_params: Poseidon) -> &mut Self {
		self.hash_params = Some(hash_params);
		self
	}

	pub fn build(&self) -> TransactionGadget {
		let hash_params = self.hash_params.clone().unwrap_or_else(|| {
			let width = 6;
			let (full_b, full_e) = (4, 4);
			let partial_rounds = 57;
			PoseidonBuilder::new(width)
				.num_rounds(full_b, full_e, partial_rounds)
				.round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
				.mds_matrix(gen_mds_matrix(width))
				.sbox(PoseidonSbox::Inverse)
				.build()
		});

		TransactionGadget {
			hash_params,
		}
	}
}
