use crate::smt::smt::VanillaSparseMerkleTree;
use crate::poseidon::gen_mds_matrix;
use crate::poseidon::gen_round_keys;
use crate::poseidon::PoseidonBuilder;
use crate::poseidon::sbox::PoseidonSbox;
use crate::poseidon::builder::Poseidon;

#[derive(Clone)]
pub struct FixedDepositTree {
	hash_params: Poseidon,
	tree: VanillaSparseMerkleTree,
}

pub struct FixedDepositTreeBuilder {
	hash_params: Option<Poseidon>,
	tree: Option<VanillaSparseMerkleTree>,
}

impl FixedDepositTreeBuilder {
	pub fn new() -> Self {
		Self {
			hash_params: None,
			tree: None,
		}
	}

	pub fn hash_params(&mut self, hash_params: Poseidon) -> &mut Self {
		self.hash_params = Some(hash_params);
		self
	}

	pub fn merkle_tree(&mut self, tree: VanillaSparseMerkleTree) -> &mut Self {
		self.tree = Some(tree);
		self
	}

	pub fn build(&self) -> FixedDepositTree {
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

		let tree = self.tree.clone().unwrap_or_else(|| {
			VanillaSparseMerkleTree::new(hash_params.clone())
		});

		FixedDepositTree {
			hash_params,
			tree,
		}
	}
}
