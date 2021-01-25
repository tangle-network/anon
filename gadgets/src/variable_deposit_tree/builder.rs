use crate::{
	poseidon::{builder::Poseidon, gen_mds_matrix, gen_round_keys, sbox::PoseidonSbox, PoseidonBuilder},
	smt::{
		builder::{SparseMerkleTreeBuilder, DEFAULT_TREE_DEPTH},
		smt::VanillaSparseMerkleTree,
	},
};

#[derive(Clone)]
pub struct VariableDepositTree {
	depth: usize,
	hash_params: Poseidon,
	tree: VanillaSparseMerkleTree,
}

pub struct VariableDepositTreeBuilder {
	depth: Option<usize>,
	hash_params: Option<Poseidon>,
	tree: Option<VanillaSparseMerkleTree>,
}

impl VariableDepositTreeBuilder {
	pub fn new() -> Self {
		Self {
			depth: None,
			hash_params: None,
			tree: None,
		}
	}

	pub fn depth(&mut self, depth: usize) -> &mut Self {
		self.depth = Some(depth);
		self
	}

	pub fn hash_params(&mut self, hash_params: Poseidon) -> &mut Self {
		self.hash_params = Some(hash_params);
		self
	}

	pub fn merkle_tree(&mut self, tree: VanillaSparseMerkleTree) -> &mut Self {
		self.tree = Some(tree);
		self
	}

	pub fn build(&self) -> VariableDepositTree {
		let depth = self.depth.unwrap_or_else(|| DEFAULT_TREE_DEPTH);
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

		let tree = self
			.tree
			.clone()
			.unwrap_or_else(|| SparseMerkleTreeBuilder::new().depth(depth).build());

		VariableDepositTree {
			depth,
			hash_params,
			tree,
		}
	}
}
