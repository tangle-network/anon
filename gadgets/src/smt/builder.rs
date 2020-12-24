
use crate::poseidon::Poseidon_hash_2;
use crate::poseidon::gen_mds_matrix;
use crate::poseidon::gen_round_keys;
use crate::poseidon::PoseidonBuilder;
use crate::poseidon::sbox::PoseidonSbox;
use sp_std::collections::btree_map::BTreeMap;

use crate::smt::smt::DBVal;

use crate::poseidon::builder::Poseidon;

use curve25519_dalek::scalar::Scalar;

use crate::utils::ScalarBytes;

pub const DEFAULT_TREE_DEPTH: usize = 30;

#[derive(Clone)]
pub struct SparseMerkleTree {
	/// The depth of the tree
	pub depth: usize,
	/// The values of empty hashes hashed with themselves, computed on init
	empty_tree_hashes: Vec<Scalar>,
	/// The DB of leaves
	db: BTreeMap<ScalarBytes, DBVal>,
	/// The hash params, defaults to Poseidon
	/// TODO: Add abstract hasher
	hash_params: Poseidon,
	/// The merkle root of the tree
	pub root: Scalar,
}

pub struct SparseMerkleTreeBuilder {
	/// The depth of the tree
	pub depth: Option<usize>,
	/// The values of empty hashes hashed with themselves, computed on init
	empty_tree_hashes: Option<Vec<Scalar>>,
	/// The DB of leaves
	db: Option<BTreeMap<ScalarBytes, DBVal>>,
	/// The hash params, defaults to Poseidon
	/// TODO: Add abstract hasher
	hash_params: Option<Poseidon>,
	/// The merkle root of the tree
	pub root: Option<Scalar>,
}

impl SparseMerkleTreeBuilder {
	pub fn new() -> Self {
		Self {
			depth: None,
			empty_tree_hashes: None,
			db: None,
			hash_params: None,
			root: None,
		}
	}

	pub fn depth(&mut self, depth: usize) -> &mut Self {
		self.depth = Some(depth);
		self
	}

	pub fn empty_tree_hashes(&mut self, hashes: Vec<Scalar>) -> &mut Self {
		self.empty_tree_hashes = Some(hashes);
		self
	}

	pub fn db(&mut self, db: BTreeMap<ScalarBytes, DBVal>) -> &mut Self {
		self.db = Some(db);
		self
	}

	pub fn hash_params(&mut self, hash_params: Poseidon) -> &mut Self {
		self.hash_params = Some(hash_params);
		self
	}

	pub fn root(&mut self, root: Scalar) -> &mut Self {
		self.root = Some(root);
		self
	}

	pub fn build(&self) -> SparseMerkleTree {
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
		// if either db or empty tree hashes are empty, then we regenerate
		let (db, empty_tree_hashes) = if self.db.is_none() || self.empty_tree_hashes.is_none() {
			let mut database: BTreeMap<ScalarBytes, DBVal> = BTreeMap::new();
			let mut empty_hashes: Vec<Scalar> = Vec::with_capacity(depth);
			for i in 1..=depth {
				let prev = empty_hashes[i-1];
				// Ensure using PoseidonSbox::Inverse
				let new = Poseidon_hash_2(prev.clone(), prev.clone(), &hash_params);
				let key = new.to_bytes();

				database.insert(key, (prev, prev));
				empty_hashes[i] = new;
			}

			(database, empty_hashes)
		} else {
			(self.db.clone().unwrap(), self.empty_tree_hashes.clone().unwrap())
		};

		let root = empty_tree_hashes[depth].clone();

		SparseMerkleTree {
			depth,
			empty_tree_hashes,
			db,
			hash_params,
			root,
		}
	}
}