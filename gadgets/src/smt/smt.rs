use crate::{
	poseidon::{
		allocate_statics_for_prover, builder::Poseidon, PoseidonSbox, Poseidon_hash_2, Poseidon_hash_2_constraints,
	},
	utils::{constrain_lc_with_scalar, get_bits, AllocatedScalar, ScalarBits, ScalarBytes},
};
use alloc::vec::Vec;
use bulletproofs::{
	r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Variable},
	BulletproofGens,
};
use crypto_constants::smt::ZERO_TREE;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use rand_core::OsRng;
use sp_std::collections::btree_map::BTreeMap;

pub type DBVal = (Scalar, Scalar);

// TODO: ABSTRACT HASH FUNCTION BETTER
#[derive(Clone)]
pub struct VanillaSparseMerkleTree {
	pub depth: usize,
	db: BTreeMap<ScalarBytes, DBVal>,
	hash_params: Poseidon,
	pub root: Scalar,
	curr_index: Scalar,
	edge_nodes: Vec<Scalar>,
	pub(crate) leaf_indices: BTreeMap<ScalarBytes, Scalar>,
}

impl VanillaSparseMerkleTree {
	pub fn new(hash_params: Poseidon, depth: usize) -> VanillaSparseMerkleTree {
		let root = Scalar::from_bytes_mod_order(ZERO_TREE[depth].clone());

		let mut edge_nodes = vec![Scalar::from_bytes_mod_order(ZERO_TREE[0].clone())];
		let mut db = BTreeMap::new();
		for i in 1..=depth {
			let prev = Scalar::from_bytes_mod_order(ZERO_TREE[i - 1]);
			// Ensure using PoseidonSbox::Inverse
			let new = Poseidon_hash_2(prev.clone(), prev.clone(), &hash_params);
			edge_nodes.push(new);
			let key = new.to_bytes();

			db.insert(key, (prev, prev));
		}

		VanillaSparseMerkleTree {
			depth,
			db,
			hash_params,
			root,
			curr_index: Scalar::zero(),
			edge_nodes,
			leaf_indices: BTreeMap::new(),
		}
	}

	// Should not be used along with `update`
	// This function allows this tree to work as a normal tree
	// Should be deleted in the future if we opt out to use sparse tree
	// that support non-membership proofs
	pub fn add_leaves(&mut self, vals: Vec<[u8; 32]>, target_root: Option<[u8; 32]>) {
		for val in vals {
			// check if current root equals target root before inserting
			// more leaves. This is necessary to prevent inconsistencies
			// between building a tree with more leaves than is being targeted.
			if let Some(root) = target_root {
				if self.root.to_bytes() == root {
					break;
				}
			}
			self.update(self.curr_index, Scalar::from_bytes_mod_order(val));
			self.leaf_indices.insert(val, self.curr_index);
			self.curr_index = self.curr_index + Scalar::one();
		}
	}

	pub fn update(&mut self, idx: Scalar, val: Scalar) -> Scalar {
		// Find path to insert the new key
		let mut cur_idx = ScalarBits::from_scalar(&idx, self.depth);
		let mut cur_val = val.clone();
		let mut sidenodes_wrap = Some(Vec::<Scalar>::new());
		self.get(idx, self.root, &mut sidenodes_wrap);
		let path = sidenodes_wrap.unwrap();

		for i in 0..self.depth {
			let side_elem = path[i];
			let (l, r) = if cur_idx.is_lsb_set() {
				// LSB is set, so put new value on right
				(side_elem, cur_val)
			} else {
				// LSB is unset, so put new value on left
				(cur_val, side_elem)
			};
			let h = Poseidon_hash_2(l, r, &self.hash_params);
			self.update_db_with_key_val(h, (l, r));
			cur_idx.shr();
			cur_val = h;
		}

		self.root = cur_val;
		self.leaf_indices.insert(val.to_bytes(), idx);
		cur_val
	}

	/// Get a value from tree, if `proof` is not None, populate `proof` with the
	/// merkle proof
	pub fn get(&self, idx: Scalar, root: Scalar, proof: &mut Option<Vec<Scalar>>) -> Scalar {
		let mut cur_idx = ScalarBits::from_scalar(&idx, self.depth);
		let mut cur_node = root.clone();

		let need_proof = proof.is_some();
		let mut proof_vec = Vec::<Scalar>::new();

		for _i in 0..self.depth {
			let k = cur_node.to_bytes();
			let v = self.db.get(&k).unwrap();
			if cur_idx.is_msb_set() {
				// MSB is set, traverse to right subtree
				cur_node = v.1;
				if need_proof {
					proof_vec.push(v.0);
				}
			} else {
				// MSB is unset, traverse to left subtree
				cur_node = v.0;
				if need_proof {
					proof_vec.push(v.1);
				}
			}
			cur_idx.shl();
		}
		proof_vec.reverse();
		match proof {
			Some(v) => {
				v.extend_from_slice(&proof_vec);
			}
			None => (),
		}

		cur_node
	}

	/// Verify a merkle proof, if `root` is None, use the current root else use
	/// given root
	pub fn verify_proof(&self, idx: Scalar, val: Scalar, proof: &[Scalar], root: Option<&Scalar>) -> bool {
		let mut cur_idx = ScalarBits::from_scalar(&idx, self.depth);
		let mut cur_val = val.clone();

		for i in 0..self.depth {
			cur_val = {
				if cur_idx.is_lsb_set() {
					Poseidon_hash_2(proof[i].clone(), cur_val.clone(), &self.hash_params)
				} else {
					Poseidon_hash_2(cur_val.clone(), proof[i].clone(), &self.hash_params)
				}
			};

			cur_idx.shr();
		}

		// Check if root is equal to cur_val
		match root {
			Some(r) => cur_val == *r,
			None => cur_val == self.root,
		}
	}

	pub fn prove_zk(
		&self,
		root: Scalar,
		leaf: Scalar,
		bp_gens: &BulletproofGens,
		mut prover: Prover,
	) -> (
		R1CSProof,
		(CompressedRistretto, Vec<CompressedRistretto>, Vec<CompressedRistretto>),
	) {
		let mut test_rng: OsRng = OsRng::default();
		let mut merkle_proof_vec = Vec::<Scalar>::new();
		let mut merkle_proof = Some(merkle_proof_vec);
		let k = self.leaf_indices.get(&leaf.to_bytes()).unwrap();
		let leaf = self.get(*k, root, &mut merkle_proof);
		merkle_proof_vec = merkle_proof.unwrap();

		let (com_leaf, var_leaf) = prover.commit(leaf, Scalar::random(&mut test_rng));
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: Some(*k),
		};

		let mut leaf_index_comms = vec![];
		let mut leaf_index_alloc_scalars = vec![];
		for b in get_bits(&k, self.depth).iter().take(self.depth) {
			let val: Scalar = Scalar::from(*b as u8);
			let (c, v) = prover.commit(val.clone(), Scalar::random(&mut test_rng));
			leaf_index_comms.push(c);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(val),
			});
		}

		let mut proof_comms = vec![];
		let mut proof_alloc_scalars = vec![];
		for p in merkle_proof_vec.iter() {
			let (c, v) = prover.commit(*p, Scalar::random(&mut test_rng));
			proof_comms.push(c);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(*p),
			});
		}

		let num_statics = 4;
		let statics = allocate_statics_for_prover(&mut prover, num_statics);

		assert!(vanilla_merkle_merkle_tree_verif_gadget(
			&mut prover,
			self.depth,
			&self.root,
			leaf_alloc_scalar,
			leaf_index_alloc_scalars,
			proof_alloc_scalars,
			statics,
			&self.hash_params
		)
		.is_ok());

		let proof = prover.prove_with_rng(bp_gens, &mut test_rng).unwrap();
		(proof, (com_leaf, leaf_index_comms, proof_comms))
	}

	fn update_db_with_key_val(&mut self, key: Scalar, val: DBVal) {
		self.db.insert(key.to_bytes(), val);
	}
}

/// left = (1-leaf_side) * leaf + (leaf_side * proof_node)
/// right = leaf_side * leaf + ((1-leaf_side) * proof_node))
pub fn vanilla_merkle_merkle_tree_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	depth: usize,
	root: &Scalar,
	leaf_val: AllocatedScalar,
	leaf_index_bits: Vec<AllocatedScalar>,
	proof_nodes: Vec<AllocatedScalar>,
	statics: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	let mut prev_hash = LinearCombination::default();

	let statics: Vec<LinearCombination> = statics.iter().map(|s| s.variable.into()).collect();

	for i in 0..depth {
		let leaf_val_lc = if i == 0 {
			LinearCombination::from(leaf_val.variable)
		} else {
			prev_hash.clone()
		};
		let one_minus_leaf_side: LinearCombination = Variable::One() - leaf_index_bits[i].variable;

		let (_, _, left_1) = cs.multiply(one_minus_leaf_side.clone(), leaf_val_lc.clone());
		let (_, _, left_2) = cs.multiply(leaf_index_bits[i].variable.into(), proof_nodes[i].variable.into());
		let left = left_1 + left_2;

		let (_, _, right_1) = cs.multiply(leaf_index_bits[i].variable.into(), leaf_val_lc);
		let (_, _, right_2) = cs.multiply(one_minus_leaf_side, proof_nodes[i].variable.into());
		let right = right_1 + right_2;

		assert!(poseidon_params.sbox == PoseidonSbox::Inverse, "Assert sbox is inverse");
		prev_hash = Poseidon_hash_2_constraints::<CS>(cs, left, right, statics.clone(), poseidon_params)?;
	}

	constrain_lc_with_scalar::<CS>(cs, prev_hash, root);

	Ok(())
}
