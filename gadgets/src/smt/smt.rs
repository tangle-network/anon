use sp_std::collections::btree_map::BTreeMap;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable};


use bulletproofs::r1cs::LinearCombination;

use crate::utils::{ScalarBytes, ScalarBits};
use crate::utils::{AllocatedScalar, constrain_lc_with_scalar};
// use crate::gadget_mimc::{mimc, MIMC_ROUNDS, mimc_hash_2, mimc_gadget};
use crate::poseidon::{Poseidon_hash_2, Poseidon_hash_2_constraints, PoseidonSbox};
use crate::poseidon::builder::Poseidon;

pub type DBVal = (Scalar, Scalar);

pub const TREE_DEPTH: usize = 30;

// TODO: ABSTRACT HASH FUNCTION BETTER

#[derive(Clone)]
pub struct VanillaSparseMerkleTree {
	pub depth: usize,
	empty_tree_hashes: Vec<Scalar>,
	db: BTreeMap<ScalarBytes, DBVal>,
	//hash_constants: &'a [Scalar],
	hash_params: Poseidon,
	pub root: Scalar
}

impl VanillaSparseMerkleTree {
	pub fn new(hash_params: Poseidon) -> VanillaSparseMerkleTree {
		let depth = TREE_DEPTH;
		let mut db = BTreeMap::new();
		let mut empty_tree_hashes: Vec<Scalar> = vec![];
		empty_tree_hashes.push(Scalar::zero());
		for i in 1..=depth {
			let prev = empty_tree_hashes[i-1];
			// let new = mimc(&prev, &prev, hash_constants);
			// Ensure using PoseidonSbox::Inverse
			let new = Poseidon_hash_2(prev.clone(), prev.clone(), &hash_params);
			let key = new.to_bytes();

			db.insert(key, (prev, prev));
			empty_tree_hashes.push(new);
		}

		let root = empty_tree_hashes[depth].clone();

		VanillaSparseMerkleTree {
			depth,
			empty_tree_hashes,
			db,
			hash_params,
			root
		}
	}

	pub fn update(&mut self, idx: Scalar, val: Scalar) -> Scalar {

		// Find path to insert the new key
		let mut sidenodes_wrap = Some(Vec::<Scalar>::new());
		self.get(idx, &mut sidenodes_wrap);
		let mut sidenodes: Vec<Scalar> = sidenodes_wrap.unwrap();

		let mut cur_idx = ScalarBits::from_scalar(&idx, TREE_DEPTH);
		let mut cur_val = val.clone();

		for _i in 0..self.depth {
			let side_elem = sidenodes.pop().unwrap();
			let new_val = {
				if cur_idx.is_lsb_set() {
					// LSB is set, so put new value on right
					//let h =  mimc(&side_elem, &cur_val, self.hash_constants);
					let h =  Poseidon_hash_2(side_elem.clone(), cur_val.clone(), &self.hash_params);
					self.update_db_with_key_val(h, (side_elem, cur_val));
					h
				} else {
					// LSB is unset, so put new value on left
					//let h =  mimc(&cur_val, &side_elem, self.hash_constants);
					let h =  Poseidon_hash_2(cur_val.clone(), side_elem.clone(), &self.hash_params);
					self.update_db_with_key_val(h, (cur_val, side_elem));
					h
				}
			};
			//println!("Root at level {} is {:?}", i, &cur_val);
			cur_idx.shr();
			cur_val = new_val;
		}

		self.root = cur_val;

		cur_val
	}

	/// Get a value from tree, if `proof` is not None, populate `proof` with the merkle proof
	pub fn get(&self, idx: Scalar, proof: &mut Option<Vec<Scalar>>) -> Scalar {
		let mut cur_idx = ScalarBits::from_scalar(&idx, TREE_DEPTH);
		let mut cur_node = self.root.clone();

		let need_proof = proof.is_some();
		let mut proof_vec = Vec::<Scalar>::new();

		for _i in 0..self.depth {
			let k = cur_node.to_bytes();
			let v = self.db.get(&k).unwrap();
			if cur_idx.is_msb_set() {
				// MSB is set, traverse to right subtree
				cur_node = v.1;
				if need_proof { proof_vec.push(v.0); }
			} else {
				// MSB is unset, traverse to left subtree
				cur_node = v.0;
				if need_proof { proof_vec.push(v.1); }
			}
			cur_idx.shl();
		}

		match proof {
			Some(v) => {
				v.extend_from_slice(&proof_vec);
			}
			None => ()
		}

		cur_node
	}

	/// Verify a merkle proof, if `root` is None, use the current root else use given root
	pub fn verify_proof(&self, idx: Scalar, val: Scalar, proof: &[Scalar], root: Option<&Scalar>) -> bool {
		let mut cur_idx = ScalarBits::from_scalar(&idx, TREE_DEPTH);
		let mut cur_val = val.clone();

		for i in 0..self.depth {
			cur_val = {
				if cur_idx.is_lsb_set() {
					Poseidon_hash_2(proof[self.depth-1-i].clone(), cur_val.clone(), &self.hash_params)
				} else {
					Poseidon_hash_2(cur_val.clone(), proof[self.depth-1-i].clone(), &self.hash_params)
				}
			};

			cur_idx.shr();
		}

		// Check if root is equal to cur_val
		match root {
			Some(r) => {
				cur_val == *r
			}
			None => {
				cur_val == self.root
			}
		}
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
	poseidon_params: &Poseidon
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

		// prev_hash = mimc_hash_2::<CS>(cs, left, right, mimc_rounds, mimc_constants)?;
		assert!(poseidon_params.sbox == PoseidonSbox::Inverse, "Assert sbox is inverse");
		prev_hash = Poseidon_hash_2_constraints::<CS>(cs, left, right, statics.clone(), poseidon_params)?;
	}

	constrain_lc_with_scalar::<CS>(cs, prev_hash, root);

	Ok(())
}
