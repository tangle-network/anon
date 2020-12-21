use pallet_merkle::merkle::keys::Data;
use pallet_merkle::merkle::poseidon::Poseidon;
use std::collections::hash_map::HashMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
	#[wasm_bindgen(js_namespace = console)]
	fn log(s: &str);
	#[wasm_bindgen(js_namespace = localStorage)]
	fn setItem(key: &str, value: &str);
	#[wasm_bindgen(js_namespace = localStorage)]
	fn getItem(key: &str);
}

pub fn set_panic_hook() {
	// When the `console_error_panic_hook` feature is enabled, we can call the
	// `set_panic_hook` function at least once during initialization, and then
	// we will get better error messages if our code ever panics.
	//
	// For more details see
	// https://github.com/rustwasm/console_error_panic_hook#readme
	#[cfg(feature = "console_error_panic_hook")]
	console_error_panic_hook::set_once();
}

pub struct TreeState {
	edge_nodes: Vec<Data>,
	leaf_count: usize,
}

#[wasm_bindgen]
pub struct MerkleClient {
	curr_root: Data,
	states: HashMap<Data, TreeState>,
	leaf_indices: HashMap<Data, usize>,
	levels: Vec<Vec<Data>>,
	hasher: Poseidon,
	max_leaves: u32,
}

#[wasm_bindgen]
impl MerkleClient {
	pub fn new(num_levels: usize) -> Self {
		assert!(num_levels < 32 && num_levels > 0, "Invalid tree height!");
		let max_levels = 32;
		let init_root = Data::zero();
		let init_tree_state = TreeState {
			edge_nodes: vec![Data::zero(); num_levels],
			leaf_count: 0,
		};
		let mut init_states = HashMap::new();
		init_states.insert(init_root, init_tree_state);
		Self {
			curr_root: init_root,
			states: init_states,
			leaf_indices: HashMap::new(),
			levels: vec![vec![Data::zero()]; num_levels],
			hasher: Poseidon::new(4),
			max_leaves: u32::MAX >> (max_levels - num_levels),
		}
	}

	pub fn add_leaves(&mut self, leaves: JsValue) {
		let elements: Vec<[u8; 32]> = leaves.into_serde().unwrap();
		for elem in elements {
			self.add_leaf(elem);
		}
	}
}

impl MerkleClient {
	pub fn add_leaf(&mut self, leaf: [u8; 32]) {
		assert!(
			self.levels[0].len() < self.max_leaves as usize,
			"Tree is already full!"
		);
		let curr_state = self.states.get(&self.curr_root).unwrap();

		// There is a new tree state on every insert
		// It consists of edge nodes, since they change on every insert
		// And they are needed for creating proofs of membership in the past trees
		let mut new_state = TreeState {
			edge_nodes: curr_state.edge_nodes.clone(),
			leaf_count: curr_state.leaf_count + 1,
		};
		let mut edge_index = curr_state.leaf_count;
		let data = Data::from(leaf);
		let mut pair_hash = data.clone();

		for i in 0..curr_state.edge_nodes.len() {
			let level = self.levels.get_mut(i).unwrap();
			// Update the edges if leaf index is uneven number
			if edge_index % 2 == 0 {
				new_state.edge_nodes[i] = pair_hash;
			}
			// Push new node one current level or replace the last one
			if edge_index >= level.len() {
				level.push(pair_hash);
			} else {
				level[edge_index] = pair_hash;
			}

			let hash = new_state.edge_nodes[i];
			pair_hash = Data::hash(hash, pair_hash, &self.hasher);

			edge_index /= 2;
		}

		self.curr_root = pair_hash;
		self.states.insert(pair_hash, new_state);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use curve25519_dalek::scalar::Scalar;
	use pallet_merkle::merkle::keys::Data;
	#[test]
	fn should_have_correct_root() {
		let mut tree = MerkleClient::new(2);
		let leaf1 = Scalar::from(1u32);
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);

		tree.add_leaf(leaf1.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf1), &tree.hasher);
		let root = Data::hash(node1, node1, &tree.hasher);
		assert_eq!(tree.curr_root, root);

		tree.add_leaf(leaf2.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf2), &tree.hasher);
		let root = Data::hash(node1, node1, &tree.hasher);
		assert_eq!(tree.curr_root, root);

		tree.add_leaf(leaf3.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf2), &tree.hasher);
		let node2 = Data::hash(Data(leaf3), Data(leaf3), &tree.hasher);
		let root = Data::hash(node1, node2, &tree.hasher);

		assert_eq!(tree.curr_root, root);
	}

	#[test]
	fn should_have_correct_levels() {
		let mut tree = MerkleClient::new(2);
		let leaf1 = Scalar::from(1u32);
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);

		tree.add_leaf(leaf1.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf1), &tree.hasher);
		let level0 = vec![Data(leaf1)];
		let level1 = vec![node1];
		assert_eq!(tree.levels, vec![level0, level1]);

		tree.add_leaf(leaf2.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf2), &tree.hasher);
		let level0 = vec![Data(leaf1), Data(leaf2)];
		let level1 = vec![node1];
		assert_eq!(tree.levels, vec![level0, level1]);

		tree.add_leaf(leaf3.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf2), &tree.hasher);
		let node2 = Data::hash(Data(leaf3), Data(leaf3), &tree.hasher);
		let level0 = vec![Data(leaf1), Data(leaf2), Data(leaf3)];
		let level1 = vec![node1, node2];

		assert_eq!(tree.levels, vec![level0, level1]);
	}

	#[test]
	fn should_have_correct_state() {
		let mut tree = MerkleClient::new(2);
		let leaf1 = Scalar::from(1u32);
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);

		tree.add_leaf(leaf1.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf1), &tree.hasher);
		let edge_nodes = vec![Data(leaf1), node1];
		let last_state = tree.states.get(&tree.curr_root).unwrap();
		assert_eq!(edge_nodes, last_state.edge_nodes);

		tree.add_leaf(leaf2.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf2), &tree.hasher);
		let edge_nodes = vec![Data(leaf1), node1];
		let last_state = tree.states.get(&tree.curr_root).unwrap();
		assert_eq!(edge_nodes, last_state.edge_nodes);

		tree.add_leaf(leaf3.to_bytes());
		let node1 = Data::hash(Data(leaf1), Data(leaf2), &tree.hasher);
		let edge_nodes = vec![Data(leaf3), node1];
		let last_state = tree.states.get(&tree.curr_root).unwrap();
		assert_eq!(edge_nodes, last_state.edge_nodes);
	}
}
