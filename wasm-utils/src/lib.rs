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
			levels: vec![Vec::new(); num_levels],
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

		let mut new_state = TreeState {
			edge_nodes: curr_state.edge_nodes.clone(),
			leaf_count: curr_state.leaf_count + 1,
		};
		let mut edge_index = curr_state.leaf_count;
		let data = Data::from(leaf);
		let mut pair_hash = data.clone();

		for i in 0..curr_state.edge_nodes.len() {
			if edge_index % 2 == 0 {
				new_state.edge_nodes[i] = pair_hash;
			}
			let level = self.levels.get_mut(i).unwrap();
			level.push(pair_hash);

			let hash = new_state.edge_nodes[i];
			pair_hash = Data::hash(hash, pair_hash, &self.hasher);

			edge_index /= 2;
		}

		self.curr_root = pair_hash;
		self.states.insert(pair_hash, new_state);
	}

	pub fn prove(&self, root_bytes: [u8; 32], leaf_bytes: [u8; 32]) -> Vec<(bool, [u8; 32])> {
		let root = Data::from(root_bytes);
		let leaf = Data::from(leaf_bytes);
		assert!(self.states.contains_key(&root), "Root not found!");
		assert!(self.leaf_indices.contains_key(&leaf), "Leaf not found!");

		let state = self.states.get(&root).unwrap();

		let mut node_index = self.leaf_indices.get(&leaf).cloned().unwrap();
		let mut path = Vec::new();
		for (i, level) in self.levels.iter().enumerate() {
			let res = if node_index % 2 == 0 {
				let node = if node_index == 0 {
					level[0]
				} else {
					level[node_index - 1]
				};
				(false, node.0.to_bytes())
			} else {
				let node = if node_index == level.len() - 1 {
					state.edge_nodes[i]
				} else {
					level[node_index + 1]
				};
				(true, node.0.to_bytes())
			};

			path.push(res);
			node_index /= 2;
		}

		path
	}

	pub fn verify(
		&self,
		root_bytes: [u8; 32],
		leaf_bytes: [u8; 32],
		path: Vec<(bool, [u8; 32])>,
	) -> bool {
		let root = Data::from(root_bytes);
		let mut hash = Data::from(leaf_bytes);
		for (right, bytes) in path {
			let pair = Data::from(bytes);

			hash = if right {
				Data::hash(hash, pair, &self.hasher)
			} else {
				Data::hash(pair, hash, &self.hasher)
			}
		}

		root == hash
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use curve25519_dalek::scalar::Scalar;
	use pallet_merkle::merkle::keys::Data;
	#[test]
	fn should_make_tree() {
		let mut tree = MerkleClient::new(2);
		let leaf1 = Scalar::from(1u32);
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);
		tree.add_leaf(leaf1.to_bytes());
		tree.add_leaf(leaf2.to_bytes());
		tree.add_leaf(leaf3.to_bytes());

		let node1 = Data::hash(Data(leaf1), Data(leaf2), &tree.hasher);
		let node2 = Data::hash(Data(leaf3), Data(leaf3), &tree.hasher);
		let root = Data::hash(node1, node2, &tree.hasher);

		assert_eq!(tree.curr_root, root, "Invalid root!");
	}
}
