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

#[wasm_bindgen]
pub fn greet() {
	log("Hello from rust");
}

pub struct TreeState {
	edge_nodes: Vec<Data>,
	leaf_count: usize,
}

#[wasm_bindgen]
pub struct MerkleClient {
	curr_root: Data,
	states: HashMap<Data, TreeState>,
	leaves: Vec<Data>,
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
			leaves: Vec::new(),
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
			self.leaves.len() < self.max_leaves as usize,
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

			let hash = new_state.edge_nodes[i];
			pair_hash = Data::hash(hash, pair_hash, &self.hasher);
			let level = self.levels.get_mut(i).unwrap();
			level.push(pair_hash);

			edge_index /= 2;
		}

		self.curr_root = pair_hash;
		self.leaves.push(data);
		self.states.insert(pair_hash, new_state);
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
