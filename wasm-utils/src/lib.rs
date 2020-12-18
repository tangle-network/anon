use curve25519_dalek::scalar::Scalar;
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

pub struct TreeState {
	edge_nodes: Vec<Data>,
	leaf_count: usize,
}

#[wasm_bindgen]
pub struct MerkleClient {
	curr_root: Data,
	states: HashMap<Scalar, TreeState>,
	leaves: Vec<Data>,
	levels: Vec<Vec<Data>>,
	hasher: Poseidon,
}

#[wasm_bindgen]
impl MerkleClient {
	pub fn new(num_levels: usize) -> Self {
		Self {
			curr_root: Data::zero(),
			states: HashMap::new(),
			leaves: vec![Data::zero(); num_levels],
			levels: vec![Vec::new(); num_levels],
			hasher: Poseidon::new(4),
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
		let curr_state = self.states.get(&self.curr_root.0).unwrap();

		let mut new_state = TreeState {
			edge_nodes: curr_state.edge_nodes.clone(),
			leaf_count: curr_state.leaf_count + 1,
		};
		let mut edge_index = curr_state.leaf_count;
		let data = Data(Scalar::from_bytes_mod_order(leaf));
		let mut pair_hash = data;

		for (i, node) in curr_state.edge_nodes.iter().enumerate() {
			if edge_index % 2 == 0 {
				new_state.edge_nodes[i] = pair_hash;
			}
			pair_hash = Data::hash(*node, pair_hash, &self.hasher);
			let level = self.levels.get_mut(i).unwrap();
			level.push(pair_hash);

			edge_index /= 2;
		}

		self.leaves.push(data);
		self.states.insert(pair_hash.0, new_state);
	}
}

#[wasm_bindgen]
pub fn greet() {
	log("Hello from rust");
}
