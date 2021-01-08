use curve25519_dalek::scalar::Scalar;
use js_sys::{Array, JsString, Map, JSON};
use pallet_merkle::merkle::helper::{leaf_data, prove_with_path, verify, ZkProof};
use pallet_merkle::merkle::keys::Data;
use pallet_merkle::merkle::poseidon::Poseidon;
use rand::rngs::OsRng;
use std::collections::hash_map::HashMap;
use wasm_bindgen::prelude::*;
use web_sys::{window, Storage};

#[wasm_bindgen]
extern "C" {
	#[wasm_bindgen(js_namespace = console)]
	fn log(s: &str);
}

#[wasm_bindgen(start)]
pub fn set_panic_hook() {
	// `set_panic_hook`is called once during initialization
	// we are printing useful errors when out code panics
	console_error_panic_hook::set_once();
}

// Decodes hex string into byte array
pub fn decode_hex(s: &str) -> [u8; 32] {
	assert!(s.len() == 64, "Invalid hex length!");
	let arr: Vec<u8> = (0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
		.collect();
	let mut buf: [u8; 32] = [0u8; 32];
	buf.copy_from_slice(&arr[..]);
	buf
}

// Encodes byte array
pub fn encode_hex(bytes: [u8; 32]) -> String {
	bytes.iter().map(|&b| format!("{:02x}", b)).collect()
}

// Keys used for saving things in storage and generating notes
const STORAGE_SECRETS_PREFIX: &str = "webb-mix-secrets";
const NOTE_PREFIX: &str = "webb.mix";

#[wasm_bindgen]
pub struct Mixer {
	tree_map: HashMap<(String, u8), MerkleClient>,
	store: Storage,
}

impl Mixer {
	fn get_tree_mut(&mut self, asset: String, id: u8) -> &mut MerkleClient {
		assert!(
			self.tree_map.contains_key(&(asset.to_owned(), id)),
			"Tree not found!"
		);
		let tree = self.tree_map.get_mut(&(asset.to_owned(), id)).unwrap();
		tree
	}

	fn get_tree(&self, asset: String, id: u8) -> &MerkleClient {
		assert!(
			self.tree_map.contains_key(&(asset.to_owned(), id)),
			"Tree not found!"
		);
		let tree = self.tree_map.get(&(asset.to_owned(), id)).unwrap();
		tree
	}
}

// Implementation available to JS
#[wasm_bindgen]
impl Mixer {
	pub fn new(trees_js: JsValue) -> Self {
		let trees: Vec<(String, u8, usize)> = trees_js.into_serde().unwrap();
		let mut tree_map = HashMap::new();
		for (asset, id, height) in trees {
			tree_map.insert((asset, id), MerkleClient::init(height));
		}
		let win = window().unwrap();
		let store = win.local_storage().unwrap().unwrap();
		Mixer { tree_map, store }
	}

	pub fn add_leaves(&mut self, asset: String, id: u8, leaves: JsValue) {
		let tree = self.get_tree_mut(asset, id);
		tree.add_leaves(leaves);
	}

	pub fn generate_proof(&self, asset: String, id: u8, root: JsValue, leaf: JsValue) -> Map {
		let tree = self.get_tree(asset, id);
		tree.generate_proof(root, leaf)
	}

	pub fn get_root(&self, asset: String, id: u8) -> JsValue {
		let tree = self.get_tree(asset, id);
		tree.get_root()
	}

	// Generates a new note with random samples
	// note has a format of `webb.mix-<mixed_id>-<r as hex string><nullifier as hex string>`
	pub fn generate_note(&mut self, asset: String, id: u8, block_number: u32) -> JsString {
		assert!(
			self.tree_map.contains_key(&(asset.to_owned(), id)),
			"Tree not found!"
		);
		let tree = self.tree_map.get_mut(&(asset.to_owned(), id)).unwrap();
		let (r, nullifier, _, _) = tree.generate_leaf_data();

		let encoded_r = encode_hex(r.to_bytes());
		let encoded_nullifier = encode_hex(nullifier.to_bytes());
		let note = format!(
			"{}-{}-{}-{}-{}{}",
			NOTE_PREFIX, asset, id, block_number, encoded_r, encoded_nullifier
		);
		let note_js = JsString::from(note);

		note_js
	}

	// Saving the note to a memory.
	// First it checks if the note is in valid format,
	// then decodes it and saves a note to a Merkle Client
	// to be used for constructing the proof
	pub fn save_note(&mut self, note_js: JsString) -> Map {
		let note: String = note_js.into();

		let parts: Vec<&str> = note.split("-").collect();
		assert!(parts[0] == NOTE_PREFIX, "Invalid note!");
		let asset: String = parts[1].to_owned();
		let id: u8 = parts[2].parse().unwrap();
		assert!(
			self.tree_map.contains_key(&(asset.to_owned(), id)),
			"Tree not found!"
		);
		let block_number: u32 = parts[3].parse().unwrap();
		let note_val = parts[4];
		assert!(note_val.len() == 128, "Invalid note length");

		// Checking the validity
		let r_bytes = decode_hex(&note_val[..64]);
		let nullifier_bytes = decode_hex(&note_val[64..]);

		let tree = self.tree_map.get_mut(&(asset, id)).unwrap();
		let (r, nullifier, nullifier_hash, leaf) =
			tree.leaf_data_from_bytes(r_bytes, nullifier_bytes);
		tree.saved_leafs.insert(
			leaf,
			LeafData {
				r,
				nullifier,
				nullifier_hash,
			},
		);

		let leaf_js = JsValue::from_serde(&leaf.0.to_bytes()).unwrap();
		let asset_js = JsValue::from(&asset);
		let id_js = JsValue::from(id);
		let block_number_js = JsValue::from(block_number);

		let map = Map::new();
		map.set(&JsValue::from_str("leaf"), &leaf_js);
		map.set(&JsValue::from_str("asset"), &asset_js);
		map.set(&JsValue::from_str("id"), &id_js);
		map.set(&JsValue::from_str("block_number"), &block_number_js);
		map
	}

	// Saving to storage which is an option with users consent
	// All saved notes are stored into one array
	pub fn save_note_to_storage(&self, note: &JsValue) {
		let key = STORAGE_SECRETS_PREFIX;
		let arr = if let Ok(Some(value)) = self.store.get_item(&key) {
			let data = JSON::parse(&value).ok().unwrap();
			Array::from(&data)
		} else {
			Array::new()
		};
		arr.push(note);
		let storage_string: String = JSON::stringify(&arr).unwrap().into();
		self.store.set_item(&key, &storage_string).unwrap();
	}

	// Loads saved notes from the storage and saves them to memory
	// to be used for constructing the tree
	pub fn load_notes_from_storage(&mut self) {
		let key = STORAGE_SECRETS_PREFIX;
		if let Ok(Some(value)) = self.store.get_item(&key) {
			let data = JSON::parse(&value).ok().unwrap();
			let arr = Array::from(&data);
			let arr_iter = arr.iter();
			for item in arr_iter {
				let note_string = JsString::from(item);
				self.save_note(note_string);
			}
		};
	}
}

pub struct LeafData {
	r: Scalar,
	nullifier: Scalar,
	nullifier_hash: Data,
}

// State of the tree which includes its size + current edge nodes
pub struct TreeState {
	edge_nodes: Vec<Data>,
	leaf_count: usize,
}

#[wasm_bindgen]
pub struct MerkleClient {
	curr_root: Data,
	states: HashMap<Data, TreeState>,
	saved_leafs: HashMap<Data, LeafData>,
	leaf_indicies: HashMap<Data, usize>,
	levels: Vec<Vec<Data>>,
	max_leaves: u32,
	hasher: Poseidon,
}

#[wasm_bindgen]
impl MerkleClient {
	// Get the current root, mostly used for testing
	pub fn get_root(&self) -> JsValue {
		JsValue::from_serde(&self.curr_root.0.to_bytes()).unwrap()
	}

	// Add array of leaves fetched from the chain
	pub fn add_leaves(&mut self, leaves: JsValue) {
		let elements: Vec<[u8; 32]> = leaves.into_serde().unwrap();
		for elem in elements {
			let leaf = Data::from(elem);
			self.add_leaf(leaf);
		}
	}

	// Generates zk proof
	pub fn generate_proof(&self, root_json: JsValue, leaf_json: JsValue) -> Map {
		let root_bytes: [u8; 32] = root_json.into_serde().unwrap();
		let leaf_bytes: [u8; 32] = leaf_json.into_serde().unwrap();
		let root = Data::from(root_bytes);
		let leaf = Data::from(leaf_bytes);

		let proof = self.prove_zk(root, leaf);

		let path = Array::new();
		for (bit, node) in proof.path {
			let level_arr = Array::new();
			let bit_js = JsValue::from_serde(&(bit.0).0).unwrap();
			let node_js = JsValue::from_serde(&(node.0).0).unwrap();

			level_arr.push(&bit_js);
			level_arr.push(&node_js);

			path.push(&level_arr);
		}
		let leaf_com = JsValue::from_serde(&proof.leaf_com.0.to_bytes()).unwrap();
		let r_com = JsValue::from_serde(&proof.r_com.0.to_bytes()).unwrap();
		let nullifier_com = JsValue::from_serde(&proof.nullifier_com.0.to_bytes()).unwrap();
		let nullifier_hash = JsValue::from_serde(&proof.nullifier_hash.0.to_bytes()).unwrap();
		let bytes = JsValue::from_serde(&proof.bytes).unwrap();

		let map = Map::new();
		map.set(&JsValue::from_str("path"), &path);
		map.set(&JsValue::from_str("leaf_com"), &leaf_com);
		map.set(&JsValue::from_str("r_com"), &r_com);
		map.set(&JsValue::from_str("nullifier_com"), &nullifier_com);
		map.set(&JsValue::from_str("nullifier_hash"), &nullifier_hash);
		map.set(&JsValue::from_str("bytes"), &bytes);

		map
	}
}

impl MerkleClient {
	// Separated from `new` method for testing purposes
	pub fn init(num_levels: usize) -> Self {
		assert!(num_levels <= 32 && num_levels > 0, "Invalid tree height!");
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
			saved_leafs: HashMap::new(),
			levels: vec![vec![Data::zero()]; num_levels],
			leaf_indicies: HashMap::new(),
			max_leaves: u32::MAX >> (max_levels - num_levels),
			hasher: Poseidon::new(4),
		}
	}

	pub fn generate_leaf_data(&self) -> (Scalar, Scalar, Data, Data) {
		let mut rng = OsRng::default();

		leaf_data(&mut rng, &self.hasher)
	}

	pub fn leaf_data_from_bytes(
		&self,
		r_bytes: [u8; 32],
		nullifier_bytes: [u8; 32],
	) -> (Scalar, Scalar, Data, Data) {
		let r = Scalar::from_bytes_mod_order(r_bytes);
		let nullifier = Scalar::from_bytes_mod_order(nullifier_bytes);
		// Construct nullifier hash for note
		let nullifier_hash = Data::hash(Data(nullifier), Data(nullifier), &self.hasher);
		// Constructing a leaf from the scalars
		let leaf = Data::hash(Data(r), Data(nullifier), &self.hasher);
		(r, nullifier, nullifier_hash, leaf)
	}

	// Used for testing purposes
	pub fn deposit(&mut self) -> Data {
		let mut rng = OsRng::default();
		let (r, nullifier, nullifier_hash, leaf) = leaf_data(&mut rng, &self.hasher);
		let ld = LeafData {
			r,
			nullifier,
			nullifier_hash,
		};
		self.saved_leafs.insert(leaf, ld);
		self.add_leaf(leaf);
		leaf
	}

	// Adds a single leaf to the tree
	// Saves the new state and saves the index of the added leaf
	pub fn add_leaf(&mut self, leaf: Data) {
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
		let data = leaf;
		let mut pair_hash = data.clone();

		for i in 0..curr_state.edge_nodes.len() {
			let level = self.levels.get_mut(i).unwrap();
			// Update the edges if leaf index is uneven number
			if edge_index % 2 == 0 {
				new_state.edge_nodes[i] = pair_hash;
			}
			// Push new node on the current level or replace the last one
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
		self.leaf_indicies.insert(data, curr_state.leaf_count);
		self.states.insert(pair_hash, new_state);
	}

	// Membership proofs
	pub fn prove(&self, root: Data, leaf: Data) -> Vec<(bool, Data)> {
		assert!(self.states.contains_key(&root), "Root not found!");
		assert!(self.leaf_indicies.contains_key(&leaf), "Leaf not found!");

		let state = self.states.get(&root).unwrap();
		assert!(state.leaf_count > 0, "Tree is empty!");
		let mut last_index = state.leaf_count - 1;
		let mut node_index = self.leaf_indicies.get(&leaf).cloned().unwrap();

		assert!(
			node_index <= last_index,
			"Current tree state doesn't contain specified leaf."
		);
		let mut path = Vec::new();
		for (i, level) in self.levels.iter().enumerate() {
			let is_right = node_index % 2 == 0;
			let node = match is_right {
				true => {
					if node_index == last_index {
						state.edge_nodes[i]
					} else {
						level[node_index + 1]
					}
				}
				false => level[node_index - 1],
			};

			path.push((is_right, node));
			node_index /= 2;
			last_index /= 2;
		}

		path
	}

	// Mostly used for testing purposes
	pub fn verify(&self, root: Data, leaf: Data, path: Vec<(bool, Data)>) -> bool {
		let mut hash = leaf;
		for (right, pair) in path {
			hash = if right {
				Data::hash(hash, pair, &self.hasher)
			} else {
				Data::hash(pair, hash, &self.hasher)
			}
		}
		root == hash
	}

	pub fn verify_zk(&self, root: Data, zk_proof: ZkProof) -> bool {
		let res = verify(root, zk_proof, &self.hasher);

		res.is_ok()
	}

	pub fn prove_zk(&self, root: Data, leaf: Data) -> ZkProof {
		assert!(
			self.saved_leafs.contains_key(&leaf),
			"Secret data not found!"
		);
		let ld = self.saved_leafs.get(&leaf).unwrap();

		// First we create normal proof, then make zk proof against it
		let path = self.prove(root, leaf);
		let valid = self.verify(root, leaf, path.clone());
		assert!(valid, "Could not make proof!");
		let path_data: Vec<(bool, Data)> = path
			.into_iter()
			// Our gadget calculates the sides inversely
			.map(|(side, d)| (!side, d))
			.collect();

		let zk_proof = prove_with_path(
			root,
			leaf,
			ld.nullifier_hash,
			ld.nullifier,
			ld.r,
			path_data,
			&self.hasher,
		);
		assert!(zk_proof.is_ok(), "Could not make proof!");

		zk_proof.unwrap()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_encode_and_decode_hex() {
		let mut rng = OsRng::default();
		let num = Scalar::random(&mut rng);

		let enc = encode_hex(num.to_bytes());
		let dec = decode_hex(&enc);

		assert!(dec == num.to_bytes());
	}

	#[test]
	fn should_have_correct_root() {
		let mut tree = MerkleClient::init(2);
		let leaf1 = Data(Scalar::from(1u32));
		let leaf2 = Data(Scalar::from(2u32));
		let leaf3 = Data(Scalar::from(3u32));

		tree.add_leaf(leaf1);
		let node1 = Data::hash(leaf1, leaf1, &tree.hasher);
		let root = Data::hash(node1, node1, &tree.hasher);
		assert_eq!(tree.curr_root, root);

		tree.add_leaf(leaf2);
		let node1 = Data::hash(leaf1, leaf2, &tree.hasher);
		let root = Data::hash(node1, node1, &tree.hasher);
		assert_eq!(tree.curr_root, root);

		tree.add_leaf(leaf3);
		let node1 = Data::hash(leaf1, leaf2, &tree.hasher);
		let node2 = Data::hash(leaf3, leaf3, &tree.hasher);
		let root = Data::hash(node1, node2, &tree.hasher);

		assert_eq!(tree.curr_root, root);
	}

	#[test]
	fn should_have_correct_levels() {
		let mut tree = MerkleClient::init(2);
		let leaf1 = Data(Scalar::from(1u32));
		let leaf2 = Data(Scalar::from(2u32));
		let leaf3 = Data(Scalar::from(3u32));

		tree.add_leaf(leaf1);
		let node1 = Data::hash(leaf1, leaf1, &tree.hasher);
		let level0 = vec![leaf1];
		let level1 = vec![node1];
		assert_eq!(tree.levels, vec![level0, level1]);

		tree.add_leaf(leaf2);
		let node1 = Data::hash(leaf1, leaf2, &tree.hasher);
		let level0 = vec![leaf1, leaf2];
		let level1 = vec![node1];
		assert_eq!(tree.levels, vec![level0, level1]);

		tree.add_leaf(leaf3);
		let node1 = Data::hash(leaf1, leaf2, &tree.hasher);
		let node2 = Data::hash(leaf3, leaf3, &tree.hasher);
		let level0 = vec![leaf1, leaf2, leaf3];
		let level1 = vec![node1, node2];

		assert_eq!(tree.levels, vec![level0, level1]);
	}

	#[test]
	fn should_have_correct_state() {
		let mut tree = MerkleClient::init(2);
		let leaf1 = Data(Scalar::from(1u32));
		let leaf2 = Data(Scalar::from(2u32));
		let leaf3 = Data(Scalar::from(3u32));

		tree.add_leaf(leaf1);
		let node1 = Data::hash(leaf1, leaf1, &tree.hasher);
		let edge_nodes = vec![leaf1, node1];
		let last_state = tree.states.get(&tree.curr_root).unwrap();
		assert_eq!(edge_nodes, last_state.edge_nodes);

		tree.add_leaf(leaf2);
		let node1 = Data::hash(leaf1, leaf2, &tree.hasher);
		let edge_nodes = vec![leaf1, node1];
		let last_state = tree.states.get(&tree.curr_root).unwrap();
		assert_eq!(edge_nodes, last_state.edge_nodes);

		tree.add_leaf(leaf3);
		let node1 = Data::hash(leaf1, leaf2, &tree.hasher);
		let edge_nodes = vec![leaf3, node1];
		let last_state = tree.states.get(&tree.curr_root).unwrap();
		assert_eq!(edge_nodes, last_state.edge_nodes);
	}

	#[test]
	fn should_make_correct_proof() {
		let mut tree = MerkleClient::init(2);
		let leaf1 = tree.deposit();
		let leaf2 = tree.deposit();
		let leaf3 = tree.deposit();

		let path = tree.prove(tree.curr_root, leaf1);
		let valid = tree.verify(tree.curr_root, leaf1, path.clone());
		assert!(valid);

		let path = tree.prove(tree.curr_root, leaf2);
		let valid = tree.verify(tree.curr_root, leaf2, path.clone());
		assert!(valid);

		let path = tree.prove(tree.curr_root, leaf3);
		let valid = tree.verify(tree.curr_root, leaf3, path.clone());
		assert!(valid);
	}

	#[test]
	fn should_not_verify_incorrect_proof() {
		let mut tree = MerkleClient::init(2);
		let leaf1 = tree.deposit();
		let leaf2 = Data(Scalar::from(2u32));
		let leaf3 = Data(Scalar::from(3u32));

		let path = tree.prove(tree.curr_root, leaf1);
		let valid = tree.verify(tree.curr_root, leaf2, path.clone());
		assert!(!valid);

		let path = tree.prove(tree.curr_root, leaf1);
		let valid = tree.verify(tree.curr_root, leaf3, path.clone());
		assert!(!valid);
	}

	#[test]
	fn should_make_correct_zk_proof() {
		let mut tree = MerkleClient::init(2);
		let leaf1 = tree.deposit();
		let leaf2 = tree.deposit();
		let leaf3 = tree.deposit();

		let proof = tree.prove_zk(tree.curr_root, leaf1);
		let valid = tree.verify_zk(tree.curr_root, proof);
		assert!(valid);

		let proof = tree.prove_zk(tree.curr_root, leaf2);
		let valid = tree.verify_zk(tree.curr_root, proof);
		assert!(valid);

		let proof = tree.prove_zk(tree.curr_root, leaf3);
		let valid = tree.verify_zk(tree.curr_root, proof);
		assert!(valid);
	}

	#[test]
	fn should_not_verify_incorrect_zk_proof() {
		let mut tree = MerkleClient::init(2);

		tree.deposit();
		let old_root = tree.curr_root;
		let leaf = tree.deposit();
		let proof = tree.prove_zk(tree.curr_root, leaf);
		let valid = tree.verify_zk(old_root, proof);
		assert!(!valid);
	}
}
