use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use curve25519_gadgets::fixed_deposit_tree::builder::{FixedDepositTree, FixedDepositTreeBuilder};
use js_sys::{Array, JsString, Map};
use merlin::Transcript;
use std::collections::hash_map::HashMap;
use wasm_bindgen::prelude::*;

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

const NOTE_PREFIX: &str = "webb.mix";
const VERSION: &str = "v1";

#[wasm_bindgen]
pub struct Mixer {
	tree_map: HashMap<(String, u8), FixedDepositTree>,
}

impl Mixer {
	fn get_tree_mut(&mut self, asset: String, id: u8) -> &mut FixedDepositTree {
		assert!(self.tree_map.contains_key(&(asset.to_owned(), id)), "Tree not found!");
		let tree = self.tree_map.get_mut(&(asset.to_owned(), id)).unwrap();
		tree
	}

	fn get_tree(&self, asset: String, id: u8) -> &FixedDepositTree {
		assert!(self.tree_map.contains_key(&(asset.to_owned(), id)), "Tree not found!");
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
		for (asset, id, depth) in trees {
			tree_map.insert((asset, id), FixedDepositTreeBuilder::new().depth(depth).build());
		}
		Mixer { tree_map }
	}

	pub fn add_leaves(&mut self, asset: String, id: u8, leaves: JsValue) {
		let fixed_tree = self.get_tree_mut(asset, id);
		let leaves_bytes: Vec<[u8; 32]> = leaves.into_serde().unwrap();
		fixed_tree.tree.add_leaves(leaves_bytes);
	}

	pub fn get_root(&self, asset: String, id: u8) -> JsValue {
		let fixed_tree = self.get_tree(asset, id);
		JsValue::from_serde(&fixed_tree.tree.root.to_bytes()).unwrap()
	}

	// Generates a new note with random samples
	// note has a format of:
	// `webb.mix-[version]-[asset]-[mixed_id]-[block_number]-[r_hex][nullifier_hex]`
	pub fn generate_note(&mut self, asset: String, id: u8, block_number: Option<u32>) -> JsString {
		assert!(self.tree_map.contains_key(&(asset.to_owned(), id)), "Tree not found!");
		let fixed_tree = self.get_tree_mut(asset.to_owned(), id);
		let leaf = fixed_tree.generate_secrets();
		let (r, nullifier, ..) = fixed_tree.get_secrets(leaf);

		let encoded_r = encode_hex(r.to_bytes());
		let encoded_nullifier = encode_hex(nullifier.to_bytes());
		let mut parts: Vec<String> = Vec::new();
		parts.push(NOTE_PREFIX.to_string());
		parts.push(VERSION.to_string());
		parts.push(format!("{}", asset));
		parts.push(format!("{}", id));
		if block_number.is_some() {
			let bn: u32 = block_number.unwrap();
			parts.push(format!("{}", bn));
		}
		parts.push(format!("{}{}", encoded_r, encoded_nullifier));
		let note = parts.join("-");
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
		let partial = parts.len() == 5;

		assert!(parts[0] == NOTE_PREFIX, "Invalid note prefix!");
		assert!(parts[1] == VERSION, "Invalid version!");
		let asset: String = parts.get(2).expect("Unable to get asset!").to_string();
		let id: u8 = parts.get(3).expect("Unable to get id!").parse().expect("Invalid id!");
		let (block_number, note_val): (Option<u32>, _) = if partial {
			(None, parts.get(4).expect("Unable to get secrets!"))
		} else {
			let bn: u32 = parts
				.get(4)
				.expect("Unable to get block number!")
				.parse()
				.expect("Invalid block number!");
			(Some(bn), parts.get(5).expect("Unable to get secrets!"))
		};
		assert!(note_val.len() == 128, "Invalid note length!");

		assert!(self.tree_map.contains_key(&(asset.to_owned(), id)), "Tree not found!");

		// Checking the validity
		let r_bytes = decode_hex(&note_val[..64]);
		let nullifier_bytes = decode_hex(&note_val[64..]);

		let tree = self.get_tree_mut(asset.to_owned(), id);
		let (r, nullifier, nullifier_hash, leaf) = tree.leaf_data_from_bytes(r_bytes, nullifier_bytes);
		tree.add_secrets(leaf, r, nullifier, nullifier_hash);

		let map = Map::new();
		let leaf_js = JsValue::from_serde(&leaf.to_bytes()).unwrap();
		let asset_js = JsValue::from(&asset);
		let id_js = JsValue::from(id);

		if block_number.is_some() {
			let block_number_js = JsValue::from(block_number.unwrap());
			map.set(&JsValue::from_str("block_number"), &block_number_js);
		}

		map.set(&JsValue::from_str("leaf"), &leaf_js);
		map.set(&JsValue::from_str("asset"), &asset_js);
		map.set(&JsValue::from_str("id"), &id_js);
		map
	}

	// Generates zk proof
	pub fn generate_proof(&self, asset: String, id: u8, root_json: JsValue, leaf_json: JsValue) -> Map {
		let root_bytes: [u8; 32] = root_json.into_serde().unwrap();
		let leaf_bytes: [u8; 32] = leaf_json.into_serde().unwrap();
		let tree = self.get_tree(asset, id);
		let root = Scalar::from_bytes_mod_order(root_bytes);
		let leaf = Scalar::from_bytes_mod_order(leaf_bytes);

		let pc_gens = PedersenGens::default();
		let bp_gens = BulletproofGens::new(40960, 1);
		let mut prover_transcript = Transcript::new(b"zk_membership_proof");
		let prover = Prover::new(&pc_gens, &mut prover_transcript);

		let (proof, (comms, nullifier_hash, leaf_index_comms, proof_comms)) =
			tree.prove_zk(root, leaf, &bp_gens, prover);

		let leaf_index_comms_js = Array::new();
		for com in leaf_index_comms {
			let bit_js = JsValue::from_serde(&com.0).unwrap();
			leaf_index_comms_js.push(&bit_js);
		}
		let proof_comms_js = Array::new();
		for com in proof_comms {
			let node = JsValue::from_serde(&com.0).unwrap();
			proof_comms_js.push(&node);
		}
		let comms_js = Array::new();
		for com in comms {
			let val = JsValue::from_serde(&com.0).unwrap();
			comms_js.push(&val);
		}

		let nullifier_hash = JsValue::from_serde(&nullifier_hash.to_bytes()).unwrap();
		let bytes = JsValue::from_serde(&proof.to_bytes()).unwrap();

		let map = Map::new();
		map.set(&JsValue::from_str("comms"), &comms_js);
		map.set(&JsValue::from_str("nullifier_hash"), &nullifier_hash);
		map.set(&JsValue::from_str("leaf_index_comms"), &leaf_index_comms_js);
		map.set(&JsValue::from_str("proof_comms"), &proof_comms_js);
		map.set(&JsValue::from_str("proof"), &bytes);

		map
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use curve25519_gadgets::poseidon::Poseidon_hash_2;
	use rand::rngs::OsRng;
	use wasm_bindgen_test::*;

	wasm_bindgen_test_configure!(run_in_browser);

	#[wasm_bindgen_test]
	fn should_encode_and_decode_hex() {
		let mut rng = OsRng::default();
		let num = Scalar::random(&mut rng);

		let enc = encode_hex(num.to_bytes());
		let dec = decode_hex(&enc);

		assert!(dec == num.to_bytes());
	}

	#[wasm_bindgen_test]
	fn should_have_correct_root() {
		let arr = Array::new();
		arr.push(&JsString::from("EDG"));
		arr.push(&JsValue::from(0));
		arr.push(&JsValue::from(2));
		let top_level_arr = Array::new();
		top_level_arr.push(&arr);
		let js_trees = JsValue::from(top_level_arr);
		let asset = "EDG";
		let id = 0;
		let mut mixer = Mixer::new(js_trees);
		let leaf1 = Scalar::from(1u32);
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);
		let zero = Scalar::zero();

		let arr = Array::new();
		arr.push(&JsValue::from_serde(&leaf1.to_bytes()).unwrap());
		arr.push(&JsValue::from_serde(&leaf2.to_bytes()).unwrap());
		arr.push(&JsValue::from_serde(&leaf3.to_bytes()).unwrap());
		let list = JsValue::from(arr);

		mixer.add_leaves(asset.to_owned(), id, list);
		let tree = mixer.get_tree(asset.to_owned(), id);
		let node1 = Poseidon_hash_2(leaf1, leaf2, &tree.hash_params);
		let node2 = Poseidon_hash_2(leaf3, zero, &tree.hash_params);
		let root = Poseidon_hash_2(node1, node2, &tree.hash_params);

		let calc_root_js = mixer.get_root(asset.to_owned(), id);
		let calc_root: [u8; 32] = calc_root_js.into_serde().unwrap();
		assert_eq!(calc_root, root.to_bytes());
	}

	#[wasm_bindgen_test]
	fn should_generate_and_save_note() {
		let arr = Array::new();
		arr.push(&JsString::from("EDG"));
		arr.push(&JsValue::from(0));
		arr.push(&JsValue::from(2));
		let top_level_arr = Array::new();
		top_level_arr.push(&arr);
		let js_trees = JsValue::from(top_level_arr);
		let asset = "EDG";
		let id = 0;
		let mut mixer = Mixer::new(js_trees);

		// Partial note
		let note_js = mixer.generate_note(asset.to_owned(), id, None);
		let note_map = mixer.save_note(note_js);

		let id_js = note_map.get(&JsValue::from("id"));
		let asset_js = note_map.get(&JsValue::from("asset"));
		let block_number_js = note_map.get(&JsValue::from("block_number"));

		let id_res: u8 = id_js.into_serde().unwrap();
		let asset_res: String = asset_js.into_serde().unwrap();

		assert_eq!(id_res, id);
		assert_eq!(asset_res, asset);
		assert!(block_number_js.is_undefined());

		// Complete note
		let note_js = mixer.generate_note(asset.to_owned(), id, Some(1));
		let note_map = mixer.save_note(note_js);

		let id_js = note_map.get(&JsValue::from("id"));
		let asset_js = note_map.get(&JsValue::from("asset"));
		let block_number_js = note_map.get(&JsValue::from("block_number"));

		let id_res: u8 = id_js.into_serde().unwrap();
		let asset_res: String = asset_js.into_serde().unwrap();
		let block_number_res: u32 = block_number_js.into_serde().unwrap();

		assert_eq!(id_res, id);
		assert_eq!(asset_res, asset);
		assert_eq!(block_number_res, 1);
	}

	#[wasm_bindgen_test]
	fn should_create_proof() {
		let arr = Array::new();
		arr.push(&JsString::from("EDG"));
		arr.push(&JsValue::from(0));
		arr.push(&JsValue::from(2));
		let top_level_arr = Array::new();
		top_level_arr.push(&arr);
		let js_trees = JsValue::from(top_level_arr);
		let asset = "EDG";
		let id = 0;
		let mut mixer = Mixer::new(js_trees);
		let tree = mixer.get_tree_mut(asset.to_owned(), id);
		let leaf1 = tree.generate_secrets();
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);
		let leaf1_js = JsValue::from_serde(&leaf1.to_bytes()).unwrap();

		let arr = Array::new();
		arr.push(&leaf1_js);
		arr.push(&JsValue::from_serde(&leaf2.to_bytes()).unwrap());
		arr.push(&JsValue::from_serde(&leaf3.to_bytes()).unwrap());
		let list = JsValue::from(arr);

		mixer.add_leaves(asset.to_owned(), id, list);
		let root = mixer.get_root(asset.to_owned(), id);

		let proof = mixer.generate_proof(asset.to_owned(), id, root, leaf1_js);
		let comms = proof.get(&JsValue::from_str("comms"));
		// let nullifier_hash = proof.get(&JsValue::from_str("nullifier_hash"));
		let leaf_index_comms = proof.get(&JsValue::from_str("leaf_index_comms"));
		let proof_comms = proof.get(&JsValue::from_str("proof_comms"));
		// let proof = proof.get(&JsValue::from_str("proof"));

		let comms_arr = Array::from(&comms);
		let leaf_index_comms_arr = Array::from(&leaf_index_comms);
		let proof_comms_arr = Array::from(&proof_comms);

		assert_eq!(comms_arr.length(), 3);
		assert_eq!(leaf_index_comms_arr.length(), 2);
		assert_eq!(proof_comms_arr.length(), 2);

		// Left for debugging purposes
		// assert_eq!(nullifier_hash, 0);
		// assert_eq!(proof, 0);
	}
}
