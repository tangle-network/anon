#![allow(clippy::vec_init_then_push)]

use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use curve25519_gadgets::{
	fixed_deposit_tree::builder::{FixedDepositTree, FixedDepositTreeBuilder},
	poseidon::{
		builder::{Poseidon, PoseidonBuilder},
		gen_mds_matrix, gen_round_keys, PoseidonSbox,
	},
};
use js_sys::{Array, JsString, Map, Uint8Array};
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

#[derive(Debug, PartialEq)]
pub enum OperationCode {
	Unknown = 0,
	// Invalid hex string length when decoding
	InvalidHexLength = 1,
	// Failed to parse hex string
	HexParsingFailed = 2,
	// Invalid number of note parts when decoding
	InvalidNoteLength = 3,
	// Invalid note prefix
	InvalidNotePrefix = 4,
	// Invalid note version
	InvalidNoteVersion = 5,
	// Invalid note id when parsing
	InvalidNoteId = 6,
	// Invalid note block number when parsing
	InvalidNoteBlockNumber = 7,
	// Invalid note secrets
	InvalidNoteSecrets = 8,
	// Unable to find merkle tree
	MerkleTreeNotFound = 9,
	// Failed serialization of passed params
	// Error for failing to parse rust type into JsValue
	SerializationFailed = 10,
	// Failed deserialization of JsValue into rust type
	DeserializationFailed = 11,
}

#[wasm_bindgen]
pub struct PoseidonHasherOptions {
	/// The size of the permutation, in field elements.
	width: usize,
	/// Number of full SBox rounds in beginning
	pub full_rounds_beginning: Option<usize>,
	/// Number of full SBox rounds in end
	pub full_rounds_end: Option<usize>,
	/// Number of partial rounds
	pub partial_rounds: Option<usize>,
	/// The desired (classical) security level, in bits.
	pub security_bits: Option<usize>,
	/// Bulletproof generators for proving/verifying (serialized)
	#[wasm_bindgen(skip)]
	pub bp_gens: Option<BulletproofGens>,
}

impl Default for PoseidonHasherOptions {
	fn default() -> Self {
		Self {
			width: 6,
			full_rounds_beginning: None,
			full_rounds_end: None,
			partial_rounds: None,
			security_bits: None,
			bp_gens: None,
		}
	}
}

#[wasm_bindgen]
impl PoseidonHasherOptions {
	#[wasm_bindgen(constructor)]
	pub fn new() -> Self {
		Self::default()
	}

	#[wasm_bindgen(setter)]
	pub fn set_bp_gens(&mut self, value: Uint8Array) {
		let bp_gens: BulletproofGens =
			bincode::deserialize(&value.to_vec()).unwrap_or_else(|_| BulletproofGens::new(4096, 1));
		self.bp_gens = Some(bp_gens);
	}

	#[wasm_bindgen(getter)]
	pub fn bp_gens(&self) -> Uint8Array {
		let val = self.bp_gens.clone().unwrap_or_else(|| BulletproofGens::new(4096, 1));
		let serialized = bincode::serialize(&val).unwrap_or_else(|_| Vec::new());
		Uint8Array::from(serialized.as_slice())
	}
}

#[wasm_bindgen]
pub struct PoseidonHasher {
	inner: Poseidon,
}

#[wasm_bindgen]
impl PoseidonHasher {
	pub fn default() -> Self {
		Self::with_options(Default::default())
	}

	#[wasm_bindgen(constructor)]
	pub fn with_options(opts: PoseidonHasherOptions) -> Self {
		let full_rounds_beginning = opts.full_rounds_beginning.unwrap_or(4);
		let full_rounds_end = opts.full_rounds_end.unwrap_or(4);
		let partial_rounds = opts.partial_rounds.unwrap_or(57);

		// default pedersen genrators
		let pc_gens = PedersenGens::default();
		let bp_gens = opts.bp_gens.clone().unwrap_or_else(|| BulletproofGens::new(4096, 1));

		let total_rounds = full_rounds_beginning + full_rounds_end + partial_rounds;
		let inner = PoseidonBuilder::new(opts.width)
			.num_rounds(full_rounds_beginning, full_rounds_end, partial_rounds)
			.round_keys(gen_round_keys(opts.width, total_rounds))
			.mds_matrix(gen_mds_matrix(opts.width))
			.sbox(PoseidonSbox::Inverse)
			.bulletproof_gens(bp_gens)
			.pedersen_gens(pc_gens)
			.build();
		Self { inner }
	}
}

impl OperationCode {
	fn into_js(self) -> JsValue {
		JsValue::from(self as u8)
	}
}

// Decodes hex string into byte array
pub fn decode_hex(s: &str) -> Result<[u8; 32], OperationCode> {
	if s.len() != 64 {
		return Err(OperationCode::InvalidHexLength);
	}
	let arr: Result<Vec<u8>, OperationCode> = (0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| OperationCode::HexParsingFailed))
		.collect();
	let mut buf: [u8; 32] = [0u8; 32];
	buf.copy_from_slice(&arr?[..]);
	Ok(buf)
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
	fn get_tree_mut(&mut self, asset: String, id: u8) -> Result<&mut FixedDepositTree, OperationCode> {
		self.tree_map
			.get_mut(&(asset, id))
			.ok_or(OperationCode::MerkleTreeNotFound)
	}

	fn get_tree(&self, asset: String, id: u8) -> Result<&FixedDepositTree, OperationCode> {
		self.tree_map.get(&(asset, id)).ok_or(OperationCode::MerkleTreeNotFound)
	}
}

// Implementation available to JS
#[wasm_bindgen]
impl Mixer {
	#[wasm_bindgen(constructor)]
	pub fn new(trees_js: JsValue, poseidon: PoseidonHasher) -> Result<Mixer, JsValue> {
		let trees: Vec<(String, u8, usize)> = trees_js
			.into_serde()
			.map_err(|_| OperationCode::DeserializationFailed.into_js())?;
		let mut tree_map = HashMap::new();
		for (asset, id, depth) in trees {
			tree_map.insert(
				(asset, id),
				FixedDepositTreeBuilder::new()
					.hash_params(poseidon.inner.clone())
					.depth(depth)
					.build(),
			);
		}
		Ok(Mixer { tree_map })
	}

	pub fn add_leaves(&mut self, asset: String, id: u8, leaves: JsValue, target_root: JsValue) -> Result<(), JsValue> {
		let fixed_tree = self.get_tree_mut(asset, id).map_err(|e| e.into_js())?;
		let leaves_bytes: Vec<[u8; 32]> = leaves
			.into_serde()
			.map_err(|_| OperationCode::DeserializationFailed.into_js())?;
		let root_option = if target_root.is_null() || target_root.is_undefined() {
			None
		} else {
			target_root
				.into_serde()
				.map_err(|_| OperationCode::DeserializationFailed.into_js())?
		};
		fixed_tree.tree.add_leaves(leaves_bytes, root_option);
		Ok(())
	}

	pub fn get_root(&self, asset: String, id: u8) -> Result<JsValue, JsValue> {
		let fixed_tree = self.get_tree(asset, id).map_err(|e| e.into_js())?;
		JsValue::from_serde(&fixed_tree.tree.root.to_bytes()).map_err(|_| OperationCode::SerializationFailed.into_js())
	}

	// Generates a new note with random samples
	// note has a format of:
	// `webb.mix-[version]-[asset]-[mixed_id]-[block_number]-[r_hex][nullifier_hex]`
	pub fn generate_note(&mut self, asset: String, id: u8, block_number: Option<u32>) -> Result<JsString, JsValue> {
		let fixed_tree = self.get_tree_mut(asset.to_owned(), id).map_err(|e| e.into_js())?;
		let leaf = fixed_tree.generate_secrets();
		let (r, nullifier, ..) = fixed_tree.get_secrets(leaf);

		let encoded_r = encode_hex(r.to_bytes());
		let encoded_nullifier = encode_hex(nullifier.to_bytes());
		let mut parts: Vec<String> = Vec::new();
		parts.push(NOTE_PREFIX.to_string());
		parts.push(VERSION.to_string());
		parts.push(asset);
		parts.push(format!("{}", id));
		if let Some(bn) = block_number {
			parts.push(format!("{}", bn));
		}
		parts.push(format!("{}{}", encoded_r, encoded_nullifier));
		let note = parts.join("-");
		let note_js = JsString::from(note);

		Ok(note_js)
	}

	// Saving the note to a memory.
	// First it checks if the note is in valid format,
	// then decodes it and saves a note to a Merkle Client
	// to be used for constructing the proof
	pub fn save_note(&mut self, note_js: JsString) -> Result<Map, JsValue> {
		let note: String = note_js.into();

		let parts: Vec<&str> = note.split('-').collect();
		let partial = parts.len() == 5;
		let full = parts.len() == 6;
		if !partial && !full {
			return Err(OperationCode::InvalidNoteLength.into_js());
		}

		if parts[0] != NOTE_PREFIX {
			return Err(OperationCode::InvalidNotePrefix.into_js());
		}
		if parts[1] != VERSION {
			return Err(OperationCode::InvalidNoteVersion.into_js());
		}
		let asset: String = parts[2].to_string();
		let id = parts[3].parse().map_err(|_| OperationCode::InvalidNoteId.into_js())?;
		let (block_number, note_val) = match partial {
			true => (None, parts[4]),
			false => {
				let bn = parts[4]
					.parse::<u32>()
					.map_err(|_| OperationCode::InvalidNoteBlockNumber.into_js())?;
				(Some(bn), parts[5])
			}
		};
		if note_val.len() != 128 {
			return Err(OperationCode::InvalidNoteSecrets.into_js());
		}
		if !self.tree_map.contains_key(&(asset.to_owned(), id)) {
			return Err(OperationCode::InvalidNoteSecrets.into_js());
		}

		// Checking the validity
		let r_bytes = decode_hex(&note_val[..64]).map_err(|e| e.into_js())?;
		let nullifier_bytes = decode_hex(&note_val[64..]).map_err(|e| e.into_js())?;

		let tree = self.get_tree_mut(asset.to_owned(), id).map_err(|e| e.into_js())?;
		let (r, nullifier, nullifier_hash, leaf) = tree.leaf_data_from_bytes(r_bytes, nullifier_bytes);
		tree.add_secrets(leaf, r, nullifier, nullifier_hash);

		let map = Map::new();
		let leaf_js: JsValue =
			JsValue::from_serde(&leaf.to_bytes()).map_err(|_| OperationCode::SerializationFailed.into_js())?;
		let asset_js = JsValue::from(&asset);
		let id_js = JsValue::from(id);

		if let Some(bn) = block_number {
			let block_number_js = JsValue::from(bn);
			map.set(&JsValue::from_str("block_number"), &block_number_js);
		}

		map.set(&JsValue::from_str("leaf"), &leaf_js);
		map.set(&JsValue::from_str("asset"), &asset_js);
		map.set(&JsValue::from_str("id"), &id_js);
		Ok(map)
	}

	// Generates zk proof
	pub fn generate_proof(
		&self,
		asset: String,
		id: u8,
		root_json: JsValue,
		leaf_json: JsValue,
	) -> Result<Map, JsValue> {
		let root_bytes: [u8; 32] = root_json
			.into_serde()
			.map_err(|_| OperationCode::DeserializationFailed.into_js())?;
		let leaf_bytes: [u8; 32] = leaf_json
			.into_serde()
			.map_err(|_| OperationCode::DeserializationFailed.into_js())?;
		let tree = self.get_tree(asset, id).map_err(|e| e.into_js())?;
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
			let bit_js = JsValue::from_serde(&com.0).map_err(|_| OperationCode::SerializationFailed.into_js())?;
			leaf_index_comms_js.push(&bit_js);
		}
		let proof_comms_js = Array::new();
		for com in proof_comms {
			let node = JsValue::from_serde(&com.0).map_err(|_| OperationCode::SerializationFailed.into_js())?;
			proof_comms_js.push(&node);
		}
		let comms_js = Array::new();
		for com in comms {
			let val = JsValue::from_serde(&com.0).map_err(|_| OperationCode::SerializationFailed.into_js())?;
			comms_js.push(&val);
		}

		let nullifier_hash = JsValue::from_serde(&nullifier_hash.to_bytes())
			.map_err(|_| OperationCode::SerializationFailed.into_js())?;
		let bytes = JsValue::from_serde(&proof.to_bytes()).map_err(|_| OperationCode::SerializationFailed.into_js())?;

		let map = Map::new();
		map.set(&JsValue::from_str("comms"), &comms_js);
		map.set(&JsValue::from_str("nullifier_hash"), &nullifier_hash);
		map.set(&JsValue::from_str("leaf_index_comms"), &leaf_index_comms_js);
		map.set(&JsValue::from_str("proof_comms"), &proof_comms_js);
		map.set(&JsValue::from_str("proof"), &bytes);

		Ok(map)
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
		let dec = decode_hex(&enc).unwrap();

		assert!(dec == num.to_bytes());
	}

	#[wasm_bindgen_test]
	fn should_return_proper_errors() {
		let asset = "EDG";
		let id = 0;
		let depth = 2;
		let arr = Array::new();
		arr.push(&JsString::from(asset));
		arr.push(&JsValue::from(id));
		arr.push(&JsValue::from(depth));
		let top_level_arr = Array::new();
		top_level_arr.push(&arr);
		let js_trees = JsValue::from(top_level_arr);
		let mut mixer = Mixer::new(js_trees, PoseidonHasher::default()).unwrap();

		let invalid_leafs = JsValue::from(1);
		let leaf_res = mixer.add_leaves(asset.to_string(), id, invalid_leafs, JsValue::NULL);
		assert_eq!(leaf_res.err().unwrap(), JsValue::from(11));

		let invalid_asset = "foo".to_string();
		let tree_res = mixer.get_tree(invalid_asset, id);
		assert_eq!(tree_res.err().unwrap(), OperationCode::MerkleTreeNotFound);
	}

	#[wasm_bindgen_test]
	fn should_have_correct_root() {
		let asset = "EDG";
		let id = 0;
		let depth = 2;
		let arr = Array::new();
		arr.push(&JsString::from(asset));
		arr.push(&JsValue::from(id));
		arr.push(&JsValue::from(depth));
		let top_level_arr = Array::new();
		top_level_arr.push(&arr);
		let js_trees = JsValue::from(top_level_arr);
		let mut mixer = Mixer::new(js_trees, PoseidonHasher::default()).unwrap();
		let leaf1 = Scalar::from(1u32);
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);
		let zero = Scalar::zero();

		let arr = Array::new();
		arr.push(&JsValue::from_serde(&leaf1.to_bytes()).unwrap());
		arr.push(&JsValue::from_serde(&leaf2.to_bytes()).unwrap());
		arr.push(&JsValue::from_serde(&leaf3.to_bytes()).unwrap());
		let list = JsValue::from(arr);

		mixer.add_leaves(asset.to_owned(), id, list, JsValue::NULL).unwrap();
		let tree = mixer.get_tree(asset.to_owned(), id).unwrap();
		let node1 = Poseidon_hash_2(leaf1, leaf2, &tree.hash_params);
		let node2 = Poseidon_hash_2(leaf3, zero, &tree.hash_params);
		let root = Poseidon_hash_2(node1, node2, &tree.hash_params);

		let calc_root_js = mixer.get_root(asset.to_owned(), id).unwrap();
		let calc_root: [u8; 32] = calc_root_js.into_serde().unwrap();
		assert_eq!(calc_root, root.to_bytes());
	}

	#[wasm_bindgen_test]
	fn should_generate_and_save_note() {
		let asset = "EDG";
		let id = 0;
		let depth = 2;
		let arr = Array::new();
		arr.push(&JsString::from(asset));
		arr.push(&JsValue::from(id));
		arr.push(&JsValue::from(depth));
		let top_level_arr = Array::new();
		top_level_arr.push(&arr);
		let js_trees = JsValue::from(top_level_arr);
		let mut mixer = Mixer::new(js_trees, PoseidonHasher::default()).unwrap();

		// Partial note
		let note_js = mixer.generate_note(asset.to_owned(), id, None).unwrap();
		let note_map = mixer.save_note(note_js).unwrap();

		let id_js = note_map.get(&JsValue::from("id"));
		let asset_js = note_map.get(&JsValue::from("asset"));
		let block_number_js = note_map.get(&JsValue::from("block_number"));

		let id_res: u8 = id_js.into_serde().unwrap();
		let asset_res: String = asset_js.into_serde().unwrap();

		assert_eq!(id_res, id);
		assert_eq!(asset_res, asset);
		assert!(block_number_js.is_undefined());

		// Complete note
		let note_js = mixer.generate_note(asset.to_owned(), id, Some(1)).unwrap();
		let note_map = mixer.save_note(note_js).unwrap();

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
		let asset = "EDG";
		let id = 0;
		let depth = 2;
		let arr = Array::new();
		arr.push(&JsString::from(asset));
		arr.push(&JsValue::from(id));
		arr.push(&JsValue::from(depth));
		let top_level_arr = Array::new();
		top_level_arr.push(&arr);
		let js_trees = JsValue::from(top_level_arr);
		let mut mixer = Mixer::new(js_trees, PoseidonHasher::default()).unwrap();
		let tree = mixer.get_tree_mut(asset.to_owned(), id).unwrap();
		let leaf1 = tree.generate_secrets();
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);
		let leaf1_js = JsValue::from_serde(&leaf1.to_bytes()).unwrap();

		let arr = Array::new();
		arr.push(&leaf1_js);
		arr.push(&JsValue::from_serde(&leaf2.to_bytes()).unwrap());
		arr.push(&JsValue::from_serde(&leaf3.to_bytes()).unwrap());
		let list = JsValue::from(arr);

		mixer.add_leaves(asset.to_owned(), id, list, JsValue::NULL).unwrap();
		let root = mixer.get_root(asset.to_owned(), id).unwrap();

		let proof = mixer.generate_proof(asset.to_owned(), id, root, leaf1_js).unwrap();
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

	#[wasm_bindgen_test]
	fn should_create_proof_with_older_target_root() {
		let asset = "EDG";
		let id = 0;
		let depth = 2;
		let arr = Array::new();
		arr.push(&JsString::from(asset));
		arr.push(&JsValue::from(id));
		arr.push(&JsValue::from(depth));
		let top_level_arr = Array::new();
		top_level_arr.push(&arr);
		let js_trees = JsValue::from(top_level_arr);
		let mut mixer = Mixer::new(js_trees, PoseidonHasher::default()).unwrap();
		let tree = mixer.get_tree_mut(asset.to_owned(), id).unwrap();
		let leaf1 = tree.generate_secrets();
		let leaf2 = Scalar::from(2u32);
		let leaf3 = Scalar::from(3u32);
		let leaf1_js = JsValue::from_serde(&leaf1.to_bytes()).unwrap();

		let arr = Array::new();
		arr.push(&leaf1_js);
		arr.push(&JsValue::from_serde(&leaf2.to_bytes()).unwrap());
		arr.push(&JsValue::from_serde(&leaf3.to_bytes()).unwrap());
		let list = JsValue::from(arr);

		mixer.add_leaves(asset.to_owned(), id, list, JsValue::NULL).unwrap();
		let root = mixer.get_root(asset.to_owned(), id).unwrap();

		let arr = Array::new();
		arr.push(&JsValue::from_serde(&Scalar::from(4u32).to_bytes()).unwrap());
		arr.push(&JsValue::from_serde(&Scalar::from(5u32).to_bytes()).unwrap());
		let list = JsValue::from(arr);
		// Attempt to add more leaves even with older target root
		mixer.add_leaves(asset.to_owned(), id, list, root.clone()).unwrap();

		let should_be_same_root = mixer.get_root(asset.to_owned(), id).unwrap();
		assert_eq!(
			root.into_serde::<[u8; 32]>().unwrap(),
			should_be_same_root.into_serde::<[u8; 32]>().unwrap()
		);

		let proof = mixer.generate_proof(asset.to_owned(), id, root, leaf1_js).unwrap();
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
	}
}
