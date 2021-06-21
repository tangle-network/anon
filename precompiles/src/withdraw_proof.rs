use super::encoding::{Decode, Encode};
use bulletproofs::r1cs::{R1CSProof, Verifier};
use bulletproofs_gadgets::{
	fixed_deposit_tree::mixer_verif_gadget,
	poseidon::{allocate_statics_for_verifier, builder::Poseidon},
	utils::AllocatedScalar,
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use evm_runtime::ExitError;
use merlin::Transcript;
use rand_chacha::rand_core::{CryptoRng, RngCore};
use sp_std::prelude::Vec;

#[derive(Debug)]
pub struct WithdrawProof {
	pub depth: u8,
	pub private_inputs: Vec<CompressedRistretto>,
	pub node_private_inputs: Vec<CompressedRistretto>,
	pub index_private_inputs: Vec<CompressedRistretto>,
	pub root: Scalar,
	pub nullifier_hash: Scalar,
	pub recipient: Scalar,
	pub relayer: Scalar,
	pub proof: R1CSProof,
}

impl WithdrawProof {
	pub fn verify<T: RngCore + CryptoRng>(&self, hasher: &Poseidon, rng: &mut T) -> Result<(), ExitError> {
		let label = b"zk_membership_proof";
		let mut verifier_transcript = Transcript::new(label);
		let mut verifier = Verifier::new(&mut verifier_transcript);

		if self.private_inputs.len() != 3 {
			return Err(ExitError::Other("InvalidPrivateInputs".into()));
		}
		let r_val = verifier.commit(self.private_inputs[0]);
		let r_alloc = AllocatedScalar {
			variable: r_val,
			assignment: None,
		};
		let nullifier_val = verifier.commit(self.private_inputs[1]);
		let nullifier_alloc = AllocatedScalar {
			variable: nullifier_val,
			assignment: None,
		};

		let var_leaf = verifier.commit(self.private_inputs[2]);
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: None,
		};

		let mut leaf_index_alloc_scalars = vec![];
		for l in &self.index_private_inputs {
			let v = verifier.commit(*l);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let mut proof_alloc_scalars = vec![];
		for p in &self.node_private_inputs {
			let v = verifier.commit(*p);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let num_statics = 4;
		let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &hasher.pc_gens);
		let gadget_res = mixer_verif_gadget(
			&mut verifier,
			&self.recipient,
			&self.relayer,
			self.depth as usize,
			&self.root,
			&self.nullifier_hash,
			r_alloc,
			nullifier_alloc,
			leaf_alloc_scalar,
			leaf_index_alloc_scalars,
			proof_alloc_scalars,
			statics,
			&hasher,
		);
		if !gadget_res.is_ok() {
			return Err(ExitError::Other("ConstraintSystemUnsatisfied".into()));
		}

		let verify_res = verifier.verify_with_rng(&self.proof, &hasher.pc_gens, &hasher.bp_gens, rng);
		if !verify_res.is_ok() {
			return Err(ExitError::Other("ZkVerificationFailed".into()));
		}
		Ok(())
	}
}

impl Decode for WithdrawProof {
	fn decode(input: &mut Vec<u8>) -> Result<Self, String> {
		let depth = u8::decode(input)?;

		// private inputs
		let private_input_bytes1 = <[u8; 32] as Decode>::decode(input)?;
		let private_input_bytes2 = <[u8; 32] as Decode>::decode(input)?;
		let private_input_bytes3 = <[u8; 32] as Decode>::decode(input)?;

		// path private inputs
		let mut nodes_bytes = Vec::new();
		for _ in 0..depth {
			let node = <[u8; 32] as Decode>::decode(input)?;
			nodes_bytes.push(node);
		}
		let mut index_bytes = Vec::new();
		for _ in 0..depth {
			let index = <[u8; 32] as Decode>::decode(input)?;
			index_bytes.push(index);
		}

		// public inputs
		let root_bytes = <[u8; 32] as Decode>::decode(input)?;
		let nullifier_hash_bytes = <[u8; 32] as Decode>::decode(input)?;
		let recipient_bytes = <[u8; 32] as Decode>::decode(input)?;
		let relayer_bytes = <[u8; 32] as Decode>::decode(input)?;

		// Taking the rest of bytes for R1CSProof
		let proof_vec = <Vec<u8>>::decode(input)?;

		// Convering to Bulletproofs types
		// private inputs
		let private_input1 = CompressedRistretto::from_slice(&private_input_bytes1);
		let private_input2 = CompressedRistretto::from_slice(&private_input_bytes2);
		let private_input3 = CompressedRistretto::from_slice(&private_input_bytes3);
		let private_inputs = vec![private_input1, private_input2, private_input3];

		// path private inputs
		let nodes = nodes_bytes.iter().map(|x| CompressedRistretto::from_slice(x)).collect();
		let indicies = index_bytes.iter().map(|x| CompressedRistretto::from_slice(x)).collect();

		// public inputs
		let root = Scalar::from_bytes_mod_order(root_bytes);
		let nullifier_hash = Scalar::from_bytes_mod_order(nullifier_hash_bytes);
		let recipient = Scalar::from_bytes_mod_order(recipient_bytes);
		let relayer = Scalar::from_bytes_mod_order(relayer_bytes);

		// proof
		let proof = R1CSProof::from_bytes(&proof_vec).map_err(|_| "Invalid proof bytes")?;

		Ok(WithdrawProof {
			depth,
			root,
			private_inputs,
			nullifier_hash,
			node_private_inputs: nodes,
			index_private_inputs: indicies,
			recipient,
			relayer,
			proof,
		})
	}
}

impl Encode for WithdrawProof {
	fn size_hint(&self) -> usize {
		// 3 private inputs + 4 public inputs
		let inputs_size = 32 * 7;
		let path_size = self.depth as usize * 64;
		let proof_size = self.proof.serialized_size();
		inputs_size + path_size + proof_size
	}

	fn encode(&self) -> Vec<u8> {
		let mut encoded = Vec::with_capacity(self.size_hint());
		encoded.push(self.depth);

		// private inputs
		for private_input in &self.private_inputs {
			encoded.extend(&private_input.to_bytes());
		}
		// private path inputs
		for index_input in &self.index_private_inputs {
			encoded.extend(&index_input.to_bytes());
		}
		for node_input in &self.node_private_inputs {
			encoded.extend(&node_input.to_bytes());
		}
		// public inputs
		encoded.extend(&self.root.to_bytes());
		encoded.extend(&self.nullifier_hash.to_bytes());
		encoded.extend(&self.recipient.to_bytes());
		encoded.extend(&self.relayer.to_bytes());
		//proof
		encoded.extend(&self.proof.to_bytes());
		encoded
	}
}

#[cfg(test)]
pub mod test {
	use super::*;
	use crate::default_bulletproofs_poseidon_hasher;
	use bulletproofs::r1cs::Prover;
	use bulletproofs_gadgets::{
		poseidon::{allocate_statics_for_prover, Poseidon_hash_2},
		smt::builder::SparseMerkleTreeBuilder,
		utils::get_bits,
	};
	use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

	pub fn generate_proof_data<T: RngCore + CryptoRng>(
		test_rng: &mut T,
	) -> (
		u8,
		Vec<CompressedRistretto>,
		Vec<CompressedRistretto>,
		Vec<CompressedRistretto>,
		Scalar,
		Scalar,
		Scalar,
		Scalar,
		R1CSProof,
		Poseidon,
	) {
		let hasher = default_bulletproofs_poseidon_hasher();
		let recipient = Scalar::random(test_rng);
		let relayer = Scalar::random(test_rng);
		let r = Scalar::random(test_rng);
		let nullifier = Scalar::random(test_rng);
		let expected_output = Poseidon_hash_2(r, nullifier, &hasher);
		let nullifier_hash = Poseidon_hash_2(nullifier, nullifier, &hasher);

		let tree_depth = 30;
		let mut tree = SparseMerkleTreeBuilder::new()
			.hash_params(hasher.clone())
			.depth(tree_depth)
			.build();

		for i in 1..=10 {
			let index = Scalar::from(i as u32);
			let s = if i == 7 { expected_output } else { index };

			tree.update(index, s);
		}

		let mut merkle_proof_vec = Vec::<Scalar>::new();
		let mut merkle_proof = Some(merkle_proof_vec);
		let k = Scalar::from(7u32);
		assert_eq!(expected_output, tree.get(k, tree.root, &mut merkle_proof));
		merkle_proof_vec = merkle_proof.unwrap();
		assert!(tree.verify_proof(k, expected_output, &merkle_proof_vec, None));
		assert!(tree.verify_proof(k, expected_output, &merkle_proof_vec, Some(&tree.root)));

		let label = b"zk_membership_proof";
		let mut prover_transcript = Transcript::new(label);
		let mut prover = Prover::new(&hasher.pc_gens, &mut prover_transcript);

		let mut comms = vec![];

		let (com_r, var_r) = prover.commit(r, Scalar::random(test_rng));
		let r_alloc = AllocatedScalar {
			variable: var_r,
			assignment: Some(r),
		};
		comms.push(com_r);

		let (com_nullifier, var_nullifier) = prover.commit(nullifier, Scalar::random(test_rng));
		let nullifier_alloc = AllocatedScalar {
			variable: var_nullifier,
			assignment: Some(nullifier),
		};
		comms.push(com_nullifier);

		let (com_leaf, var_leaf) = prover.commit(expected_output, Scalar::random(test_rng));
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: Some(expected_output),
		};
		comms.push(com_leaf);

		let mut leaf_index_comms = vec![];
		let mut leaf_index_vars = vec![];
		let mut leaf_index_alloc_scalars = vec![];
		for b in get_bits(&k, tree_depth).iter().take(tree.depth) {
			let val: Scalar = Scalar::from(*b as u8);
			let (c, v) = prover.commit(val, Scalar::random(test_rng));
			leaf_index_comms.push(c);
			leaf_index_vars.push(v);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(val),
			});
		}

		let mut proof_comms = vec![];
		let mut proof_vars = vec![];
		let mut proof_alloc_scalars = vec![];
		for p in merkle_proof_vec.iter() {
			let (c, v) = prover.commit(*p, Scalar::random(test_rng));
			proof_comms.push(c);
			proof_vars.push(v);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(*p),
			});
		}

		let num_statics = 4;
		let statics = allocate_statics_for_prover(&mut prover, num_statics);

		assert!(mixer_verif_gadget(
			&mut prover,
			&recipient,
			&relayer,
			tree.depth,
			&tree.root,
			&nullifier_hash,
			r_alloc,
			nullifier_alloc,
			leaf_alloc_scalar,
			leaf_index_alloc_scalars,
			proof_alloc_scalars,
			statics,
			&hasher,
		)
		.is_ok());

		let proof = prover.prove_with_rng(&hasher.bp_gens, test_rng).unwrap();

		(
			tree_depth as u8,
			comms,
			leaf_index_comms,
			proof_comms,
			nullifier_hash,
			recipient,
			relayer,
			tree.root,
			proof,
			hasher,
		)
	}

	#[test]
	fn should_verify_proof() {
		let mut test_rng = ChaChaRng::from_seed([1u8; 32]);
		let (
			tree_depth,
			comms,
			leaf_index_comms,
			proof_comms,
			nullifier_hash,
			recipient,
			relayer,
			root,
			proof,
			poseidon,
		) = generate_proof_data(&mut test_rng);
		let withdraw_proof = WithdrawProof {
			depth: tree_depth,
			private_inputs: comms,
			index_private_inputs: leaf_index_comms,
			node_private_inputs: proof_comms,
			nullifier_hash,
			recipient,
			relayer,
			root,
			proof: proof.clone(),
		};

		let mut encoded_wp = withdraw_proof.encode();

		let decoded_wp = WithdrawProof::decode(&mut encoded_wp).unwrap();
		assert_eq!(decoded_wp.depth, tree_depth);
		assert_eq!(decoded_wp.proof.to_bytes(), proof.to_bytes());

		let verify_res = withdraw_proof.verify(&poseidon, &mut test_rng);
		assert!(verify_res.is_ok());
	}

	#[test]
	fn should_not_verify_invalid_proof() {
		let mut test_rng = ChaChaRng::from_seed([1u8; 32]);
		let (tree_depth, comms, leaf_index_comms, proof_comms, _, recipient, relayer, root, proof, poseidon) =
			generate_proof_data(&mut test_rng);
		let withdraw_proof = WithdrawProof {
			depth: tree_depth,
			private_inputs: comms,
			index_private_inputs: leaf_index_comms,
			node_private_inputs: proof_comms,
			// Invalid nullifier hash
			nullifier_hash: Scalar::random(&mut test_rng),
			recipient,
			relayer,
			root,
			proof: proof.clone(),
		};

		let mut encoded_wp = withdraw_proof.encode();

		let decoded_wp = WithdrawProof::decode(&mut encoded_wp).unwrap();
		assert_eq!(decoded_wp.depth, tree_depth);
		assert_eq!(decoded_wp.proof.to_bytes(), proof.to_bytes());

		let verify_res = withdraw_proof.verify(&poseidon, &mut test_rng);
		assert!(verify_res.is_err());
	}

	#[test]
	fn should_not_decode_invalid_proof() {
		let mut test_rng = ChaChaRng::from_seed([1u8; 32]);
		let (tree_depth, comms, leaf_index_comms, proof_comms, nullifier_hash, recipient, relayer, root, proof, _) =
			generate_proof_data(&mut test_rng);
		let withdraw_proof = WithdrawProof {
			depth: tree_depth,
			private_inputs: comms,
			index_private_inputs: leaf_index_comms,
			node_private_inputs: proof_comms,
			nullifier_hash,
			recipient,
			relayer,
			root,
			proof: proof.clone(),
		};

		let mut encoded_wp = withdraw_proof.encode();
		encoded_wp = encoded_wp.drain(encoded_wp.len() - 10..).collect();

		let decoded_wp = WithdrawProof::decode(&mut encoded_wp);
		assert!(decoded_wp.is_err());
	}
}
