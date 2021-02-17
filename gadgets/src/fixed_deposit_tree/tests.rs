use crate::fixed_deposit_tree::batched_commit_for_verifier;
use crate::fixed_deposit_tree::batched_fixed_deposit_tree_verif_gadget;
use crate::fixed_deposit_tree::{TransactionCommitment, Transaction};
use crate::{
	fixed_deposit_tree::fixed_deposit_tree_verif_gadget,
	poseidon::{
		allocate_statics_for_prover, allocate_statics_for_verifier, gen_mds_matrix, gen_round_keys, sbox::PoseidonSbox,
		PoseidonBuilder, Poseidon_hash_2,
	},
	smt::builder::{SparseMerkleTreeBuilder, DEFAULT_TREE_DEPTH},
	utils::{get_bits, AllocatedScalar},
};
use bulletproofs::{
	r1cs::{Prover, Verifier},
	BulletproofGens, PedersenGens,
};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::OsRng;

// For benchmarking
#[cfg(feature = "std")]
use std::time::Instant;

#[test]
fn test_fixed_deposit_tree_verification() {
	let width = 6;
	let (full_b, full_e) = (4, 4);
	let partial_rounds = 57;
	let total_rounds = full_b + partial_rounds + full_e;
	let p_params = PoseidonBuilder::new(width)
		.num_rounds(full_b, full_e, partial_rounds)
		.round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
		.mds_matrix(gen_mds_matrix(width))
		.sbox(PoseidonSbox::Inverse)
		.build();

	let mut test_rng = OsRng::default();
	let r = Scalar::random(&mut test_rng);
	let nullifier = Scalar::random(&mut test_rng);
	let expected_output = Poseidon_hash_2(r, nullifier, &p_params);
	let nullifier_hash = Poseidon_hash_2(nullifier, nullifier, &p_params);

	let mut tree = SparseMerkleTreeBuilder::new().hash_params(p_params.clone()).build();

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

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(40960, 1);

	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(b"FixedDepositTree");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut comms = vec![];

		let (com_r, var_r) = prover.commit(r, Scalar::random(&mut test_rng));
		let r_alloc = AllocatedScalar {
			variable: var_r,
			assignment: Some(r),
		};
		comms.push(com_r);

		let (com_nullifier, var_nullifier) = prover.commit(nullifier, Scalar::random(&mut test_rng));
		let nullifier_alloc = AllocatedScalar {
			variable: var_nullifier,
			assignment: Some(nullifier),
		};
		comms.push(com_nullifier);

		let (com_leaf, var_leaf) = prover.commit(expected_output, Scalar::random(&mut test_rng));
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: Some(expected_output),
		};
		comms.push(com_leaf);

		let mut leaf_index_comms = vec![];
		let mut leaf_index_vars = vec![];
		let mut leaf_index_alloc_scalars = vec![];
		for b in get_bits(&k, DEFAULT_TREE_DEPTH).iter().take(tree.depth) {
			let val: Scalar = Scalar::from(*b as u8);
			let (c, v) = prover.commit(val.clone(), Scalar::random(&mut test_rng));
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
			let (c, v) = prover.commit(*p, Scalar::random(&mut test_rng));
			proof_comms.push(c);
			proof_vars.push(v);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(*p),
			});
		}

		let num_statics = 4;
		let statics = allocate_statics_for_prover(&mut prover, num_statics);

		let start = Instant::now();
		assert!(fixed_deposit_tree_verif_gadget(
			&mut prover,
			tree.depth,
			&tree.root,
			&nullifier_hash,
			r_alloc,
			nullifier_alloc,
			leaf_alloc_scalar,
			leaf_index_alloc_scalars,
			proof_alloc_scalars,
			statics,
			&p_params.clone(),
		)
		.is_ok());

		println!(
			"For binary tree of height {} and Poseidon rounds {}, no of multipliers is {} and constraints is {}",
			tree.depth,
			total_rounds,
			&prover.num_multipliers(),
			&prover.num_constraints()
		);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		let end = start.elapsed();

		println!("Proving time is {:?}", end);

		(proof, (comms, leaf_index_comms, proof_comms))
	};

	let mut verifier_transcript = Transcript::new(b"FixedDepositTree");
	let mut verifier = Verifier::new(&mut verifier_transcript);
	let r_val = verifier.commit(commitments.0[0]);
	let nullifier_val = verifier.commit(commitments.0[1]);
	let r_alloc = AllocatedScalar {
		variable: r_val,
		assignment: None,
	};
	let nullifier_alloc = AllocatedScalar {
		variable: nullifier_val,
		assignment: None,
	};

	let var_leaf = verifier.commit(commitments.0[2]);
	let leaf_alloc_scalar = AllocatedScalar {
		variable: var_leaf,
		assignment: None,
	};

	let mut leaf_index_alloc_scalars = vec![];
	for l in commitments.1 {
		let v = verifier.commit(l);
		leaf_index_alloc_scalars.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let mut proof_alloc_scalars = vec![];
	for p in commitments.2 {
		let v = verifier.commit(p);
		proof_alloc_scalars.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let num_statics = 4;
	let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

	let start = Instant::now();
	assert!(fixed_deposit_tree_verif_gadget(
		&mut verifier,
		tree.depth,
		&tree.root,
		&nullifier_hash,
		r_alloc,
		nullifier_alloc,
		leaf_alloc_scalar,
		leaf_index_alloc_scalars,
		proof_alloc_scalars,
		statics,
		&p_params,
	)
	.is_ok());

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}

#[test]
fn test_batched_verif() {
	let width = 6;
	let (full_b, full_e) = (4, 4);
	let partial_rounds = 57;
	let total_rounds = full_b + partial_rounds + full_e;
	let p_params = PoseidonBuilder::new(width)
		.num_rounds(full_b, full_e, partial_rounds)
		.round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
		.mds_matrix(gen_mds_matrix(width))
		.sbox(PoseidonSbox::Inverse)
		.build();

	let mut test_rng = OsRng::default();
	let mut rs = Vec::new();
	let mut nullifiers = Vec::new();
	let mut expected_outputs = Vec::new();
	let mut nullifier_hashes = Vec::new();
	// batch 3 proofs
	let indices = vec![7,8,9];

	for _ in 0..indices.len() {
		let r = Scalar::random(&mut test_rng);
		let nullifier = Scalar::random(&mut test_rng);
		let expected_output = Poseidon_hash_2(r, nullifier, &p_params);
		let nullifier_hash = Poseidon_hash_2(nullifier, nullifier, &p_params);

		rs.push(r);
		nullifiers.push(nullifier);
		expected_outputs.push(expected_output);
		nullifier_hashes.push(nullifier_hash);
	}

	let mut tree = SparseMerkleTreeBuilder::new().hash_params(p_params.clone()).build();

	for i in 1..=10 {
		let index = Scalar::from(i as u32);
		let s = if i == 7 {
			expected_outputs[0]
		} else if i == 8 {
			expected_outputs[1]
		} else if i== 9 {
			expected_outputs[2]
		} else {
			index
		};

		tree.update(index, s);
	}

	let mut merkle_proof_vecs = Vec::new();
	let mut merkle_proofs = Vec::new();
	let mut scalar_indices = Vec::new();

	for i in 0..indices.len() {
		let mut merkle_proof_vec = Vec::<Scalar>::new();
		let mut merkle_proof = Some(merkle_proof_vec);
		let k = Scalar::from(indices[i] as u32);
		assert_eq!(expected_outputs[i], tree.get(k, tree.root, &mut merkle_proof));
		merkle_proof_vec = merkle_proof.clone().unwrap();
		assert!(tree.verify_proof(k, expected_outputs[i], &merkle_proof_vec, None));
		assert!(tree.verify_proof(k, expected_outputs[i], &merkle_proof_vec, Some(&tree.root)));

		merkle_proof_vecs.push(merkle_proof_vec);
		merkle_proofs.push(merkle_proof);
		scalar_indices.push(k);
	}

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(40960, 1);

	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(b"BatchedFixedDepositTree");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut comms = vec![];
		let mut txes = vec![];

		for i in 0..indices.len() {
			let (com_r, var_r) = prover.commit(rs[i], Scalar::random(&mut test_rng));
			let r_alloc = AllocatedScalar {
				variable: var_r,
				assignment: Some(rs[i]),
			};

			let (com_nullifier, var_nullifier) = prover.commit(nullifiers[i], Scalar::random(&mut test_rng));
			let nullifier_alloc = AllocatedScalar {
				variable: var_nullifier,
				assignment: Some(nullifiers[i]),
			};

			let (com_leaf, var_leaf) = prover.commit(expected_outputs[i], Scalar::random(&mut test_rng));
			let leaf_alloc_scalar = AllocatedScalar {
				variable: var_leaf,
				assignment: Some(expected_outputs[i]),
			};

			let mut leaf_index_comms = vec![];
			let mut leaf_index_vars = vec![];
			let mut leaf_index_alloc_scalars = vec![];
			for b in get_bits(&scalar_indices[i], DEFAULT_TREE_DEPTH).iter().take(tree.depth) {
				let val: Scalar = Scalar::from(*b as u8);
				let (c, v) = prover.commit(val.clone(), Scalar::random(&mut test_rng));
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
			for p in merkle_proof_vecs[i].iter() {
				let (c, v) = prover.commit(*p, Scalar::random(&mut test_rng));
				proof_comms.push(c);
				proof_vars.push(v);
				proof_alloc_scalars.push(AllocatedScalar {
					variable: v,
					assignment: Some(*p),
				});
			}

			let tx_comm = TransactionCommitment {
				root: tree.root,
				nullifier_hash: nullifier_hashes[i],
				r: com_r,
				nullifier: com_nullifier,
				leaf_val: com_leaf,
				leaf_index_bits: leaf_index_comms,
				proof_nodes: proof_comms,				
			};

			comms.push(tx_comm);

			let tx = Transaction {
				root: tree.root,
				nullifier_hash: nullifier_hashes[i],
				r: r_alloc,
				nullifier: nullifier_alloc,
				leaf_val: leaf_alloc_scalar,
				leaf_index_bits: leaf_index_alloc_scalars,
				proof_nodes: proof_alloc_scalars,				
			};

			txes.push(tx);
		}

		let num_statics = 4;
		let statics = allocate_statics_for_prover(&mut prover, num_statics);

		let start = Instant::now();
		assert!(batched_fixed_deposit_tree_verif_gadget(
			&mut prover,
			tree.depth,
			txes,
			statics,
			&p_params.clone(),
		)
		.is_ok());

		println!(
			"For binary tree of height {} and Poseidon rounds {}, no of multipliers is {} and constraints is {}",
			tree.depth,
			total_rounds,
			&prover.num_multipliers(),
			&prover.num_constraints()
		);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		let end = start.elapsed();

		println!("Proving time is {:?}", end);

		(proof, comms)
	};

	let mut verifier_transcript = Transcript::new(b"BatchedFixedDepositTree");
	let mut verifier = Verifier::new(&mut verifier_transcript);
	let txes = batched_commit_for_verifier(&mut verifier, commitments);

	let num_statics = 4;
	let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

	let start = Instant::now();
	assert!(batched_fixed_deposit_tree_verif_gadget(
		&mut verifier,
		tree.depth,
		txes,
		statics,
		&p_params,
	)
	.is_ok());

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}
