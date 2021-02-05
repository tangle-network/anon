use super::{AllocatedInputCoin, AllocatedOutputCoin, AllocatedTimedDeposit, Transaction};
use crate::{
	poseidon::{
		allocate_statics_for_prover, allocate_statics_for_verifier, gen_mds_matrix, gen_round_keys, sbox::PoseidonSbox,
		PoseidonBuilder, Poseidon_hash_2, Poseidon_hash_4,
	},
	smt::builder::{SparseMerkleTreeBuilder, DEFAULT_TREE_DEPTH},
	time_based_rewarding::time_based_reward_verif_gadget,
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
fn test_time_based_reward_gadget_verification() {
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

	let mut deposit_tree = SparseMerkleTreeBuilder::new().hash_params(p_params.clone()).build();

	for i in 1..=10 {
		let index = Scalar::from(i as u32);
		let s = if i == 7 { expected_output } else { index };

		deposit_tree.update(index, s);
	}

	let mut merkle_proof_vec = Vec::<Scalar>::new();
	let mut merkle_proof = Some(merkle_proof_vec);
	let k = Scalar::from(7u32);
	assert_eq!(
		expected_output,
		deposit_tree.get(k, deposit_tree.root, &mut merkle_proof)
	);
	merkle_proof_vec = merkle_proof.unwrap();
	assert!(deposit_tree.verify_proof(k, expected_output, &merkle_proof_vec, None));
	assert!(deposit_tree.verify_proof(k, expected_output, &merkle_proof_vec, Some(&deposit_tree.root)));

	// compute hash for timing deposits/withdrawal lengths
	let deposit_block_number = Scalar::from(1u32);
	let current_block_number = Scalar::from(11u32);
	let timed_deposit_leaf_val = Poseidon_hash_2(expected_output, deposit_block_number, &p_params);

	let mut timed_tree = SparseMerkleTreeBuilder::new().hash_params(p_params.clone()).build();

	for i in 1..=10 {
		let index = Scalar::from(i as u32);
		let s = if i == 7 { timed_deposit_leaf_val } else { index };

		timed_tree.update(index, s);
	}

	let mut timed_merkle_proof_vec = Vec::<Scalar>::new();
	let mut timed_merkle_proof = Some(timed_merkle_proof_vec);
	assert_eq!(
		timed_deposit_leaf_val,
		timed_tree.get(k, timed_tree.root, &mut timed_merkle_proof)
	);
	timed_merkle_proof_vec = timed_merkle_proof.unwrap();
	assert!(timed_tree.verify_proof(k, timed_deposit_leaf_val, &timed_merkle_proof_vec, None));
	assert!(timed_tree.verify_proof(
		k,
		timed_deposit_leaf_val,
		&timed_merkle_proof_vec,
		Some(&timed_tree.root)
	));

	let output_1 = Scalar::from(5u32);
	let output_1_inverse = Scalar::from(5u32).invert();
	let output_1_rho = Scalar::random(&mut test_rng);
	let output_1_r = Scalar::random(&mut test_rng);
	let output_1_nullifier = Scalar::random(&mut test_rng);
	let _output_1_sn = Poseidon_hash_2(output_1_r, output_1_nullifier, &p_params);
	let output_1_cm = Poseidon_hash_4([output_1, output_1_rho, output_1_r, output_1_nullifier], &p_params);

	let output_2 = Scalar::from(5u32);
	let output_2_inverse = Scalar::from(5u32).invert();
	let output_2_rho = Scalar::random(&mut test_rng);
	let output_2_r = Scalar::random(&mut test_rng);
	let output_2_nullifier = Scalar::random(&mut test_rng);
	let _output_2_sn = Poseidon_hash_2(output_2_r, output_2_nullifier, &p_params);
	let output_2_cm = Poseidon_hash_4([output_2, output_2_rho, output_2_r, output_2_nullifier], &p_params);

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(40960, 1);

	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(b"RewardTree");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut input_comms = vec![];
		let mut timed_comms = vec![];
		let mut output_comms = vec![];

		let (com_input_r, var_input_r) = prover.commit(r.clone(), Scalar::random(&mut test_rng));
		let alloc_input_r = AllocatedScalar {
			variable: var_input_r,
			assignment: Some(r),
		};
		input_comms.push(com_input_r);
		let (com_input_nullifier, var_input_nullifier) =
			prover.commit(nullifier.clone(), Scalar::random(&mut test_rng));
		let alloc_input_nullifier = AllocatedScalar {
			variable: var_input_nullifier,
			assignment: Some(nullifier),
		};
		input_comms.push(com_input_nullifier);

		let (leaf_com, leaf_var) = prover.commit(expected_output, Scalar::random(&mut test_rng));
		let alloc_leaf_val = AllocatedScalar {
			variable: leaf_var,
			assignment: Some(expected_output),
		};
		input_comms.push(leaf_com);

		let mut input_leaf_index_comms = vec![];
		let mut leaf_index_vars = vec![];
		let mut leaf_index_alloc_scalars = vec![];
		for b in get_bits(&k, DEFAULT_TREE_DEPTH).iter().take(deposit_tree.depth) {
			let val: Scalar = Scalar::from(*b as u8);
			let (c, v) = prover.commit(val.clone(), Scalar::random(&mut test_rng));
			input_leaf_index_comms.push(c);
			leaf_index_vars.push(v);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(val),
			});
		}

		let mut input_proof_comms = vec![];
		let mut proof_vars = vec![];
		let mut proof_alloc_scalars = vec![];
		for p in merkle_proof_vec.iter() {
			let (c, v) = prover.commit(*p, Scalar::random(&mut test_rng));
			input_proof_comms.push(c);
			proof_vars.push(v);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(*p),
			});
		}

		let coin = AllocatedInputCoin {
			r: alloc_input_r,
			nullifier: alloc_input_nullifier,
			leaf_cm_val: alloc_leaf_val,
			leaf_index_bits: leaf_index_alloc_scalars,
			leaf_proof_nodes: proof_alloc_scalars,
			sn: nullifier_hash,
		};

		let (com_deposit_time, var_deposit_time) =
			prover.commit(deposit_block_number.clone(), Scalar::random(&mut test_rng));
		let alloc_deposit_time = AllocatedScalar {
			variable: var_deposit_time,
			assignment: Some(deposit_block_number),
		};
		timed_comms.push(com_deposit_time);
		let (com_deposit_time_leaf_val, var_deposit_time_leaf_val) =
			prover.commit(timed_deposit_leaf_val.clone(), Scalar::random(&mut test_rng));
		let alloc_deposit_time_leaf_val = AllocatedScalar {
			variable: var_deposit_time_leaf_val,
			assignment: Some(timed_deposit_leaf_val),
		};
		timed_comms.push(com_deposit_time_leaf_val);

		let mut deposit_time_index_comms = vec![];
		let mut deposit_time_index_vars = vec![];
		let mut deposit_time_index_alloc_scalars = vec![];
		for b in get_bits(&k, DEFAULT_TREE_DEPTH).iter().take(deposit_tree.depth) {
			let val: Scalar = Scalar::from(*b as u8);
			let (c, v) = prover.commit(val.clone(), Scalar::random(&mut test_rng));
			deposit_time_index_comms.push(c);
			deposit_time_index_vars.push(v);
			deposit_time_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(val),
			});
		}

		let mut deposit_time_proof_comms = vec![];
		let mut deposit_time_proof_vars = vec![];
		let mut deposit_time_proof_alloc_scalars = vec![];
		for p in merkle_proof_vec.iter() {
			let (c, v) = prover.commit(*p, Scalar::random(&mut test_rng));
			deposit_time_proof_comms.push(c);
			deposit_time_proof_vars.push(v);
			deposit_time_proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(*p),
			});
		}

		let timed_deposit = AllocatedTimedDeposit {
			time_root: timed_tree.root,
			multiplier: Scalar::from(1u32),
			current_time: current_block_number,
			deposit_time: alloc_deposit_time,
			deposit_time_cm_val: alloc_deposit_time_leaf_val,
			deposit_time_index_bits: deposit_time_index_alloc_scalars,
			deposit_time_proof_nodes: deposit_time_proof_alloc_scalars,
		};

		let (com_output_1_inverse_val, var_output_1_inverse_val) =
			prover.commit(output_1_inverse.clone(), Scalar::random(&mut test_rng));
		let alloc_output_1_inverse_val = AllocatedScalar {
			variable: var_output_1_inverse_val,
			assignment: Some(output_1_inverse),
		};
		output_comms.push(com_output_1_inverse_val);
		let (com_output_1_val, var_output_1_val) = prover.commit(output_1.clone(), Scalar::random(&mut test_rng));
		let alloc_output_1_val = AllocatedScalar {
			variable: var_output_1_val,
			assignment: Some(output_1),
		};
		output_comms.push(com_output_1_val);
		let (com_output_1_rho, var_output_1_rho) = prover.commit(output_1_rho.clone(), Scalar::random(&mut test_rng));
		let alloc_output_1_rho = AllocatedScalar {
			variable: var_output_1_rho,
			assignment: Some(output_1_rho),
		};
		output_comms.push(com_output_1_rho);
		let (com_output_1_r, var_output_1_r) = prover.commit(output_1_r.clone(), Scalar::random(&mut test_rng));
		let alloc_output_1_r = AllocatedScalar {
			variable: var_output_1_r,
			assignment: Some(output_1_r),
		};
		output_comms.push(com_output_1_r);
		let (com_output_1_nullifier, var_output_1_nullifier) =
			prover.commit(output_1_nullifier.clone(), Scalar::random(&mut test_rng));
		let alloc_output_1_nullifier = AllocatedScalar {
			variable: var_output_1_nullifier,
			assignment: Some(output_1_nullifier),
		};
		output_comms.push(com_output_1_nullifier);

		let output_1_coin = AllocatedOutputCoin {
			inv_value: alloc_output_1_inverse_val,
			value: alloc_output_1_val,
			rho: alloc_output_1_rho,
			r: alloc_output_1_r,
			nullifier: alloc_output_1_nullifier,
			leaf_cm: output_1_cm,
		};

		let (com_output_2_inverse_val, var_output_2_inverse_val) =
			prover.commit(output_2_inverse.clone(), Scalar::random(&mut test_rng));
		let alloc_output_2_inverse_val = AllocatedScalar {
			variable: var_output_2_inverse_val,
			assignment: Some(output_2_inverse),
		};
		output_comms.push(com_output_2_inverse_val);
		let (com_output_2_val, var_output_2_val) = prover.commit(output_2.clone(), Scalar::random(&mut test_rng));
		let alloc_output_2_val = AllocatedScalar {
			variable: var_output_2_val,
			assignment: Some(output_2),
		};
		output_comms.push(com_output_2_val);
		let (com_output_2_rho, var_output_2_rho) = prover.commit(output_2_rho.clone(), Scalar::random(&mut test_rng));
		let alloc_output_2_rho = AllocatedScalar {
			variable: var_output_2_rho,
			assignment: Some(output_2_rho),
		};
		output_comms.push(com_output_2_rho);
		let (com_output_2_r, var_output_1_r) = prover.commit(output_2_r.clone(), Scalar::random(&mut test_rng));
		let alloc_output_2_r = AllocatedScalar {
			variable: var_output_1_r,
			assignment: Some(output_1_r),
		};
		output_comms.push(com_output_2_r);
		let (com_output_2_nullifier, var_output_2_nullifier) =
			prover.commit(output_2_nullifier.clone(), Scalar::random(&mut test_rng));
		let alloc_output_2_nullifier = AllocatedScalar {
			variable: var_output_2_nullifier,
			assignment: Some(output_2_nullifier),
		};
		output_comms.push(com_output_2_nullifier);

		let output_2_coin = AllocatedOutputCoin {
			inv_value: alloc_output_2_inverse_val,
			value: alloc_output_2_val,
			rho: alloc_output_2_rho,
			r: alloc_output_2_r,
			nullifier: alloc_output_2_nullifier,
			leaf_cm: output_2_cm,
		};

		let num_statics = 4;
		let statics_2 = allocate_statics_for_prover(&mut prover, num_statics);

		let num_statics = 2;
		let statics_4 = allocate_statics_for_prover(&mut prover, num_statics);

		let transaction = Transaction {
			depth: deposit_tree.depth,
			deposit_root: deposit_tree.root,
			input: coin,
			timed_deposit,
			outputs: vec![output_1_coin, output_2_coin],
			statics_2,
			statics_4,
		};

		let start = Instant::now();
		assert!(time_based_reward_verif_gadget(&mut prover, vec![transaction], &p_params,).is_ok());

		println!(
			"For binary tree of height {} and Poseidon rounds {}, no of multipliers is {} and constraints is {}",
			deposit_tree.depth,
			total_rounds,
			&prover.num_multipliers(),
			&prover.num_constraints()
		);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		let end = start.elapsed();

		println!("Proving time is {:?}", end);

		(
			proof,
			(
				[input_comms, input_leaf_index_comms, input_proof_comms],
				[timed_comms, deposit_time_index_comms, deposit_time_proof_comms],
				output_comms,
			),
		)
	};

	let mut verifier_transcript = Transcript::new(b"RewardTree");
	let mut verifier = Verifier::new(&mut verifier_transcript);
	// output commitments
	let comms_for_input = commitments.0;
	let [input_comms, input_bit_comms, input_proof_comms] = comms_for_input;
	// output commitments
	let comms_for_timed = commitments.1;
	let [timed_comms, timed_bit_comms, timed_proof_comms] = comms_for_timed;
	// output commitments
	let output_comms = commitments.2;

	let mut input_comms_alloc = vec![];
	for i in input_comms {
		let v = verifier.commit(i);
		input_comms_alloc.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let mut leaf_index_alloc_scalars = vec![];
	for l in input_bit_comms {
		let v = verifier.commit(l);
		leaf_index_alloc_scalars.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let mut proof_alloc_scalars = vec![];
	for p in input_proof_comms {
		let v = verifier.commit(p);
		proof_alloc_scalars.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let input_coin = AllocatedInputCoin {
		r: input_comms_alloc[0],
		nullifier: input_comms_alloc[1],
		leaf_cm_val: input_comms_alloc[2],
		leaf_index_bits: leaf_index_alloc_scalars,
		leaf_proof_nodes: proof_alloc_scalars,
		sn: nullifier_hash,
	};

	let mut timed_comms_alloc = vec![];
	for i in timed_comms {
		let v = verifier.commit(i);
		timed_comms_alloc.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let mut timed_index_alloc_scalars = vec![];
	for l in timed_bit_comms {
		let v = verifier.commit(l);
		timed_index_alloc_scalars.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let mut timed_proof_alloc_scalars = vec![];
	for p in timed_proof_comms {
		let v = verifier.commit(p);
		timed_proof_alloc_scalars.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let timed_deposit = AllocatedTimedDeposit {
		time_root: timed_tree.root,
		multiplier: Scalar::from(1u32),
		current_time: current_block_number,
		deposit_time: timed_comms_alloc[0],
		deposit_time_cm_val: timed_comms_alloc[1],
		deposit_time_index_bits: timed_index_alloc_scalars,
		deposit_time_proof_nodes: timed_proof_alloc_scalars,
	};

	let mut output_comms_alloc = vec![];
	// every 5 elements is another output
	for o in output_comms {
		let v = verifier.commit(o);
		output_comms_alloc.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let output_coins = vec![
		AllocatedOutputCoin {
			inv_value: output_comms_alloc[0],
			value: output_comms_alloc[1],
			rho: output_comms_alloc[2],
			r: output_comms_alloc[3],
			nullifier: output_comms_alloc[4],
			leaf_cm: output_1_cm,
		},
		AllocatedOutputCoin {
			inv_value: output_comms_alloc[5],
			value: output_comms_alloc[6],
			rho: output_comms_alloc[7],
			r: output_comms_alloc[8],
			nullifier: output_comms_alloc[9],
			leaf_cm: output_2_cm,
		},
	];

	let num_statics = 4;
	let statics_2 = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

	let num_statics = 2;
	let statics_4 = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

	let transaction = Transaction {
		deposit_root: deposit_tree.root,
		depth: deposit_tree.depth,
		input: input_coin,
		timed_deposit,
		outputs: output_coins,
		statics_2,
		statics_4,
	};

	let start = Instant::now();
	assert!(time_based_reward_verif_gadget(&mut verifier, vec![transaction], &p_params,).is_ok());

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}
