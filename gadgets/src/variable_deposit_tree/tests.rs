use crate::{
	poseidon::{Poseidon_hash_2, Poseidon_hash_4},
	smt::builder::{SparseMerkleTreeBuilder, DEFAULT_TREE_DEPTH},
	variable_deposit_tree::{variable_deposit_tree_verif_gadget, AllocatedInputCoin, AllocatedOutputCoin, Transaction},
};

use crate::poseidon::{gen_mds_matrix, gen_round_keys, sbox::PoseidonSbox, PoseidonBuilder};

use rand::rngs::StdRng;

use bulletproofs::{
	r1cs::{Prover, Verifier},
	BulletproofGens, PedersenGens,
};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::utils::{get_bits, AllocatedScalar};
// use crate::gadget_mimc::{mimc, MIMC_ROUNDS, mimc_hash_2, mimc_gadget};
use crate::poseidon::{allocate_statics_for_prover, allocate_statics_for_verifier};

use rand::SeedableRng;

// For benchmarking
#[cfg(feature = "std")]
use std::time::Instant;

#[test]
fn test_variable_deposit_tree_verification() {
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

	let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);

	let input = Scalar::from(10u32);
	let input_inverse = input.invert();
	let input_rho = Scalar::random(&mut test_rng);
	let input_r = Scalar::random(&mut test_rng);
	let input_nullifier = Scalar::random(&mut test_rng);
	let input_sn = Poseidon_hash_2(input_r, input_nullifier, &p_params);
	let input_cm = Poseidon_hash_4([input, input_rho, input_r, input_nullifier], &p_params);

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

	let mut tree = SparseMerkleTreeBuilder::new().hash_params(p_params.clone()).build();

	for i in 1..=10 {
		let index = Scalar::from(i as u32);
		let s = if i == 7 { input_cm } else { index };

		tree.update(index, s);
	}

	let mut merkle_proof_vec = Vec::<Scalar>::new();
	let mut merkle_proof = Some(merkle_proof_vec);
	let k = Scalar::from(7u32);
	assert_eq!(input_cm, tree.get(k, tree.root, &mut merkle_proof));
	merkle_proof_vec = merkle_proof.unwrap();
	assert!(tree.verify_proof(k, input_cm, &merkle_proof_vec, None));
	assert!(tree.verify_proof(k, input_cm, &merkle_proof_vec, Some(&tree.root)));

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(40960, 1);

	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(b"FixedDepositTree");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut input_comms = vec![];
		let mut output_comms = vec![];
		let (com_input_inverse_val, var_input_inverse_val) =
			prover.commit(input_inverse.clone(), Scalar::random(&mut test_rng));
		let alloc_input_inverse_val = AllocatedScalar {
			variable: var_input_inverse_val,
			assignment: Some(input_inverse),
		};
		input_comms.push(com_input_inverse_val);
		let (com_input_val, var_input_val) = prover.commit(input.clone(), Scalar::random(&mut test_rng));
		let alloc_input_val = AllocatedScalar {
			variable: var_input_val,
			assignment: Some(input),
		};
		input_comms.push(com_input_val);
		let (com_input_rho, var_input_rho) = prover.commit(input_rho.clone(), Scalar::random(&mut test_rng));
		let alloc_input_rho = AllocatedScalar {
			variable: var_input_rho,
			assignment: Some(input_rho),
		};
		input_comms.push(com_input_rho);
		let (com_input_r, var_input_r) = prover.commit(input_r.clone(), Scalar::random(&mut test_rng));
		let alloc_input_r = AllocatedScalar {
			variable: var_input_r,
			assignment: Some(input_r),
		};
		input_comms.push(com_input_r);
		let (com_input_nullifier, var_input_nullifier) =
			prover.commit(input_nullifier.clone(), Scalar::random(&mut test_rng));
		let alloc_input_nullifier = AllocatedScalar {
			variable: var_input_nullifier,
			assignment: Some(input_nullifier),
		};
		input_comms.push(com_input_nullifier);

		let (leaf_com, leaf_var) = prover.commit(input_cm, Scalar::random(&mut test_rng));
		let alloc_leaf_val = AllocatedScalar {
			variable: leaf_var,
			assignment: Some(input_cm),
		};
		input_comms.push(leaf_com);

		let mut input_leaf_index_comms = vec![];
		let mut leaf_index_vars = vec![];
		let mut leaf_index_alloc_scalars = vec![];
		for b in get_bits(&k, DEFAULT_TREE_DEPTH).iter().take(tree.depth) {
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
			inv_value: alloc_input_inverse_val,
			value: alloc_input_val,
			rho: alloc_input_rho,
			r: alloc_input_r,
			nullifier: alloc_input_nullifier,
			leaf_cm_val: alloc_leaf_val,
			leaf_index_bits: leaf_index_alloc_scalars,
			leaf_proof_nodes: proof_alloc_scalars,
			sn: input_sn,
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
			inputs: vec![coin],
			outputs: vec![output_1_coin, output_2_coin],
			statics_2,
			statics_4,
		};

		let start = Instant::now();
		assert!(variable_deposit_tree_verif_gadget(
			&mut prover,
			tree.depth,
			&tree.root,
			vec![transaction],
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

		(
			proof,
			(input_comms, output_comms, input_leaf_index_comms, input_proof_comms),
		)
	};

	let mut verifier_transcript = Transcript::new(b"FixedDepositTree");
	let mut verifier = Verifier::new(&mut verifier_transcript);

	let input_comms = commitments.0;
	let output_comms = commitments.1;
	let input_bit_comms = commitments.2;
	let input_proof_comms = commitments.3;

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

	let input_coins = vec![AllocatedInputCoin {
		inv_value: input_comms_alloc[0],
		value: input_comms_alloc[1],
		rho: input_comms_alloc[2],
		r: input_comms_alloc[3],
		nullifier: input_comms_alloc[4],
		leaf_cm_val: input_comms_alloc[5],
		leaf_index_bits: leaf_index_alloc_scalars,
		leaf_proof_nodes: proof_alloc_scalars,
		sn: input_sn,
	}];

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
		inputs: input_coins,
		outputs: output_coins,
		statics_2,
		statics_4,
	};

	let start = Instant::now();
	assert!(
		variable_deposit_tree_verif_gadget(&mut verifier, tree.depth, &tree.root, vec![transaction], &p_params).is_ok()
	);

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}
