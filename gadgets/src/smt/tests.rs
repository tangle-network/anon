use super::smt::*;
use crate::poseidon::gen_mds_matrix;
use crate::poseidon::gen_round_keys;
use crate::poseidon::sbox::PoseidonSbox;
use crate::poseidon::PoseidonBuilder;
use rand::rngs::StdRng;

use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::utils::get_bits;
use crate::utils::AllocatedScalar;
// use crate::gadget_mimc::{mimc, MIMC_ROUNDS, mimc_hash_2, mimc_gadget};
use crate::poseidon::{allocate_statics_for_prover, allocate_statics_for_verifier};

use crate::smt::builder::{SparseMerkleTreeBuilder, DEFAULT_TREE_DEPTH};
use rand::rngs::OsRng;
use rand::SeedableRng;
// For benchmarking
#[cfg(feature = "std")]
use std::time::Instant;

#[test]
fn test_vanilla_sparse_merkle_tree() {
	let mut test_rng: OsRng = OsRng::default();
	let width = 6;
	let (full_b, full_e) = (4, 4);
	let partial_rounds = 57;
	let p_params = PoseidonBuilder::new(width)
		.num_rounds(full_b, full_e, partial_rounds)
		.round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
		.mds_matrix(gen_mds_matrix(width))
		.sbox(PoseidonSbox::Inverse)
		.build();

	let mut tree = SparseMerkleTreeBuilder::new().hash_params(p_params).build();

	for i in 1..10 {
		let s = Scalar::from(i as u32);
		tree.update(s, s);
	}

	for i in 1..10 {
		let s = Scalar::from(i as u32);
		assert_eq!(s, tree.get(s, tree.root, &mut None));
		let mut proof_vec = Vec::<Scalar>::new();
		let mut proof = Some(proof_vec);
		assert_eq!(s, tree.get(s, tree.root, &mut proof));
		proof_vec = proof.unwrap();
		assert!(tree.verify_proof(s, s, &proof_vec, None));
		assert!(tree.verify_proof(s, s, &proof_vec, Some(&tree.root)));
	}

	let kvs: Vec<(Scalar, Scalar)> = (0..100)
		.map(|_| (Scalar::random(&mut test_rng), Scalar::random(&mut test_rng)))
		.collect();
	for i in 0..kvs.len() {
		tree.update(kvs[i].0, kvs[i].1);
	}

	for i in 0..kvs.len() {
		assert_eq!(kvs[i].1, tree.get(kvs[i].0, tree.root, &mut None));
	}
}

#[test]
fn test_vsmt_verif() {
	let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);

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

	let mut tree = SparseMerkleTreeBuilder::new()
		.hash_params(p_params.clone())
		.build();

	for i in 1..=10 {
		let s = Scalar::from(i as u32);
		tree.update(s, s);
	}

	let mut merkle_proof_vec = Vec::<Scalar>::new();
	let mut merkle_proof = Some(merkle_proof_vec);
	let k = Scalar::from(7u32);
	assert_eq!(k, tree.get(k, tree.root, &mut merkle_proof));
	merkle_proof_vec = merkle_proof.unwrap();
	assert!(tree.verify_proof(k, k, &merkle_proof_vec, None));
	assert!(tree.verify_proof(k, k, &merkle_proof_vec, Some(&tree.root)));

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(40960, 1);

	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(b"VSMT");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let (com_leaf, var_leaf) = prover.commit(k, Scalar::random(&mut test_rng));
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: Some(k),
		};

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
		for p in merkle_proof_vec.iter().rev() {
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
		assert!(vanilla_merkle_merkle_tree_verif_gadget(
			&mut prover,
			tree.depth,
			&tree.root,
			leaf_alloc_scalar,
			leaf_index_alloc_scalars,
			proof_alloc_scalars,
			statics,
			&p_params
		)
		.is_ok());

		//            println!("For tree height {} and MiMC rounds {}, no of constraints is {}", tree.depth, &MIMC_ROUNDS, &prover.num_constraints());

		println!("For binary tree of height {} and Poseidon rounds {}, no of multipliers is {} and constraints is {}", tree.depth, total_rounds, &prover.num_multipliers(), &prover.num_constraints());

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		let end = start.elapsed();

		println!("Proving time is {:?}", end);

		(proof, (com_leaf, leaf_index_comms, proof_comms))
	};

	let mut verifier_transcript = Transcript::new(b"VSMT");
	let mut verifier = Verifier::new(&mut verifier_transcript);
	let var_leaf = verifier.commit(commitments.0);
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
	assert!(vanilla_merkle_merkle_tree_verif_gadget(
		&mut verifier,
		tree.depth,
		&tree.root,
		leaf_alloc_scalar,
		leaf_index_alloc_scalars,
		proof_alloc_scalars,
		statics,
		&p_params
	)
	.is_ok());

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}

#[test]
fn test_vsmt_prove_verif() {
	let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);

	let width = 6;
	let (full_b, full_e) = (4, 4);
	let partial_rounds = 57;
	let p_params = PoseidonBuilder::new(width)
		.num_rounds(full_b, full_e, partial_rounds)
		.round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
		.mds_matrix(gen_mds_matrix(width))
		.sbox(PoseidonSbox::Inverse)
		.build();
	let mut tree = SparseMerkleTreeBuilder::new()
		.hash_params(p_params.clone())
		.build();

	for i in 1..=10 {
		let s = Scalar::from(i as u32);
		tree.update(s, s);
	}

	let mut merkle_proof_vec = Vec::<Scalar>::new();
	let mut merkle_proof = Some(merkle_proof_vec);
	let k = Scalar::from(7u32);
	assert_eq!(k, tree.get(k, tree.root, &mut merkle_proof));
	merkle_proof_vec = merkle_proof.unwrap();
	assert!(tree.verify_proof(k, k, &merkle_proof_vec, None));
	assert!(tree.verify_proof(k, k, &merkle_proof_vec, Some(&tree.root)));

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(40960, 1);
	let mut prover_transcript = Transcript::new(b"VSMT");
	let prover = Prover::new(&pc_gens, &mut prover_transcript);

	let (proof, commitments) = tree.prove_zk(k, tree.root, &bp_gens, prover);

	// Verify part
	let mut verifier_transcript = Transcript::new(b"VSMT");
	let mut verifier = Verifier::new(&mut verifier_transcript);
	let var_leaf = verifier.commit(commitments.0);
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
	assert!(vanilla_merkle_merkle_tree_verif_gadget(
		&mut verifier,
		tree.depth,
		&tree.root,
		leaf_alloc_scalar,
		leaf_index_alloc_scalars,
		proof_alloc_scalars,
		statics,
		&p_params
	)
	.is_ok());

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}
