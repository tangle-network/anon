use crate::poseidon::Poseidon_hash_4;
use crate::poseidon::Poseidon_hash_2;
use crate::poseidon::allocate_statics_for_verifier;
use crate::poseidon::allocate_statics_for_prover;
use crate::transaction::Transaction;
use crate::transaction::AllocatedCoin;

use crate::poseidon::PoseidonBuilder;
use crate::poseidon::builder::Poseidon;
use crate::poseidon::PoseidonSbox;
use crate::transaction::transaction_preimage_gadget;

use crate::utils::AllocatedScalar;

use crate::poseidon::builder::gen_round_keys;
use crate::poseidon::builder::gen_mds_matrix;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

#[cfg(feature="std")]
use std::time::{Instant};

#[cfg(feature="std")]
use rand::SeedableRng;

#[cfg(feature="std")]
use rand::rngs::StdRng;

#[cfg(feature="std")]
fn get_poseidon_params(sbox: Option<PoseidonSbox>) -> Poseidon{
	let width = 6;
	let (full_b, full_e) = (4, 4);
	let partial_rounds = 57;

	let sbox = sbox.unwrap_or_else(|| PoseidonSbox::Inverse);

	PoseidonBuilder::new(width)
		.num_rounds(full_b, full_e, partial_rounds)
		.round_keys(gen_round_keys(width, full_b + full_e + partial_rounds))
		.mds_matrix(gen_mds_matrix(width))
		.sbox(sbox)
		.build()
}

#[test]
fn test_is_valid_transaction_spend() {
	let params = get_poseidon_params(Some(PoseidonSbox::Exponentiation3));
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(4096, 1);

	let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);

	let input = Scalar::from(10u32);
	let input_inverse = input.invert();
	let input_rho = Scalar::random(&mut test_rng);
	let input_r = Scalar::random(&mut test_rng);
	let input_nullifier = Scalar::random(&mut test_rng);
	let input_sn = Poseidon_hash_2(input_r, input_nullifier, &params);
	let input_cm = Poseidon_hash_4([input, input_rho, input_r, input_nullifier], &params);

	let output_1 = Scalar::from(5u32);
	let output_1_inverse = Scalar::from(5u32).invert();
	let output_1_rho = Scalar::random(&mut test_rng);
	let output_1_r = Scalar::random(&mut test_rng);
	let output_1_nullifier = Scalar::random(&mut test_rng);
	let output_1_sn = Poseidon_hash_2(output_1_r, output_1_nullifier, &params);
	let output_1_cm = Poseidon_hash_4([output_1, output_1_rho, output_1_r, output_1_nullifier], &params);

	let output_2 = Scalar::from(5u32);
	let output_2_inverse = Scalar::from(5u32).invert();
	let output_2_rho = Scalar::random(&mut test_rng);
	let output_2_r = Scalar::random(&mut test_rng);
	let output_2_nullifier = Scalar::random(&mut test_rng);
	let output_2_sn = Poseidon_hash_2(output_2_r, output_2_nullifier, &params);
	let output_2_cm = Poseidon_hash_4([output_2, output_2_rho, output_2_r, output_2_nullifier], &params);

	{
		let (proof, commitments) = {
			let mut coms = vec![];

			let mut prover_transcript = Transcript::new(b"Transaction");
			let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

			let (com_input_inverse_val, var_input_inverse_val) = prover.commit(input_inverse.clone(), Scalar::random(&mut test_rng));
			let alloc_input_inverse_val = AllocatedScalar {
				variable: var_input_inverse_val,
				assignment: Some(input_inverse),
			};
			coms.push(com_input_inverse_val);
			let (com_input_val, var_input_val) = prover.commit(input.clone(), Scalar::random(&mut test_rng));
			let alloc_input_val = AllocatedScalar {
				variable: var_input_val,
				assignment: Some(input),
			};
			coms.push(com_input_val);
			let (com_input_rho, var_input_rho) = prover.commit(input_rho.clone(), Scalar::random(&mut test_rng));
			let alloc_input_rho = AllocatedScalar {
				variable: var_input_rho,
				assignment: Some(input_rho),
			};
			coms.push(com_input_rho);
			let (com_input_r, var_input_r) = prover.commit(input_r.clone(), Scalar::random(&mut test_rng));
			let alloc_input_r = AllocatedScalar {
				variable: var_input_r,
				assignment: Some(input_r),
			};
			coms.push(com_input_r);
			let (com_input_nullifier, var_input_nullifier) = prover.commit(input_nullifier.clone(), Scalar::random(&mut test_rng));
			let alloc_input_nullifier = AllocatedScalar {
				variable: var_input_nullifier,
				assignment: Some(input_nullifier),
			};
			coms.push(com_input_nullifier);
			let coin = AllocatedCoin::new_for_input(
				alloc_input_inverse_val,
				alloc_input_val,
				alloc_input_rho,
				alloc_input_r,
				alloc_input_nullifier,
				input_sn,
				input_cm,
			);

			let (com_output_1_inverse_val, var_output_1_inverse_val) = prover.commit(output_1_inverse.clone(), Scalar::random(&mut test_rng));
			let alloc_output_1_inverse_val = AllocatedScalar {
				variable: var_output_1_inverse_val,
				assignment: Some(output_1_inverse),
			};
			coms.push(com_output_1_inverse_val);
			let (com_output_1_val, var_output_1_val) = prover.commit(output_1.clone(), Scalar::random(&mut test_rng));
			let alloc_output_1_val = AllocatedScalar {
				variable: var_output_1_val,
				assignment: Some(output_1),
			};
			coms.push(com_output_1_val);
			let (com_output_1_rho, var_output_1_rho) = prover.commit(output_1_rho.clone(), Scalar::random(&mut test_rng));
			let alloc_output_1_rho = AllocatedScalar {
				variable: var_output_1_rho,
				assignment: Some(output_1_rho),
			};
			coms.push(com_output_1_rho);
			let (com_output_1_r, var_output_1_r) = prover.commit(output_1_r.clone(), Scalar::random(&mut test_rng));
			let alloc_output_1_r = AllocatedScalar {
				variable: var_output_1_r,
				assignment: Some(output_1_r),
			};
			coms.push(com_output_1_r);
			let (com_output_1_nullifier, var_output_1_nullifier) = prover.commit(output_1_nullifier.clone(), Scalar::random(&mut test_rng));
			let alloc_output_1_nullifier = AllocatedScalar {
				variable: var_output_1_nullifier,
				assignment: Some(output_1_nullifier),
			};
			coms.push(com_output_1_nullifier);

			let output_coin_1 = AllocatedCoin::new_for_output(
				alloc_output_1_inverse_val,
				alloc_output_1_val,
				alloc_output_1_rho,
				alloc_output_1_r,
				alloc_output_1_nullifier,
				output_1_cm,
			);

			let (com_output_2_inverse_val, var_output_2_inverse_val) = prover.commit(output_2_inverse.clone(), Scalar::random(&mut test_rng));
			let alloc_output_2_inverse_val = AllocatedScalar {
				variable: var_output_2_inverse_val,
				assignment: Some(output_2_inverse),
			};
			coms.push(com_output_2_inverse_val);
			let (com_output_2_val, var_output_2_val) = prover.commit(output_2.clone(), Scalar::random(&mut test_rng));
			let alloc_output_2_val = AllocatedScalar {
				variable: var_output_2_val,
				assignment: Some(output_2),
			};
			coms.push(com_output_2_val);
			let (com_output_2_rho, var_output_2_rho) = prover.commit(output_2_rho.clone(), Scalar::random(&mut test_rng));
			let alloc_output_2_rho = AllocatedScalar {
				variable: var_output_2_rho,
				assignment: Some(output_2_rho),
			};
			coms.push(com_output_2_rho);
			let (com_output_2_r, var_output_1_r) = prover.commit(output_2_r.clone(), Scalar::random(&mut test_rng));
			let alloc_output_2_r = AllocatedScalar {
				variable: var_output_1_r,
				assignment: Some(output_1_r),
			};
			coms.push(com_output_2_r);
			let (com_output_2_nullifier, var_output_2_nullifier) = prover.commit(output_2_nullifier.clone(), Scalar::random(&mut test_rng));
			let alloc_output_2_nullifier = AllocatedScalar {
				variable: var_output_2_nullifier,
				assignment: Some(output_2_nullifier),
			};
			coms.push(com_output_2_nullifier);

			let output_coin_2 = AllocatedCoin::new_for_output(
				alloc_output_2_inverse_val,
				alloc_output_2_val,
				alloc_output_2_rho,
				alloc_output_2_r,
				alloc_output_2_nullifier,
				output_2_cm,
			);

			let num_statics = 4;
			let statics_2 = allocate_statics_for_prover(&mut prover, num_statics);

			let num_statics = 2;
			let statics_4 = allocate_statics_for_prover(&mut prover, num_statics);

			let transaction = Transaction {
				inputs: vec![coin],
				outputs: vec![output_coin_1, output_coin_2],
				statics_2,
				statics_4,
			};

			let start = Instant::now();
			assert!(transaction_preimage_gadget(
				&mut prover,
				vec![transaction],
				&params
			).is_ok());

			let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

			let end = start.elapsed();

			println!("Proving time is {:?}", end);
			(proof, coms)
		};

		let mut verifier_transcript = Transcript::new(b"Transaction");
		let mut verifier = Verifier::new(&mut verifier_transcript);
		let mut allocs = vec![];
		for i in 0..commitments.len() {
			let v = verifier.commit(commitments[i]);
			allocs.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let num_statics = 4;
		let statics_2 = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

		let num_statics = 2;
		let statics_4 = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

		let transaction = Transaction {
			inputs: vec![AllocatedCoin::new_for_input(
				allocs[0],
				allocs[1],
				allocs[2],
				allocs[3],
				allocs[4],
				input_sn,
				input_cm,
			)],
			outputs: vec![AllocatedCoin::new_for_output(
				allocs[5],
				allocs[6],
				allocs[7],
				allocs[8],
				allocs[9],
				output_1_cm,
			), AllocatedCoin::new_for_output(
				allocs[10],
				allocs[11],
				allocs[12],
				allocs[13],
				allocs[14],
				output_2_cm,
			)],
			statics_2,
			statics_4,
		};

		let start = Instant::now();
		assert!(transaction_preimage_gadget(
			&mut verifier,
			vec![transaction],
			&params
		).is_ok());

		assert!(verifier.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng).is_ok());
		let end = start.elapsed();

		println!("Verification time is {:?}", end);
	}
}