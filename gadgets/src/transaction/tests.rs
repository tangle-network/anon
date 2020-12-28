// use super::*;
// use merlin::Transcript;

// #[test]
// fn test_is_zero_non_zero() {
// 	let pc_gens = PedersenGens::default();
// 	let bp_gens = BulletproofGens::new(128, 1);

// 	// To prove/verify value == 0, set y = 0 and inv = 0
// 	// To prove/verify value != 0, set y = 1 and inv = value^-1

// 	let mut rng = rand::thread_rng();

// 	{
// 		let expected_output = Poseidon_permutation(&input, &s_params);
// 		let (proof, commitment) = {
// 			let value = Scalar::zero();
// 			let mut prover_transcript = Transcript::new(b"Transaction");
// 			let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

// 			let (com_val, var_val) = prover.commit(value.clone(), Scalar::random(&mut rng));
// 			let alloc_scal = AllocatedScalar {
// 				variable: var_val,
// 				assignment: Some(value),
// 			};
// 			assert!(is_zero_gadget(&mut prover, alloc_scal).is_ok());

// 			let proof = prover.prove_with_rng(&bp_gens, &mut rng).unwrap();

// 			(proof, com_val)
// 		};

// 		let mut verifier_transcript = Transcript::new(b"ZeroTest");
// 		let mut verifier = Verifier::new(&mut verifier_transcript);
// 		let var_val = verifier.commit(commitment);
// 		let alloc_scal = AllocatedScalar {
// 			variable: var_val,
// 			assignment: None,
// 		};

// 		assert!(is_zero_gadget(&mut verifier, alloc_scal).is_ok());

// 		verifier.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut rng).unwrap();
// 	}
// }