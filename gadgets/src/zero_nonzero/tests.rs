use super::*;
use bulletproofs::r1cs::{Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

#[test]
fn test_is_zero_non_zero() {
	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(128, 1);

	// To prove/verify value == 0, set y = 0 and inv = 0
	// To prove/verify value != 0, set y = 1 and inv = value^-1

	let mut rng = rand::thread_rng();

	{
		let _inv = 0;
		let _y = 0;

		let (proof, commitment) = {
			let value = Scalar::zero();
			let mut prover_transcript = Transcript::new(b"ZeroTest");
			let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

			let (com_val, var_val) = prover.commit(value.clone(), Scalar::random(&mut rng));
			let alloc_scal = AllocatedScalar {
				variable: var_val,
				assignment: Some(value),
			};
			assert!(is_zero_gadget(&mut prover, alloc_scal).is_ok());

			let proof = prover.prove_with_rng(&bp_gens, &mut rng).unwrap();

			(proof, com_val)
		};

		let mut verifier_transcript = Transcript::new(b"ZeroTest");
		let mut verifier = Verifier::new(&mut verifier_transcript);
		let var_val = verifier.commit(commitment);
		let alloc_scal = AllocatedScalar {
			variable: var_val,
			assignment: None,
		};

		assert!(is_zero_gadget(&mut verifier, alloc_scal).is_ok());

		verifier.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut rng).unwrap();
	}

	{
		let (proof, commitments) = {

			let value = Scalar::random(&mut rng);
			let inv = value.invert();
			let mut prover_transcript = Transcript::new(b"NonZeroTest");
			let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

			let (com_val, var_val) = prover.commit(value.clone(), Scalar::random(&mut rng));
			let alloc_scal = AllocatedScalar {
				variable: var_val,
				assignment: Some(value),
			};

			let (com_val_inv, var_val_inv) = prover.commit(inv.clone(), Scalar::random(&mut rng));
			let alloc_scal_inv = AllocatedScalar {
				variable: var_val_inv,
				assignment: Some(inv),
			};
			assert!(is_nonzero_gadget(&mut prover, alloc_scal, alloc_scal_inv).is_ok());

			let proof = prover.prove_with_rng(&bp_gens, &mut rng).unwrap();

			(proof, (com_val, com_val_inv))
		};

		let mut verifier_transcript = Transcript::new(b"NonZeroTest");
		let mut verifier = Verifier::new(&mut verifier_transcript);
		let var_val = verifier.commit(commitments.0);
		let alloc_scal = AllocatedScalar {
			variable: var_val,
			assignment: None,
		};

		let var_val_inv = verifier.commit(commitments.1);
		let alloc_scal_inv = AllocatedScalar {
			variable: var_val_inv,
			assignment: None,
		};

		assert!(is_nonzero_gadget(&mut verifier, alloc_scal, alloc_scal_inv).is_ok());

		verifier.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut rng).unwrap();
	}
}