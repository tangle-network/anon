use super::*;
use crate::poseidon::builder::{gen_mds_matrix, gen_round_keys};
use builder::{Poseidon, PoseidonBuilder};
use bulletproofs::{
	r1cs::{Prover, Verifier},
	BulletproofGens, PedersenGens,
};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[cfg(feature = "std")]
use std::time::Instant;

#[cfg(feature = "std")]
use rand::SeedableRng;

#[cfg(feature = "std")]
use rand::rngs::StdRng;

#[cfg(feature = "std")]
fn get_poseidon_params(sbox: Option<PoseidonSbox>) -> Poseidon {
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

#[cfg(feature = "std")]
fn poseidon_perm(s_params: Poseidon, transcript_label: &'static [u8]) {
	let width = s_params.width;
	let total_rounds = s_params.get_total_rounds();

	let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
	let input = (0..width)
		.map(|_| Scalar::random(&mut test_rng))
		.collect::<Vec<_>>();
	let expected_output = Poseidon_permutation(&input, &s_params);

	/*println!("Input:\n");
	println!("{:?}", &input);
	println!("Expected output:\n");
	println!("{:?}", &expected_output);*/

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(2048, 1);

	println!("Proving");
	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(transcript_label);
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut comms = vec![];
		let mut allocs = vec![];

		for i in 0..width {
			let (com, var) = prover.commit(input[i].clone(), Scalar::random(&mut test_rng));
			comms.push(com);
			allocs.push(AllocatedScalar {
				variable: var,
				assignment: Some(input[i]),
			});
		}

		assert!(
			Poseidon_permutation_gadget(&mut prover, allocs, &s_params, &expected_output).is_ok()
		);

		println!(
			"For Poseidon permutation rounds {}, no of constraints is {}, no of multipliers is {}",
			total_rounds,
			&prover.num_constraints(),
			&prover.num_multipliers()
		);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		(proof, comms)
	};

	println!("Verifying");

	let mut verifier_transcript = Transcript::new(transcript_label);
	let mut verifier = Verifier::new(&mut verifier_transcript);
	let mut allocs = vec![];
	for i in 0..width {
		let v = verifier.commit(commitments[i]);
		allocs.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}
	assert!(
		Poseidon_permutation_gadget(&mut verifier, allocs, &s_params, &expected_output).is_ok()
	);

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
}

#[cfg(feature = "std")]
fn poseidon_hash_2(s_params: Poseidon, transcript_label: &'static [u8]) {
	let _width = s_params.width;
	let total_rounds = s_params.get_total_rounds();

	let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
	let xl = Scalar::random(&mut test_rng);
	let xr = Scalar::random(&mut test_rng);
	let expected_output = Poseidon_hash_2(xl, xr, &s_params);

	/*println!("Input:\n");
	println!("xl={:?}", &xl);
	println!("xr={:?}", &xr);
	println!("Expected output:\n");
	println!("{:?}", &expected_output);*/

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(2048, 1);

	println!("Proving");
	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(transcript_label);
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut comms = vec![];

		let (com_l, var_l) = prover.commit(xl.clone(), Scalar::random(&mut test_rng));
		comms.push(com_l);
		let l_alloc = AllocatedScalar {
			variable: var_l,
			assignment: Some(xl),
		};

		let (com_r, var_r) = prover.commit(xr.clone(), Scalar::random(&mut test_rng));
		comms.push(com_r);
		let r_alloc = AllocatedScalar {
			variable: var_r,
			assignment: Some(xr),
		};

		let num_statics = 4;
		let statics = allocate_statics_for_prover(&mut prover, num_statics);

		let start = Instant::now();
		assert!(Poseidon_hash_2_gadget(
			&mut prover,
			l_alloc,
			r_alloc,
			statics,
			&s_params,
			&expected_output
		)
		.is_ok());

		println!(
			"For Poseidon hash 2:1 rounds {}, no of constraints is {}, no of multipliers is {}",
			total_rounds,
			&prover.num_constraints(),
			&prover.num_multipliers()
		);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

		let end = start.elapsed();

		println!("Proving time is {:?}", end);
		(proof, comms)
	};

	println!("Verifying");

	let mut verifier_transcript = Transcript::new(transcript_label);
	let mut verifier = Verifier::new(&mut verifier_transcript);

	let lv = verifier.commit(commitments[0]);
	let rv = verifier.commit(commitments[1]);
	let l_alloc = AllocatedScalar {
		variable: lv,
		assignment: None,
	};
	let r_alloc = AllocatedScalar {
		variable: rv,
		assignment: None,
	};

	let num_statics = 4;
	let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

	let start = Instant::now();
	assert!(Poseidon_hash_2_gadget(
		&mut verifier,
		l_alloc,
		r_alloc,
		statics,
		&s_params,
		&expected_output
	)
	.is_ok());

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}

#[cfg(feature = "std")]
fn poseidon_hash_4(s_params: Poseidon, transcript_label: &'static [u8]) {
	let _width = s_params.width;
	let total_rounds = s_params.get_total_rounds();

	let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
	let _input = (0..4)
		.map(|_| Scalar::random(&mut test_rng))
		.collect::<Vec<_>>();
	let mut input = [Scalar::zero(); 4];
	input.copy_from_slice(_input.as_slice());
	let expected_output = Poseidon_hash_4(input, &s_params);

	/*println!("Input:\n");
	println!("xl={:?}", &xl);
	println!("xr={:?}", &xr);
	println!("Expected output:\n");
	println!("{:?}", &expected_output);*/

	let pc_gens = PedersenGens::default();
	let bp_gens = BulletproofGens::new(2048, 1);

	println!("Proving");
	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(transcript_label);
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut comms = vec![];
		let mut allocs = vec![];

		for inp in input.iter() {
			let (com, var) = prover.commit(inp.clone(), Scalar::random(&mut test_rng));
			comms.push(com);
			allocs.push(AllocatedScalar {
				variable: var,
				assignment: Some(inp.clone()),
			});
		}

		let num_statics = 2;
		let statics = allocate_statics_for_prover(&mut prover, num_statics);

		let start = Instant::now();
		assert!(
			Poseidon_hash_4_gadget(&mut prover, allocs, statics, &s_params, &expected_output)
				.is_ok()
		);

		println!(
			"For Poseidon hash 4:1 rounds {}, no of constraints is {}, no of multipliers is {}",
			total_rounds,
			&prover.num_constraints(),
			&prover.num_multipliers()
		);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();

		let end = start.elapsed();

		println!("Proving time is {:?}", end);
		(proof, comms)
	};

	println!("Verifying");

	let mut verifier_transcript = Transcript::new(transcript_label);
	let mut verifier = Verifier::new(&mut verifier_transcript);
	let mut allocs = vec![];
	for com in commitments {
		let v = verifier.commit(com);
		allocs.push({
			AllocatedScalar {
				variable: v,
				assignment: None,
			}
		});
	}

	let num_statics = 2;
	let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

	let start = Instant::now();
	assert!(
		Poseidon_hash_4_gadget(&mut verifier, allocs, statics, &s_params, &expected_output).is_ok()
	);

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}

#[test]
fn test_poseidon_perm_cube_sbox() {
	poseidon_perm(
		get_poseidon_params(Some(PoseidonSbox::Exponentiation3)),
		b"Poseidon_perm_cube",
	);
}

#[test]
fn test_poseidon_perm_inverse_sbox() {
	poseidon_perm(
		get_poseidon_params(Some(PoseidonSbox::Inverse)),
		b"Poseidon_perm_inverse",
	);
}

#[test]
fn test_poseidon_hash_2_cube_sbox() {
	poseidon_hash_2(
		get_poseidon_params(Some(PoseidonSbox::Exponentiation3)),
		b"Poseidon_hash_2_cube",
	);
}

#[test]
fn test_poseidon_hash_2_inverse_sbox() {
	poseidon_hash_2(
		get_poseidon_params(Some(PoseidonSbox::Inverse)),
		b"Poseidon_hash_2_inverse",
	);
}

#[test]
fn test_poseidon_hash_4_cube_sbox() {
	poseidon_hash_4(
		get_poseidon_params(Some(PoseidonSbox::Exponentiation3)),
		b"Poseidon_hash_2_cube",
	);
}

#[test]
fn test_poseidon_hash_4_inverse_sbox() {
	poseidon_hash_4(
		get_poseidon_params(Some(PoseidonSbox::Inverse)),
		b"Poseidon_hash_2_inverse",
	);
}
