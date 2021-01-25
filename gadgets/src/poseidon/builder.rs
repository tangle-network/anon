use crate::{
	poseidon::{allocate_statics_for_prover, sbox::PoseidonSbox, Poseidon_hash_2_gadget},
	utils::{get_scalar_from_hex, AllocatedScalar},
};
use alloc::{string::String, vec::Vec};
use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use crypto_constants::poseidon::{
	constants_3, constants_4, constants_5, constants_6, constants_7, constants_8, constants_9,
};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "std")]
use std::time::Instant;

// const DEFAULT_SECURITY_BITS: usize = 128;

// const LARGEST_ED25519_S: [u8;32] = [
// 	0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
// 	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
// 	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
// 	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
// ];

pub type Matrix = Vec<Vec<Scalar>>;

/// The Poseidon permutation.
#[derive(Clone)]
pub struct Poseidon {
	/// The size of the permutation, in field elements.
	pub width: usize,
	/// Number of full SBox rounds in beginning
	pub full_rounds_beginning: usize,
	/// Number of full SBox rounds in end
	pub full_rounds_end: usize,
	/// Number of partial rounds
	pub partial_rounds: usize,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
	/// The round key constants
	pub round_keys: Vec<Scalar>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Matrix,
	/// The transcript label for the prover & verifier
	pub transcript_label: &'static [u8],
	/// Pedersen generators for proving/verifying
	pub pc_gens: PedersenGens,
	/// Bulletproof generators for proving/verifying
	pub bp_gens: BulletproofGens,
}

/// Builds a `Poseidon` instance.
pub struct PoseidonBuilder {
	/// The size of the permutation, in field elements.
	width: usize,
	/// Number of full SBox rounds in beginning
	pub full_rounds_beginning: Option<usize>,
	/// Number of full SBox rounds in end
	pub full_rounds_end: Option<usize>,
	/// Number of partial rounds
	pub partial_rounds: Option<usize>,
	/// The S-box to apply in the sub words layer.
	sbox: Option<PoseidonSbox>,
	/// The desired (classical) security level, in bits.
	security_bits: Option<usize>,
	/// The round key constants
	pub round_keys: Option<Vec<Scalar>>,
	/// The MDS matrix to apply in the mix layer.
	mds_matrix: Option<Matrix>,
	/// The transcript label for the prover & verifier
	transcript_label: Option<&'static [u8]>,
	/// Pedersen generators for proving/verifying
	pc_gens: Option<PedersenGens>,
	/// Bulletproof generators for proving/verifying
	bp_gens: Option<BulletproofGens>,
}

impl PoseidonBuilder {
	pub fn new(width: usize) -> Self {
		PoseidonBuilder {
			width,
			full_rounds_beginning: None,
			full_rounds_end: None,
			partial_rounds: None,
			sbox: None,
			security_bits: None,
			round_keys: None,
			mds_matrix: None,
			transcript_label: None,
			pc_gens: None,
			bp_gens: None,
		}
	}

	pub fn sbox(&mut self, sbox: PoseidonSbox) -> &mut Self {
		self.sbox = Some(sbox);
		self
	}

	pub fn num_rounds(&mut self, full_b: usize, full_e: usize, partial: usize) -> &mut Self {
		self.full_rounds_beginning = Some(full_b);
		self.full_rounds_end = Some(full_e);
		self.partial_rounds = Some(partial);
		self
	}

	pub fn security_bits(&mut self, security_bits: usize) -> &mut Self {
		self.security_bits = Some(security_bits);
		self
	}

	pub fn round_keys_hex(&mut self, r_keys: Vec<String>) -> &mut Self {
		let cap = if self.full_rounds_beginning.is_some()
			&& self.full_rounds_end.is_some()
			&& self.partial_rounds.is_some()
		{
			(self.full_rounds_beginning.unwrap() + self.partial_rounds.unwrap() + self.full_rounds_end.unwrap())
				* self.width
		} else {
			r_keys.len()
		};
		assert!(cap <= r_keys.len());
		let mut rc = vec![];
		for i in 0..cap {
			// TODO: Remove unwrap, handle error
			let c = get_scalar_from_hex(&r_keys[i]);
			rc.push(c);
		}
		self.round_keys = Some(rc);

		self
	}

	pub fn round_keys(&mut self, r_keys: Vec<Scalar>) -> &mut Self {
		self.round_keys = Some(r_keys);
		self
	}

	pub fn mds_matrix(&mut self, mds_matrix: Matrix) -> &mut Self {
		self.mds_matrix = Some(mds_matrix);
		self
	}

	pub fn transcript_label(&mut self, label: &'static [u8]) -> &mut Self {
		self.transcript_label = Some(label);
		self
	}

	pub fn pedersen_gens(&mut self, gens: PedersenGens) -> &mut Self {
		self.pc_gens = Some(gens);
		self
	}

	pub fn bulletproof_gens(&mut self, gens: BulletproofGens) -> &mut Self {
		self.bp_gens = Some(gens);
		self
	}

	pub fn build(&self) -> Poseidon {
		let width = self.width;

		let round_keys = self.round_keys.clone().expect("Round keys required for now");

		// TODO: Generate a default MDS matrix instead of making the caller
		// supply one.
		let mds_matrix = self.mds_matrix.clone().expect("MDS matrix required for now");

		// If an S-box is not specified, determine the optimal choice based on
		// the guidance in the paper.
		let sbox = self.sbox.unwrap_or_else(|| PoseidonSbox::Inverse);

		if self.full_rounds_beginning.is_some()
			&& self.full_rounds_end.is_some()
			&& self.partial_rounds.is_some()
			&& self.security_bits.is_some()
		{
			panic!("Cannot specify both the number of rounds and the desired security level");
		}

		let full_rounds_beginning = self.full_rounds_beginning.unwrap_or_else(|| 3);
		let full_rounds_end = self.full_rounds_end.unwrap_or_else(|| 3);
		let partial_rounds = self.partial_rounds.unwrap_or_else(|| 57);

		// default pedersen genrators
		let pc_gens = self.pc_gens.unwrap_or_else(|| PedersenGens::default());
		// default 4096 might not be enough
		let bp_gens = self.bp_gens.clone().unwrap_or_else(|| BulletproofGens::new(4096, 1));

		let transcript_label = self.transcript_label.unwrap_or_else(|| b"test_poseidon_transcript");

		Poseidon {
			width,
			full_rounds_beginning,
			full_rounds_end,
			partial_rounds,
			sbox,
			round_keys,
			mds_matrix,
			transcript_label,
			pc_gens,
			bp_gens,
		}
	}
}

impl Poseidon {
	pub fn get_total_rounds(&self) -> usize {
		self.full_rounds_beginning + self.partial_rounds + self.full_rounds_end
	}

	#[cfg(feature = "std")]
	pub fn prove_hash_2<C: CryptoRng + RngCore>(&self, xl: Scalar, xr: Scalar, output: Scalar, mut rng: &mut C) {
		let total_rounds = self.get_total_rounds();
		let (_proof, _commitments) = {
			let mut prover_transcript = Transcript::new(self.transcript_label);
			let mut prover = Prover::new(&self.pc_gens, &mut prover_transcript);

			let mut comms = vec![];

			let (com_l, var_l) = prover.commit(xl.clone(), Scalar::random(&mut rng));
			comms.push(com_l);
			let l_alloc = AllocatedScalar {
				variable: var_l,
				assignment: Some(xl),
			};

			let (com_r, var_r) = prover.commit(xr.clone(), Scalar::random(&mut rng));
			comms.push(com_r);
			let r_alloc = AllocatedScalar {
				variable: var_r,
				assignment: Some(xr),
			};

			let num_statics = 4;
			let statics = allocate_statics_for_prover(&mut prover, num_statics);

			let start = Instant::now();
			assert!(Poseidon_hash_2_gadget(&mut prover, l_alloc, r_alloc, statics, &self, &output).is_ok());

			println!(
				"For Poseidon hash 2:1 rounds {}, no of constraints is {}, no of multipliers is {}",
				total_rounds,
				&prover.num_constraints(),
				&prover.num_multipliers()
			);

			let proof = prover.prove_with_rng(&self.bp_gens, &mut rng).unwrap();

			let end = start.elapsed();

			println!("Proving time is {:?}", end);
			(proof, comms)
		};
	}
}

// TODO: Write logic to generate correct round keys.
pub fn gen_round_keys(width: usize, total_rounds: usize) -> Vec<Scalar> {
	let ROUND_CONSTS = if width == 3 {
		constants_3::ROUND_CONSTS.to_vec()
	} else if width == 4 {
		constants_4::ROUND_CONSTS.to_vec()
	} else if width == 5 {
		constants_5::ROUND_CONSTS.to_vec()
	} else if width == 6 {
		constants_6::ROUND_CONSTS.to_vec()
	} else if width == 7 {
		constants_7::ROUND_CONSTS.to_vec()
	} else if width == 8 {
		constants_8::ROUND_CONSTS.to_vec()
	} else if width == 9 {
		constants_9::ROUND_CONSTS.to_vec()
	} else {
		constants_3::ROUND_CONSTS.to_vec()
	};

	let cap = total_rounds * width;
	/*let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
	vec![Scalar::random(&mut test_rng); cap]*/
	if ROUND_CONSTS.len() < cap {
		panic!("Not enough round constants, need {}, found {}", cap, ROUND_CONSTS.len());
	}
	let mut rc = vec![];
	for i in 0..cap {
		// TODO: Remove unwrap, handle error
		let c = get_scalar_from_hex(ROUND_CONSTS[i]);
		rc.push(c);
	}
	rc
}

// TODO: Write logic to generate correct MDS matrix. Currently loading hardcoded
// constants.
pub fn gen_mds_matrix(width: usize) -> Vec<Vec<Scalar>> {
	let MDS_ENTRIES: Vec<Vec<&str>> = if width == 3 {
		constants_3::MDS_ENTRIES.to_vec().iter().map(|v| v.to_vec()).collect()
	} else if width == 4 {
		constants_4::MDS_ENTRIES.to_vec().iter().map(|v| v.to_vec()).collect()
	} else if width == 5 {
		constants_5::MDS_ENTRIES.to_vec().iter().map(|v| v.to_vec()).collect()
	} else if width == 6 {
		constants_6::MDS_ENTRIES.to_vec().iter().map(|v| v.to_vec()).collect()
	} else if width == 7 {
		constants_7::MDS_ENTRIES.to_vec().iter().map(|v| v.to_vec()).collect()
	} else if width == 8 {
		constants_8::MDS_ENTRIES.to_vec().iter().map(|v| v.to_vec()).collect()
	} else if width == 9 {
		constants_9::MDS_ENTRIES.to_vec().iter().map(|v| v.to_vec()).collect()
	} else {
		constants_3::MDS_ENTRIES.to_vec().iter().map(|v| v.to_vec()).collect()
	};

	/*let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);
	vec![vec![Scalar::random(&mut test_rng); width]; width]*/
	if MDS_ENTRIES.len() != width {
		panic!("Incorrect width, only width {} is supported now", width);
	}
	let mut mds: Vec<Vec<Scalar>> = vec![vec![Scalar::zero(); width]; width];
	for i in 0..width {
		if MDS_ENTRIES[i].len() != width {
			panic!("Incorrect width, only width {} is supported now", width);
		}
		for j in 0..width {
			// TODO: Remove unwrap, handle error
			mds[i][j] = get_scalar_from_hex(MDS_ENTRIES[i][j]);
		}
	}
	mds
}
