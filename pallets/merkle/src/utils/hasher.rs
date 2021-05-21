use crate::utils::keys::{slice_to_bytes_32, ScalarBytes};
use arkworks_gadgets::{
	merkle_tree::gen_empty_hashes,
	prelude::{
		to_bytes,
		webb_crypto_primitives::crh::{poseidon::PoseidonParameters, CRH},
		Bls381,
	},
	setup::mixer::{setup_params_3, MixerTreeConfig, PoseidonCRH3},
};
use bulletproofs::{
	r1cs::{R1CSProof, Verifier},
	BulletproofGens, PedersenGens,
};
use bulletproofs_gadgets::{
	fixed_deposit_tree::mixer_verif_gadget,
	poseidon::{
		allocate_statics_for_verifier,
		builder::{Poseidon, PoseidonBuilder},
		PoseidonSbox, Poseidon_hash_2,
	},
	smt::gen_zero_tree,
	utils::AllocatedScalar,
};
use codec::{Decode, Encode};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use lazy_static::lazy_static;
use merlin::Transcript;
use rand_core::OsRng;
use sp_std::prelude::*;

lazy_static! {
	static ref DEFAULT_POSEIDON_HASHER: Poseidon = default_bulletproofs_poseidon_hasher();
	static ref POSEIDON_PARAMETERS: PoseidonParameters<Bls381> = setup_params_3::<Bls381>();
}

/// Default hasher instance used to construct the tree
pub fn default_bulletproofs_poseidon_hasher() -> Poseidon {
	let width = 6;
	// TODO: should be able to pass the number of generators
	let bp_gens = BulletproofGens::new(16400, 1);
	PoseidonBuilder::new(width)
		.bulletproof_gens(bp_gens)
		.sbox(PoseidonSbox::Exponentiation3)
		.build()
}

/// Hash functions for MerkleTree
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub enum HashFunction {
	PoseidonDefault,
	// First argument is width, second is exponentiation
	Poseidon(u8, u8),
	MiMC,
	Blake2,
	Sha256,
}

/// Different curve types
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub enum Curve {
	Bls381,
	Bn254,
	Curve25519,
}

/// Different curve types
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub enum Snark {
	Groth16,
	Marlin,
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub enum Backend {
	Arkworks(Curve, Snark),
	Bulletproofs(Curve),
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub enum SetupError {
	InvalidPrivateInputs,
	ConstraintSystemUnsatisfied,
	VerificationFailed,
	InvalidProof,
	HashingFailed,
	ZeroTreeGenFailed,
	Unimplemented,
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub struct Setup {
	hasher: HashFunction,
	backend: Backend,
}

impl Setup {
	pub fn new(hasher: HashFunction, backend: Backend) -> Self {
		Self { hasher, backend }
	}

	pub fn hash(&self, xl: &ScalarBytes, xr: &ScalarBytes) -> Result<ScalarBytes, SetupError> {
		match self.backend {
			Backend::Bulletproofs(Curve::Curve25519) => match self.hasher {
				HashFunction::PoseidonDefault | HashFunction::Poseidon(6, 3) => {
					let sl = Scalar::from_bytes_mod_order(slice_to_bytes_32(xl));
					let sr = Scalar::from_bytes_mod_order(slice_to_bytes_32(xr));
					Ok(Poseidon_hash_2(sl, sr, &DEFAULT_POSEIDON_HASHER).to_bytes().to_vec())
				}
				_ => Err(SetupError::Unimplemented),
			},
			Backend::Arkworks(Curve::Bls381, _) => match self.hasher {
				HashFunction::PoseidonDefault => {
					let mut bytes = Vec::new();
					bytes.extend(xl);
					bytes.extend(xr);
					let res = PoseidonCRH3::evaluate(&POSEIDON_PARAMETERS, &bytes).unwrap();
					let bytes_res = to_bytes![res];
					let bytes = match bytes_res {
						Ok(bytes) => bytes,
						Err(_) => return Err(SetupError::HashingFailed),
					};
					Ok(bytes)
				}
				_ => Err(SetupError::Unimplemented),
			},
			_ => Err(SetupError::Unimplemented),
		}
	}

	pub fn get_bulletproofs_poseidon(&self) -> Result<&Poseidon, SetupError> {
		match (&self.backend, &self.hasher) {
			(Backend::Bulletproofs(Curve::Curve25519), HashFunction::PoseidonDefault) => Ok(&DEFAULT_POSEIDON_HASHER),
			_ => Err(SetupError::Unimplemented),
		}
	}

	pub fn generate_zero_tree(&self, depth: usize) -> Result<(Vec<ScalarBytes>, ScalarBytes), SetupError> {
		match self.backend {
			Backend::Bulletproofs(Curve::Curve25519) => match self.hasher {
				HashFunction::PoseidonDefault => {
					let zero_tree = gen_zero_tree(DEFAULT_POSEIDON_HASHER.width, &DEFAULT_POSEIDON_HASHER.sbox);
					Ok((
						zero_tree[0..depth].iter().map(|x| x.to_vec()).collect(),
						zero_tree[depth].to_vec(),
					))
				}
				_ => Err(SetupError::Unimplemented),
			},
			Backend::Arkworks(Curve::Bls381, _) => match self.hasher {
				HashFunction::PoseidonDefault => {
					let res = gen_empty_hashes::<MixerTreeConfig>(&POSEIDON_PARAMETERS, &POSEIDON_PARAMETERS)
						.map_err(|_| SetupError::ZeroTreeGenFailed)?;
					let zero_tree: Vec<ScalarBytes> = res
						.iter()
						.map(|val| to_bytes![val].map_err(|_| SetupError::ZeroTreeGenFailed))
						.collect::<Result<Vec<ScalarBytes>, _>>()?;
					Ok((zero_tree[0..depth].to_vec(), zero_tree[depth].clone()))
				}
				_ => Err(SetupError::Unimplemented),
			},
			_ => Err(SetupError::Unimplemented),
		}
	}

	pub fn verify_zk(
		&self,
		depth: usize,
		cached_root: ScalarBytes,
		comms: Vec<ScalarBytes>,
		nullifier_hash: ScalarBytes,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<ScalarBytes>,
		proof_commitments: Vec<ScalarBytes>,
		recipient: ScalarBytes,
		relayer: ScalarBytes,
	) -> Result<(), SetupError> {
		match self.backend {
			Backend::Bulletproofs(Curve::Curve25519) => {
				let cached_root_s = Scalar::from_bytes_mod_order(slice_to_bytes_32(&cached_root));
				let comms_c = comms.iter().map(|x| CompressedRistretto::from_slice(x)).collect();
				let nullifier_hash_s = Scalar::from_bytes_mod_order(slice_to_bytes_32(&nullifier_hash));
				let leaf_index_commitments_c = leaf_index_commitments
					.iter()
					.map(|x| CompressedRistretto::from_slice(x))
					.collect();
				let proof_commitments_c = proof_commitments
					.iter()
					.map(|x| CompressedRistretto::from_slice(x))
					.collect();
				let recipient_s = Scalar::from_bytes_mod_order(slice_to_bytes_32(&recipient));
				let relayer_s = Scalar::from_bytes_mod_order(slice_to_bytes_32(&relayer));
				self.verify_bulletproofs_poseidon(
					depth,
					cached_root_s,
					comms_c,
					nullifier_hash_s,
					proof_bytes,
					leaf_index_commitments_c,
					proof_commitments_c,
					recipient_s,
					relayer_s,
				)
			}
			_ => return Err(SetupError::Unimplemented),
		}
	}

	// TODO: move to bulletproofs-gadgets
	pub fn verify_bulletproofs_poseidon(
		&self,
		depth: usize,
		cached_root: Scalar,
		comms: Vec<CompressedRistretto>,
		nullifier_hash: Scalar,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<CompressedRistretto>,
		proof_commitments: Vec<CompressedRistretto>,
		recipient: Scalar,
		relayer: Scalar,
	) -> Result<(), SetupError> {
		let pc_gens = PedersenGens::default();
		let label = b"zk_membership_proof";
		let mut verifier_transcript = Transcript::new(label);
		let mut verifier = Verifier::new(&mut verifier_transcript);

		if comms.len() != 3 {
			return Err(SetupError::InvalidPrivateInputs);
		}
		let r_val = verifier.commit(comms[0]);
		let r_alloc = AllocatedScalar {
			variable: r_val,
			assignment: None,
		};
		let nullifier_val = verifier.commit(comms[1]);
		let nullifier_alloc = AllocatedScalar {
			variable: nullifier_val,
			assignment: None,
		};

		let var_leaf = verifier.commit(comms[2]);
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: None,
		};

		let mut leaf_index_alloc_scalars = vec![];
		for l in leaf_index_commitments {
			let v = verifier.commit(l);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let mut proof_alloc_scalars = vec![];
		for p in proof_commitments {
			let v = verifier.commit(p);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let num_statics = 4;
		let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);
		let hasher = self.get_bulletproofs_poseidon()?;
		let gadget_res = mixer_verif_gadget(
			&mut verifier,
			&recipient,
			&relayer,
			depth as usize,
			&cached_root,
			&nullifier_hash,
			r_alloc,
			nullifier_alloc,
			leaf_alloc_scalar,
			leaf_index_alloc_scalars,
			proof_alloc_scalars,
			statics,
			&hasher,
		);
		if !gadget_res.is_ok() {
			return Err(SetupError::ConstraintSystemUnsatisfied);
		}

		let proof = R1CSProof::from_bytes(&proof_bytes);
		if !proof.is_ok() {
			return Err(SetupError::InvalidProof);
		}
		let proof = proof.unwrap();

		let mut rng = OsRng::default();
		let verify_res = verifier.verify_with_rng(&proof, &hasher.pc_gens, &hasher.bp_gens, &mut rng);
		if !verify_res.is_ok() {
			return Err(SetupError::VerificationFailed);
		}
		Ok(())
	}
}
