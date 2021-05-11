use crate::utils::keys::{Commitment, ScalarData};
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
use lazy_static::lazy_static;
use merlin::Transcript;
use rand_core::OsRng;

lazy_static! {
	static ref DEFAULT_POSEIDON_HASHER: Poseidon = default_bulletproofs_poseidon_hasher();
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
	Poseidon(u8, u8),
	MiMC,
	Blake2,
	Sha256,
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Encode, Decode, PartialEq)]
pub enum Backend {
	Arkworks,
	Bulletproofs,
}

pub enum SetupError {
	InvalidPrivateInputs,
	ConstraintSystemUnsatisfied,
	VerificationFailed,
	InvalidProof,
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

	pub fn hash(&self, xl: ScalarData, xr: ScalarData) -> ScalarData {
		let res = match self.hasher {
			HashFunction::PoseidonDefault => Poseidon_hash_2(xl.0, xr.0, &DEFAULT_POSEIDON_HASHER),
			_ => Poseidon_hash_2(xl.0, xr.0, &DEFAULT_POSEIDON_HASHER),
		};

		ScalarData(res)
	}

	pub fn get_bulletproofs_poseidon(&self) -> &Poseidon {
		match self.backend {
			Backend::Bulletproofs => match self.hasher {
				HashFunction::PoseidonDefault => &DEFAULT_POSEIDON_HASHER,
				_ => panic!("Hasher is not default poseidon hasher"),
			},
			_ => panic!("Backend not bulletproofs"),
		}
	}

	pub fn generate_zero_tree(&self, depth: usize) -> (Vec<ScalarData>, ScalarData) {
		let zero_tree = match self.hasher {
			HashFunction::PoseidonDefault => {
				gen_zero_tree(DEFAULT_POSEIDON_HASHER.width, &DEFAULT_POSEIDON_HASHER.sbox)
			}
			_ => gen_zero_tree(DEFAULT_POSEIDON_HASHER.width, &DEFAULT_POSEIDON_HASHER.sbox),
		};
		let init_edges: Vec<ScalarData> = zero_tree[0..depth].iter().map(|x| ScalarData::from(*x)).collect();
		(init_edges, ScalarData::from(zero_tree[depth]))
	}

	pub fn verify_bulletproofs_poseidon(
		&self,
		depth: usize,
		cached_root: ScalarData,
		comms: Vec<Commitment>,
		nullifier_hash: ScalarData,
		proof_bytes: Vec<u8>,
		leaf_index_commitments: Vec<Commitment>,
		proof_commitments: Vec<Commitment>,
		recipient: ScalarData,
		relayer: ScalarData,
	) -> Result<(), SetupError> {
		let pc_gens = PedersenGens::default();
		let label = b"zk_membership_proof";
		let mut verifier_transcript = Transcript::new(label);
		let mut verifier = Verifier::new(&mut verifier_transcript);

		if comms.len() != 3 {
			return Err(SetupError::InvalidPrivateInputs);
		}
		let r_val = verifier.commit(comms[0].0);
		let r_alloc = AllocatedScalar {
			variable: r_val,
			assignment: None,
		};
		let nullifier_val = verifier.commit(comms[1].0);
		let nullifier_alloc = AllocatedScalar {
			variable: nullifier_val,
			assignment: None,
		};

		let var_leaf = verifier.commit(comms[2].0);
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: None,
		};

		let mut leaf_index_alloc_scalars = vec![];
		for l in leaf_index_commitments {
			let v = verifier.commit(l.0);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let mut proof_alloc_scalars = vec![];
		for p in proof_commitments {
			let v = verifier.commit(p.0);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: None,
			});
		}

		let num_statics = 4;
		let statics = allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);
		let hasher = self.get_bulletproofs_poseidon();
		let gadget_res = mixer_verif_gadget(
			&mut verifier,
			&recipient.to_scalar(),
			&relayer.to_scalar(),
			depth as usize,
			&cached_root.0,
			&nullifier_hash.0,
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
