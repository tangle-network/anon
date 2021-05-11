use crate::utils::keys::ScalarData;
use bulletproofs::{
	r1cs::{R1CSProof, Verifier},
	BulletproofGens, PedersenGens,
};
use bulletproofs_gadgets::{
	poseidon::{
		builder::{Poseidon, PoseidonBuilder},
		PoseidonSbox, Poseidon_hash_2,
	},
	smt::gen_zero_tree,
};
use codec::{Decode, Encode};
use lazy_static::lazy_static;

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
}
