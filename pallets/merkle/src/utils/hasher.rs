use crate::{
	utils::keys::{slice_to_bytes_32, ScalarBytes},
	Config, Error,
};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use arkworks_gadgets::{
	merkle_tree::gen_empty_hashes,
	prelude::{
		ark_bls12_381::{Bls12_381, Fr as Bls381},
		ark_ff::to_bytes,
		webb_crypto_primitives::{
			crh::{poseidon::PoseidonParameters, CRH},
			to_field_elements,
		},
	},
	setup::{
		common::{setup_params_3, verify_groth16, PoseidonCRH3, TreeConfig},
		mixer::{get_public_inputs, setup_random_groth16},
	},
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
pub struct Setup {
	pub hasher: HashFunction,
	pub backend: Backend,
}

impl Setup {
	pub fn new(hasher: HashFunction, backend: Backend) -> Self {
		Self { hasher, backend }
	}

	pub fn hash<C: Config>(&self, xl: &ScalarBytes, xr: &ScalarBytes) -> Result<ScalarBytes, Error<C>> {
		match self.backend {
			Backend::Bulletproofs(Curve::Curve25519) => match self.hasher {
				HashFunction::PoseidonDefault | HashFunction::Poseidon(6, 3) => {
					let sl = Scalar::from_bytes_mod_order(slice_to_bytes_32(xl));
					let sr = Scalar::from_bytes_mod_order(slice_to_bytes_32(xr));
					Ok(Poseidon_hash_2(sl, sr, &DEFAULT_POSEIDON_HASHER).to_bytes().to_vec())
				}
				_ => Err(Error::<C>::Unimplemented),
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
						Err(_) => return Err(Error::<C>::HashingFailed),
					};
					Ok(bytes)
				}
				_ => Err(Error::<C>::Unimplemented),
			},
			_ => Err(Error::<C>::Unimplemented),
		}
	}

	pub fn get_default_bulletproofs_poseidon<C: Config>(&self) -> Result<&Poseidon, Error<C>> {
		match (&self.backend, &self.hasher) {
			(Backend::Bulletproofs(Curve::Curve25519), HashFunction::PoseidonDefault) => Ok(&DEFAULT_POSEIDON_HASHER),
			_ => Err(Error::<C>::Unimplemented),
		}
	}

	pub fn generate_zero_tree<C: Config>(&self, depth: usize) -> Result<(Vec<ScalarBytes>, ScalarBytes), Error<C>> {
		match self.backend {
			Backend::Bulletproofs(Curve::Curve25519) => match self.hasher {
				HashFunction::PoseidonDefault => {
					let zero_tree = gen_zero_tree(DEFAULT_POSEIDON_HASHER.width, &DEFAULT_POSEIDON_HASHER.sbox);
					Ok((
						zero_tree[0..depth].iter().map(|x| x.to_vec()).collect(),
						zero_tree[depth].to_vec(),
					))
				}
				_ => Err(Error::<C>::Unimplemented),
			},
			Backend::Arkworks(Curve::Bls381, _) => match self.hasher {
				HashFunction::PoseidonDefault => {
					let res = gen_empty_hashes::<TreeConfig>(&(), &POSEIDON_PARAMETERS)
						.map_err(|_| Error::<C>::ZeroTreeGenFailed)?;
					let zero_tree: Vec<ScalarBytes> = res
						.iter()
						.map(|val| to_bytes![val].map_err(|_| Error::<C>::ZeroTreeGenFailed))
						.collect::<Result<Vec<ScalarBytes>, _>>()?;
					Ok((zero_tree[0..depth].to_vec(), zero_tree[depth].clone()))
				}
				_ => Err(Error::<C>::Unimplemented),
			},
			_ => Err(Error::<C>::Unimplemented),
		}
	}

	pub fn verify_zk<C: Config>(
		&self,
		depth: usize,
		root_bytes: ScalarBytes,
		private_inputs_bytes: Vec<ScalarBytes>,
		nullifier_hash_bytes: ScalarBytes,
		proof_bytes: Vec<u8>,
		verifier_key: Option<Vec<u8>>,
		path_indices_bytes: Vec<ScalarBytes>,
		path_nodes_bytes: Vec<ScalarBytes>,
		recipient_bytes: ScalarBytes,
		relayer_bytes: ScalarBytes,
	) -> Result<(), Error<C>> {
		match self.backend {
			Backend::Bulletproofs(Curve::Curve25519) => {
				let root = Scalar::from_bytes_mod_order(slice_to_bytes_32(&root_bytes));
				let private_inputs = private_inputs_bytes
					.iter()
					.map(|x| CompressedRistretto::from_slice(x))
					.collect();
				let nullifier_hash = Scalar::from_bytes_mod_order(slice_to_bytes_32(&nullifier_hash_bytes));
				let path_indices = path_indices_bytes
					.iter()
					.map(|x| CompressedRistretto::from_slice(x))
					.collect();
				let path_nodes = path_nodes_bytes
					.iter()
					.map(|x| CompressedRistretto::from_slice(x))
					.collect();
				let recipient = Scalar::from_bytes_mod_order(slice_to_bytes_32(&recipient_bytes));
				let relayer = Scalar::from_bytes_mod_order(slice_to_bytes_32(&relayer_bytes));
				self.verify_bulletproofs_poseidon(
					depth,
					root,
					private_inputs,
					nullifier_hash,
					proof_bytes,
					path_indices,
					path_nodes,
					recipient,
					relayer,
				)
			}
			Backend::Arkworks(Curve::Bls381, Snark::Groth16) => {
				let nullifier_elts =
					to_field_elements::<Bls381>(&nullifier_hash_bytes).map_err(|_| Error::<C>::InvalidPublicInputs)?;
				let root_elts =
					to_field_elements::<Bls381>(&root_bytes).map_err(|_| Error::<C>::InvalidPublicInputs)?;
				let recipient_elts =
					to_field_elements::<Bls381>(&recipient_bytes).map_err(|_| Error::<C>::InvalidPublicInputs)?;
				let relayer_elts =
					to_field_elements::<Bls381>(&relayer_bytes).map_err(|_| Error::<C>::InvalidPublicInputs)?;

				let nullifier = nullifier_elts.get(0).ok_or(Error::<C>::InvalidPublicInputs)?;
				let root = root_elts.get(0).ok_or(Error::<C>::InvalidPublicInputs)?;
				let recipient = recipient_elts.get(0).ok_or(Error::<C>::InvalidPublicInputs)?;
				let relayer = relayer_elts.get(0).ok_or(Error::<C>::InvalidPublicInputs)?;

				if verifier_key.is_none() {
					return Err(Error::<C>::InvalidVerifierKey);
				}
				let vk = VerifyingKey::<Bls12_381>::deserialize(&verifier_key.unwrap()[..])
					.map_err(|_| Error::<C>::InvalidVerifierKey)?;
				let public_inputs = get_public_inputs(*nullifier, *root, *recipient, *relayer);
				let proof =
					Proof::<Bls12_381>::deserialize(&proof_bytes[..]).map_err(|_| Error::<C>::InvalidZkProof)?;
				let res = verify_groth16(&vk, &public_inputs, &proof);
				if !res {
					return Err(Error::<C>::ZkVerificationFailed);
				}

				Ok(())
			}
			_ => return Err(Error::<C>::Unimplemented),
		}
	}

	// TODO: move to bulletproofs-gadgets
	pub fn verify_bulletproofs_poseidon<C: Config>(
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
	) -> Result<(), Error<C>> {
		let pc_gens = PedersenGens::default();
		let label = b"zk_membership_proof";
		let mut verifier_transcript = Transcript::new(label);
		let mut verifier = Verifier::new(&mut verifier_transcript);

		if comms.len() != 3 {
			return Err(Error::<C>::InvalidPrivateInputs);
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
		let hasher = self.get_default_bulletproofs_poseidon()?;
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
			return Err(Error::<C>::ConstraintSystemUnsatisfied);
		}

		let proof = R1CSProof::from_bytes(&proof_bytes);
		if !proof.is_ok() {
			return Err(Error::<C>::InvalidZkProof);
		}
		let proof = proof.unwrap();

		let mut rng = OsRng::default();
		let verify_res = verifier.verify_with_rng(&proof, &hasher.pc_gens, &hasher.bp_gens, &mut rng);
		if !verify_res.is_ok() {
			return Err(Error::<C>::ZkVerificationFailed);
		}
		Ok(())
	}
}
