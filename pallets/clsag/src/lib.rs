#![cfg_attr(not(feature = "std"), no_std)]

/// A runtime module Groups with necessary imports

/// Feel free to remove or edit this file as needed.
/// If you change the name of this file, make sure to update its references in runtime/src/lib.rs
/// If you remove this file, you can remove those references


/// For more guidance on Substrate modules, see the example module
/// https://github.com/paritytech/substrate/blob/master/frame/example/src/lib.rs

pub mod clsag;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
pub mod tests;

use sha2::Sha512;
use clsag::transcript::TranscriptProtocol;
use clsag::clsag::calc_aggregation_coefficients;
use clsag::constants::BASEPOINT;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use merlin::Transcript;

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch, ensure};
use frame_system::{ensure_signed};
use sp_std::prelude::*;

pub type RingPK = clsag::keys::RingPublicKey;
// pub type RingPK = [u8;32];

/// The pallet's configuration trait.
pub trait Trait: frame_system::Trait {
	// Add other types and constants required to configure this pallet.

	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
}

type GroupId = u32;

// This pallet's storage items.
decl_storage! {
	trait Store for Module<T: Trait> as CLSAGGroups {
		Groups get(fn groups): map hasher(blake2_128_concat) GroupId => Option<Vec<RingPK>>;
	}
}

// The pallet's events
decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		NewMember(u32, AccountId, RingPK),
	}
);

// The pallet's errors
decl_error! {
	pub enum Error for Module<T: Trait> {
		/// Value was None
		NoneValue,
		/// 
		IncorrectNumOfPubKeys,
		///
		ChallengeMismatch,
		///
		BadPoint,
	}
}

// The pallet's dispatchable functions.
decl_module! {
	/// The module declaration.
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;

		fn deposit_event() = default;

		#[weight = 0]
		pub fn add_member(origin, group_id: u32, pub_key: RingPK) -> dispatch::DispatchResult {
			// Check it was signed and get the signer. See also: ensure_root and ensure_none
			let who = ensure_signed(origin)?;

			// Code to execute when something calls this.
			// For example: the following line stores the passed in u32 in the storage
			let mut group = {
				match Self::groups(group_id) {
					Some(g) => g,
					None => vec![],
				}
			};
			// add new member
			group.push(pub_key.clone());
			<Groups>::insert(group_id, group);

			// Here we are raising the Something event
			Self::deposit_event(RawEvent::NewMember(group_id, who, pub_key));
			Ok(())
		}

		#[weight = 0]
		pub fn verify_ring_sig(
			origin,
			group_id: GroupId,
			_challenge: clsag::keys::RingScalar,
			_responses: Vec<clsag::keys::RingScalar>,
			_key_images: Vec<RingPK>,
			_msg: Option<[u8; 32]>,
		) -> dispatch::DispatchResult {
			// Check it was signed and get the signer. See also: ensure_root and ensure_none
			let _who = ensure_signed(origin)?;
			// Skip subgroup check as ristretto points have co-factor 1.
			let group = <Groups>::get(group_id).unwrap_or(Vec::new());
			ensure!(group.len() > 0, Error::<T>::NoneValue);

			let num_responses = _responses.len();
			let num_pubkey_sets = group.len();
			// Check that we have the correct amount of public keys
			ensure!(num_pubkey_sets == num_responses, Error::<T>::IncorrectNumOfPubKeys);
			// Calculate all response * BASEPOINT
			let response_points: Vec<RistrettoPoint> = _responses
				.iter()
				.map(|response| response.0 * BASEPOINT)
				.collect();

			// calculate all response * H(signingKeys)
			let response_hashed_points: Vec<RistrettoPoint> = _responses
				.iter()
				.zip(group.iter())
				.map(|(response, pub_key)| {
					let first_pubkey = pub_key.0;
					let hashed_pubkey =
						RistrettoPoint::hash_from_bytes::<Sha512>(first_pubkey.as_bytes());

					response.0 * hashed_pubkey
				})
				.collect();


			let pub_key_matrix: Vec<u8> = {
				let mut bytes: Vec<u8> = Vec::with_capacity(_key_images.len() * _responses.len() * 64);
				for i in 0..group.len() {
					let pubkey_bytes: Vec<u8> = group[i].to_bytes().to_vec();
					bytes.extend(pubkey_bytes);
				}
				bytes
			};

			let msg = _msg.unwrap_or(*b"hello world world world world wo");
			// Calculate aggregation co-efficients
			let k_images: Vec<CompressedRistretto> = _key_images.iter().map(|x| x.0).collect();
			let agg_coeffs = calc_aggregation_coefficients(&pub_key_matrix, &k_images, &msg);

			let mut challenge = _challenge.clone();

			for ((resp_point, resp_hashed_point), pub_key) in response_points
				.iter()
				.zip(response_hashed_points.iter())
				.zip(group.iter())
			{
				let challenge_agg_coeffs: Vec<Scalar> =
					agg_coeffs.iter().map(|ac| ac * &challenge.0).collect();

				let mut l_i = RistrettoPoint::optional_multiscalar_mul(
					&challenge_agg_coeffs,
					vec![pub_key].iter().map(|pt| pt.0.decompress()),
				)
				.ok_or(Error::<T>::BadPoint)?;
				l_i = l_i + resp_point;

				let mut r_i = RistrettoPoint::optional_multiscalar_mul(
					&challenge_agg_coeffs,
					_key_images.iter().map(|pt| pt.0.decompress()),
				)
				.ok_or(Error::<T>::BadPoint)?;
				r_i = r_i + resp_hashed_point;

				let mut transcript = Transcript::new(b"clsag");
				transcript.append_message(b"", &pub_key_matrix);
				transcript.append_point(b"", &l_i);
				transcript.append_point(b"", &r_i);

				challenge = clsag::keys::RingScalar(transcript.challenge_scalar(b""));
			}

			ensure!(challenge == _challenge, Error::<T>::ChallengeMismatch);
			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
	pub fn get_members(group_id: u32) -> Option<Vec<RingPK>> {
		return <Groups>::get(group_id);
	}
}
