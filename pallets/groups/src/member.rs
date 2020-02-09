#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::prelude::*;
use crate::constants::BASEPOINT;
use crate::keys::{PrivateSet, PublicSet};
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;

#[derive(Debug)]
pub enum Error {
    // Occurs when you try to use a method specific to
    // a signer as a decoy
    NotASigner,
    // Occurs when you try to use a method specific to
    // a decoy as a signer
    NotADecoy,
}

// A member represents a member in the ring
// This includes the signer of the ring
#[derive(Clone)]
pub struct Member {
    // The signer is the only member with a set of private keys
    private_set: Option<PrivateSet>,

    pub(crate) public_set: PublicSet,

    // This is the hash of the first public key
    // in the public set.
    hashed_pubkey_basepoint: RistrettoPoint,

    // The signing member will have a nonce.
    // In an sigma protocol, this nonce would signify the commit phase.
    pub(crate) nonce: Option<Scalar>,

    // Each member will have a response value.
    // In an sigma protocol, this would signify the reponse phase.
    pub(crate) response: Option<Scalar>,
}

#[cfg(feature="std")]
impl Member {
    // Creates a member who will be the signer of the ring
    // Protocol explicitly checks if there is one signer per ring
    pub fn new_signer(private_keys: Vec<Scalar>) -> Self {
        let private_set = PrivateSet::new(private_keys);

        let nonce = generate_rand_scalar();

        let public_set = private_set.to_public_set();

        let hashed_pubkey = public_set.hashed_pubkey();

        Member {
            nonce: Some(nonce),

            public_set: public_set,

            hashed_pubkey_basepoint: hashed_pubkey,

            private_set: Some(private_set),

            response: None,
        }
    }
    // Creates a member who will be a decoy in the ring
    pub fn new_decoy(public_keys: Vec<RistrettoPoint>) -> Self {
        let response = generate_rand_scalar();

        Self::new_decoy_with_responses(public_keys, response)
    }

    // Creates a member who will be used for verification in a signature
    pub(crate) fn new_decoy_with_responses(
        public_keys: Vec<RistrettoPoint>,
        response: Scalar,
    ) -> Self {
        let public_set = PublicSet(public_keys);
        let hashed_pubkey = public_set.hashed_pubkey();

        Member {
            nonce: None,
            public_set: public_set,
            hashed_pubkey_basepoint: hashed_pubkey,
            private_set: None,
            response: Some(response),
        }
    }
    // Returns true if the member has a set of private keys
    pub fn is_signer(&self) -> bool {
        self.private_set.is_some()
    }
    // Returns the number of keys the member has
    pub fn num_keys(&self) -> usize {
        self.public_set.len()
    }
    // Computes the key images if the member is a signer
    pub fn compute_key_images(&self) -> Result<Vec<CompressedRistretto>, Error> {
        match &self.private_set {
            Some(priv_set) => Ok(priv_set.compute_key_images(&self.hashed_pubkey_basepoint)),
            None => Err(Error::NotASigner),
        }
    }

    // This function uses the nonces to calculate the first challenge scalar
    // Effectively committing the current member; the ring will therefore
    // only be completed if the current member can generate the corresponding
    // responses per nonce, which can only be done if the current member possess
    // the discrete log to the public keys corresponding to his position in the ring.
    // returns a challenge scalar or an error if the user is not a signer
    pub fn compute_challenge_commitment(&self, pubkey_matrix: &[u8]) -> Result<Scalar, Error> {
        if !self.is_signer() {
            return Err(Error::NotASigner);
        }

        let nonce = match &self.nonce {
            Some(x) => Ok(x),
            _ => Err(Error::NotASigner),
        }?;

        let mut transcript = Transcript::new(b"clsag");

        // L = nonce * basepoint
        let l = nonce * &BASEPOINT;

        // R = nonce * hashed_pubkey
        let r = nonce * self.hashed_pubkey_basepoint;

        // Add elements to transcript
        // H(pubkey_matrix || m || L ||R)
        // XXX: Note m is omitted and will be added in a later iteration
        transcript.append_message(b"", pubkey_matrix);
        transcript.append_point(b"", &l);
        transcript.append_point(b"", &r);

        Ok(transcript.challenge_scalar(b""))
    }
    // This function is for the signer and will use the signers
    // private set to calculate the correct response value
    // mu_x and mu_j are the aggregation co-efficients
    // returns a responses or an error, if the user is not a signer
    pub fn compute_signer_response(
        &self,
        challenge: Scalar,
        agg_coeff: &[Scalar],
    ) -> Result<(Scalar), Error> {
        let private_set = self.private_set.as_ref().ok_or(Error::NotASigner)?;
        let nonce = self.nonce.as_ref().ok_or(Error::NotASigner)?;

        // t = mu_x * signing_priv_key[0]
        //sum_aux = sum(mu_j * auxilary_priv_keys)
        // response = nonce - challenge(t + sum_aux)
        // let t = mu_x * private_set.0[0];
        let sum_aux: Scalar = private_set
            .0
            .iter()
            .zip(agg_coeff.iter())
            .map(|(x, mu)| x * mu)
            .sum();
        let response = nonce - challenge * (sum_aux);

        Ok(response)
    }
    // This function is ran by all members who did not compute the challenge commitment (decoys)
    // Each member that runs this function, will link themselves to the ring using the challenge
    // passed to them by the newest member of the ring.
    // returns a challenge scalar, to be used by the next member who wants to join the ring
    pub fn compute_decoy_challenge(
        &self,
        challenge: &Scalar,
        key_images: &[CompressedRistretto],
        agg_coeffs: &[Scalar],
        pubkey_matrix: &[u8],
    ) -> Result<Scalar, Error> {
        if self.private_set.is_some() {
            return Err(Error::NotADecoy);
        }

        let response = self.response.as_ref().ok_or(Error::NotASigner)?;

        assert_eq!(self.public_set.len(), key_images.len());

        let challenge = compute_challenge_ring(
            &self.public_set.to_keys(),
            challenge,
            key_images,
            response,
            agg_coeffs,
            &self.hashed_pubkey_basepoint,
            pubkey_matrix,
        );

        Ok(challenge)
    }
}
// A generic function to calculate the challenge for any member in the ring
// While signing, this function will be used by the decoys
// When verifying this function will be used by all members
#[cfg(feature="std")]
pub fn compute_challenge_ring(
    public_keys: &[CompressedRistretto],
    challenge: &Scalar,
    key_images: &[CompressedRistretto],
    response: &Scalar,
    agg_coeffs: &[Scalar],
    hashed_pubkey_point: &RistrettoPoint,
    pubkey_matrix: &[u8],
) -> Scalar {
    let challenge_agg_coeffs: Vec<Scalar> = agg_coeffs.iter().map(|ac| ac * challenge).collect();

    //sum_aux_point = sum(mu_j * auxilary_public_keys)
    // L =response * G + challenge (sum_aux_point)
    let sum_aux_point = RistrettoPoint::optional_multiscalar_mul(
        &challenge_agg_coeffs,
        public_keys.iter().map(|pt| pt.decompress()),
    )
    .unwrap();
    let l = (response * BASEPOINT) + sum_aux_point;

    // K = response * hashed_pubkey_point
    //sum_aux_images = sum(mu_j * aux_key_images)
    // R = K  + challenge (sum_aux_images)
    let k = response * hashed_pubkey_point;
    let sum_aux_images = RistrettoPoint::optional_multiscalar_mul(
        &challenge_agg_coeffs,
        key_images.iter().map(|pt| pt.decompress()),
    )
    .unwrap();
    let r = k + sum_aux_images;

    let mut transcript = Transcript::new(b"clsag");

    // Add elements to transcript
    transcript.append_message(b"", pubkey_matrix);
    transcript.append_point(b"", &l);
    transcript.append_point(b"", &r);

    transcript.challenge_scalar(b"")
}

#[cfg(feature = "std")]
fn generate_rand_scalar() -> Scalar {
    let mut rng = rand::thread_rng();
    Scalar::random(&mut rng)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests_helper::generate_rand_scalars;

    // Simple tests to check that when the members are instantiated
    // We have the correct number of values
    #[test]
    fn test_new() {
        let num_private_keys = 10;
        let scalars = generate_rand_scalars(num_private_keys);

        let signer = Member::new_signer(scalars);

        // We should have a nonce for the signer
        match signer.nonce {
            Some(_) => {}
            None => panic!(
                "We should not have a `None` value here as we have instantiated a signing member"
            ),
        }

        // The number of private keys argument we passed in as an argument
        //should equal the length of the private key set
        match signer.private_set {
            Some(priv_set) => {
                assert_eq!(priv_set.len(), num_private_keys);
            }
            _ => panic!("we should not have a `None` value for the private key set"),
        }

        // The number of private keys argument we passed in as an argument
        //should equal the length of the public key set
        assert_eq!(signer.public_set.len(), num_private_keys)
    }
}
