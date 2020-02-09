use sp_std::prelude::*;
use crate::clsag::calc_aggregation_coefficients;
use crate::constants::BASEPOINT;
#[cfg(feature="std")]
use crate::member::compute_challenge_ring;

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use sha2::Sha512;

#[cfg(feature="std")]
#[derive(Debug, Clone)]
pub struct Signature {
    pub(crate) challenge: Scalar,
    pub(crate) responses: Vec<Scalar>,
    pub(crate) key_images: Vec<CompressedRistretto>,
}

#[cfg(feature="std")]
pub enum Error {
    // This error occurs if the signature contains an amount of public keys
    // that does not match the number of public keys
    IncorrectNumOfPubKeys,
    // This error occurs when either one of the key images supplied cannot be decompressed
    BadKeyImages,
    // This error occurs when the calculated challenge is different from the challenge in the signature
    ChallengeMismatch,
    // This error occurs when the point cannot be correctly decompressed
    BadPoint,
    // This error occurs when an underlying error from the member package occurs
    MemberError(String),
}

#[cfg(feature="std")]
impl From<crate::member::Error> for Error {
    fn from(e: crate::member::Error) -> Error {
        let err_string = format!(" underlying member error {:?}", e);
        Error::MemberError(err_string)
    }
}

#[cfg(feature="std")]
impl Signature {
    pub fn verify(&self, public_keys: &mut Vec<Vec<CompressedRistretto>>) -> Result<(), Error> {
        // Skip subgroup check as ristretto points have co-factor 1.

        let num_responses = self.responses.len();
        let num_pubkey_sets = public_keys.len();

        // -- Check that we have the correct amount of public keys
        if num_pubkey_sets != num_responses {
            return Err(Error::IncorrectNumOfPubKeys);
        }

        let pubkey_matrix_bytes: Vec<u8> = self.pubkeys_to_bytes(public_keys);

        // Calculate aggregation co-efficients
        let agg_coeffs = calc_aggregation_coefficients(&pubkey_matrix_bytes, &self.key_images);

        let mut challenge = self.challenge.clone();
        for (pub_keys, response) in public_keys.iter().zip(self.responses.iter()) {
            let first_pubkey = pub_keys[0];
            let hashed_pubkey = RistrettoPoint::hash_from_bytes::<Sha512>(first_pubkey.as_bytes());
            challenge = compute_challenge_ring(
                pub_keys,
                &challenge,
                &self.key_images,
                response,
                &agg_coeffs,
                &hashed_pubkey,
                &pubkey_matrix_bytes,
            );
        }

        if self.challenge != challenge {
            return Err(Error::ChallengeMismatch);
        }

        Ok(())
    }

    pub fn optimised_verify(
        &self,
        public_keys: &mut Vec<Vec<CompressedRistretto>>,
    ) -> Result<(), Error> {
        // Skip subgroup check as ristretto points have co-factor 1.

        let num_responses = self.responses.len();
        let num_pubkey_sets = public_keys.len();

        // -- Check that we have the correct amount of public keys
        if num_pubkey_sets != num_responses {
            return Err(Error::IncorrectNumOfPubKeys);
        }

        // Calculate all response * BASEPOINT
        let response_points: Vec<RistrettoPoint> = self
            .responses
            .iter()
            .map(|response| response * BASEPOINT)
            .collect();

        // calculate all response * H(signingKeys)
        let response_hashed_points: Vec<RistrettoPoint> = self
            .responses
            .iter()
            .zip(public_keys.iter())
            .map(|(response, pub_keys)| {
                let first_pubkey = pub_keys[0];
                let hashed_pubkey =
                    RistrettoPoint::hash_from_bytes::<Sha512>(first_pubkey.as_bytes());

                response * hashed_pubkey
            })
            .collect();

        // compute the public key bytes
        let pubkey_matrix_bytes = self.pubkeys_to_bytes(public_keys);

        // Calculate aggregation co-efficients
        let agg_coeffs = calc_aggregation_coefficients(&pubkey_matrix_bytes, &self.key_images);

        let mut challenge = self.challenge.clone();

        for ((resp_point, resp_hashed_point), pub_keys) in response_points
            .iter()
            .zip(response_hashed_points.iter())
            .zip(public_keys.iter())
        {
            let challenge_agg_coeffs: Vec<Scalar> =
                agg_coeffs.iter().map(|ac| ac * &challenge).collect();

            let mut l_i = RistrettoPoint::optional_multiscalar_mul(
                &challenge_agg_coeffs,
                pub_keys.iter().map(|pt| pt.decompress()),
            )
            .ok_or(Error::BadPoint)?;
            l_i = l_i + resp_point;

            let mut r_i = RistrettoPoint::optional_multiscalar_mul(
                &challenge_agg_coeffs,
                self.key_images.iter().map(|pt| pt.decompress()),
            )
            .ok_or(Error::BadPoint)?;
            r_i = r_i + resp_hashed_point;

            let mut transcript = Transcript::new(b"clsag");
            transcript.append_message(b"", &pubkey_matrix_bytes);
            transcript.append_point(b"", &l_i);
            transcript.append_point(b"", &r_i);

            challenge = transcript.challenge_scalar(b"");
        }

        if challenge != self.challenge {
            return Err(Error::ChallengeMismatch);
        }

        Ok(())
    }

    fn pubkeys_to_bytes(&self, pubkey_matrix: &Vec<Vec<CompressedRistretto>>) -> Vec<u8> {
        let mut bytes: Vec<u8> =
            Vec::with_capacity(self.key_images.len() * self.responses.len() * 64);
        for i in 0..pubkey_matrix.len() {
            let pubkey_bytes: Vec<u8> = pubkey_matrix[i]
                .iter()
                .map(|pubkey| pubkey.to_bytes().to_vec())
                .flatten()
                .collect();
            bytes.extend(pubkey_bytes);
        }
        bytes
    }
}

#[cfg(test)]
mod test {
    use crate::tests_helper::*;

    #[test]
    fn test_verify() {
        let num_keys = 1;
        let num_decoys = 1;

        let mut clsag = generate_clsag_with(num_decoys, num_keys);
        clsag.add_member(generate_signer(num_keys));
        let sig = clsag.sign().unwrap();
        let mut pub_keys = clsag.public_keys();

        let expected_pubkey_bytes = clsag.public_keys_bytes();
        let have_pubkey_bytes = sig.pubkeys_to_bytes(&pub_keys);

        assert_eq!(expected_pubkey_bytes, have_pubkey_bytes);
        assert!(sig.optimised_verify(&mut pub_keys).is_ok());
    }

    #[test]
    fn test_verify_fail_incorrect_num_keys() {
        let num_keys = 2;
        let num_decoys = 11;

        let mut clsag = generate_clsag_with(num_decoys, num_keys);
        clsag.add_member(generate_signer(num_keys));
        let sig = clsag.sign().unwrap();
        let mut pub_keys = clsag.public_keys();

        // Add extra key
        let extra_key = generate_rand_compressed_points(num_keys);
        pub_keys.push(extra_key);
        assert!(sig.optimised_verify(&mut pub_keys).is_err());

        // remove the extra key and test should pass
        pub_keys.remove(pub_keys.len() - 1);
        assert!(sig.optimised_verify(&mut pub_keys).is_ok());

        // remove another key and tests should fail
        pub_keys.remove(pub_keys.len() - 1);
        assert!(sig.optimised_verify(&mut pub_keys).is_err());
    }
}