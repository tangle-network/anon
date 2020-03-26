use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use sha2::Sha512;

/// Extension trait to the Merlin transcript API that allows committing scalars and points and
/// generating challenges as scalars.
pub trait TranscriptProtocol {
    /// Appends a `point` with a given label
    fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint);

    /// Appends `scalar * point` with a given label
    fn append_scalar_mult(&mut self, label: &'static [u8], scalar: &Scalar, point: &RistrettoPoint);

    /// Appends `scalar * hash_to_point(point)` with a given label
    fn append_scalar_hash_point(
        &mut self,
        label: &'static [u8],
        scalar: &Scalar,
        point: &RistrettoPoint,
    );

    /// Given (s_1, s_2) and (P_1, P_2)
    /// Appends s_1 * P_1 + s_2 * P_2 with a given label
    fn append_double_scalar_mult_add(
        &mut self,
        label: &'static [u8],
        scalars: (&Scalar, &Scalar),
        points: (&RistrettoPoint, &RistrettoPoint),
    );

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn append_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        self.append_message(label, point.compress().as_bytes());
    }

    fn append_scalar_mult(
        &mut self,
        label: &'static [u8],
        scalar: &Scalar,
        point: &RistrettoPoint,
    ) {
        let new_point = scalar * point;
        self.append_message(label, new_point.compress().as_bytes());
    }

    fn append_scalar_hash_point(
        &mut self,
        label: &'static [u8],
        scalar: &Scalar,
        point: &RistrettoPoint,
    ) {
        let hashed_point = RistrettoPoint::hash_from_bytes::<Sha512>(point.compress().as_bytes());
        let scalar_hashed_point = scalar * hashed_point;
        self.append_message(label, scalar_hashed_point.compress().as_bytes());
    }

    fn append_double_scalar_mult_add(
        &mut self,
        label: &'static [u8],
        scalars: (&Scalar, &Scalar),
        points: (&RistrettoPoint, &RistrettoPoint),
    ) {
        let left_scalar_mult = scalars.0 * points.0;
        let right_scalar_mult = scalars.1 * points.1;

        let new_point = left_scalar_mult + right_scalar_mult;
        self.append_message(label, new_point.compress().as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }
}