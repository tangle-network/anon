// helper functions for tests
use crate::clsag::Clsag;
use crate::keys::PrivateSet;
use crate::member::Member;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

// There is an exact copy of this function in member.rs
// which is being used to generate nonces. The reason is because the code in this
// file should only be used for test
pub fn generate_rand_scalars(num: usize) -> Vec<Scalar> {
    let mut rng = rand::thread_rng();
    let mut scalars = Vec::<Scalar>::with_capacity(num);

    for _ in 0..num {
        scalars.push(Scalar::random(&mut rng));
    }

    scalars
}

pub fn generate_private_set(num: usize) -> PrivateSet {
    let scalars = generate_rand_scalars(num);
    PrivateSet(scalars)
}

pub fn generate_rand_points(num: usize) -> Vec<RistrettoPoint> {
    let mut rng = rand::thread_rng();
    let mut points = Vec::<RistrettoPoint>::with_capacity(num);

    for _ in 0..num {
        points.push(RistrettoPoint::random(&mut rng));
    }

    points
}
pub fn generate_rand_compressed_points(num: usize) -> Vec<CompressedRistretto> {
    let mut rng = rand::thread_rng();
    let mut points = Vec::<CompressedRistretto>::with_capacity(num);

    for _ in 0..num {
        points.push(RistrettoPoint::random(&mut rng).compress());
    }

    points
}

pub fn generate_decoy(num_keys: usize) -> Member {
    let points = generate_rand_points(num_keys);
    Member::new_decoy(points)
}

pub fn generate_decoys(num_decoys: usize, num_keys: usize) -> Vec<Member> {
    let mut decoys: Vec<Member> = Vec::with_capacity(num_decoys);
    for _ in 0..num_decoys {
        decoys.push(generate_decoy(num_keys));
    }
    decoys
}

pub fn generate_signer(num_keys: usize) -> Member {
    let scalars = generate_rand_scalars(num_keys);
    Member::new_signer(scalars)
}

pub fn generate_clsag_with(num_decoys: usize, num_keys: usize) -> Clsag {
    let mut clsag = Clsag::new();

    for _ in 0..num_decoys {
        clsag.add_member(generate_decoy(num_keys));
    }

    clsag
}