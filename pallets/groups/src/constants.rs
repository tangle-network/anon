#![cfg_attr(not(feature = "std"), no_std)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;

pub const BASEPOINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;