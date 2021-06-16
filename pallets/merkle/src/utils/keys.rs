//! Type definitions used in merkle pallet
use curve25519_dalek::ristretto::CompressedRistretto;
use bulletproofs::BulletproofGens;
use sp_std::prelude::*;
use codec::{Input};
pub type ScalarBytes = Vec<u8>;

pub fn slice_to_bytes_32(vec: &[u8]) -> [u8; 32] {
	let mut bytes_array = [0u8; 32];
	bytes_array
		.iter_mut()
		.enumerate()
		.for_each(|(i, x)| *x = *vec.get(i).unwrap_or(&0u8));
	bytes_array
}

pub fn get_bp_gen_bytes(bp_gens: &BulletproofGens) -> Vec<u8> {
	let g_vec_bytes = bp_gens
		.G_vec
		.iter()
		.map(|vec| {
			vec.iter()
				.map(|pt| pt.compress().to_bytes())
				.fold(vec![], |mut acc, curr| {
					// inside inner len (except this should always be 32 bytes so we can drop the
					// length) NOT_NEEDED - acc.append(&mut
					// curr.to_vec().len().to_be_bytes().to_vec()); inside inner data
					acc.append(&mut curr.to_vec());
					acc
				})
		})
		.fold(vec![], |mut acc, curr| {
			// inner len
			acc.append(&mut (curr.to_vec().len() as u32).to_be_bytes().to_vec());
			// inner data
			acc.append(&mut curr.to_vec());
			acc
		});

	let h_vec_bytes = bp_gens
		.H_vec
		.iter()
		.map(|vec| {
			vec.iter()
				.map(|pt| pt.compress().to_bytes())
				.fold(vec![], |mut acc, curr| {
					// inside inner len (except this should always be 32 bytes so we can drop the
					// length) NOT_NEEDED - acc.append(&mut
					// curr.to_vec().len().to_be_bytes().to_vec()); inside inner data
					acc.append(&mut curr.to_vec());
					acc
				})
		})
		.fold(vec![], |mut acc, curr| {
			// inner len
			acc.append(&mut (curr.to_vec().len() as u32).to_be_bytes().to_vec());
			// inner data
			acc.append(&mut curr.to_vec());
			acc
		});

	let mut bytes = vec![];
	bytes.extend_from_slice(&(bp_gens.gens_capacity as u32).to_be_bytes());
	bytes.extend_from_slice(&(bp_gens.party_capacity as u32).to_be_bytes());
	bytes.extend_from_slice(&(g_vec_bytes.len() as u32).to_be_bytes());
	bytes.extend_from_slice(&g_vec_bytes);
	bytes.extend_from_slice(&(h_vec_bytes.len() as u32).to_be_bytes());
	bytes.extend_from_slice(&h_vec_bytes);
	bytes
}

pub fn from_bytes_to_bp_gens(mut input: &[u8]) -> BulletproofGens {
	let mut gens_capacity_bytes = [0u8; 4];
	let _ = input.read(&mut gens_capacity_bytes);
	let gens_capacity: usize = u32::from_be_bytes(gens_capacity_bytes) as usize;

	let mut party_capacity_bytes = [0u8; 4];
	let _ = input.read(&mut party_capacity_bytes);
	let party_capacity: usize = u32::from_be_bytes(party_capacity_bytes) as usize;

	let mut g_vec_len_bytes = [0u8; 4];
	let _ = input.read(&mut g_vec_len_bytes);
	let g_vec_len: usize = u32::from_be_bytes(g_vec_len_bytes) as usize;
	let mut g_vec = vec![0u8; g_vec_len];
	let _ = input.read(&mut g_vec);
	let mut g_slice = g_vec.as_slice();
	let mut vec_of_vecs_g = vec![];
	while g_slice.len() > 0 {
		let mut inner_vec_len = [0u8; 4];
		let _ = g_slice.read(&mut inner_vec_len);
		let inner_vec_len_u32 = u32::from_be_bytes(inner_vec_len) as usize;
		let mut inner_vec = vec![0u8; inner_vec_len_u32];
		let _ = g_slice.read(&mut inner_vec);
		let mut inner_g_slice = inner_vec.as_slice();
		let mut vec_of_points = vec![];
		while inner_g_slice.len() > 0 {
			let mut inside_inner_g_slice = [0u8; 32];
			let _ = inner_g_slice.read(&mut inside_inner_g_slice);
			vec_of_points.push(CompressedRistretto(inside_inner_g_slice).decompress().unwrap());
		}
		vec_of_vecs_g.push(vec_of_points);
	}

	let mut h_vec_len_bytes = [0u8; 4];
	let _ = input.read(&mut h_vec_len_bytes);
	let h_vec_len: usize = u32::from_be_bytes(h_vec_len_bytes) as usize;
	let mut h_vec = vec![0u8; h_vec_len];
	let _ = input.read(&mut h_vec);
	let mut h_slice = h_vec.as_slice();
	let mut vec_of_vecs_h = vec![];
	while h_slice.len() > 0 {
		let mut inner_vec_len = [0u8; 4];
		let _ = h_slice.read(&mut inner_vec_len);
		let inner_vec_len_u32 = u32::from_be_bytes(inner_vec_len) as usize;
		let mut inner_vec = vec![0u8; inner_vec_len_u32];
		let _ = h_slice.read(&mut inner_vec);
		let mut inner_h_slice = inner_vec.as_slice();
		let mut vec_of_points = vec![];
		while inner_h_slice.len() > 0 {
			let mut inside_inner_h_slice = [0u8; 32];
			let _ = inner_h_slice.read(&mut inside_inner_h_slice);
			vec_of_points.push(CompressedRistretto(inside_inner_h_slice).decompress().unwrap());
		}
		vec_of_vecs_h.push(vec_of_points);
	}

	BulletproofGens {
		gens_capacity,
		party_capacity,
		G_vec: vec_of_vecs_g,
		H_vec: vec_of_vecs_h,
	}
}

pub fn get_bp_gen_bytes(bp_gens: &BulletproofGens) -> Vec<u8> {
	let g_vec_bytes = bp_gens
		.G_vec
		.iter()
		.map(|vec| {
			vec.iter()
				.map(|pt| pt.compress().to_bytes())
				.fold(vec![], |mut acc, curr| {
					// inside inner len (except this should always be 32 bytes so we can drop the
					// length) NOT_NEEDED - acc.append(&mut
					// curr.to_vec().len().to_be_bytes().to_vec()); inside inner data
					acc.append(&mut curr.to_vec());
					acc
				})
		})
		.fold(vec![], |mut acc, curr| {
			// inner len
			acc.append(&mut (curr.to_vec().len() as u32).to_be_bytes().to_vec());
			// inner data
			acc.append(&mut curr.to_vec());
			acc
		});

	let h_vec_bytes = bp_gens
		.H_vec
		.iter()
		.map(|vec| {
			vec.iter()
				.map(|pt| pt.compress().to_bytes())
				.fold(vec![], |mut acc, curr| {
					// inside inner len (except this should always be 32 bytes so we can drop the
					// length) NOT_NEEDED - acc.append(&mut
					// curr.to_vec().len().to_be_bytes().to_vec()); inside inner data
					acc.append(&mut curr.to_vec());
					acc
				})
		})
		.fold(vec![], |mut acc, curr| {
			// inner len
			acc.append(&mut (curr.to_vec().len() as u32).to_be_bytes().to_vec());
			// inner data
			acc.append(&mut curr.to_vec());
			acc
		});

	let mut bytes = vec![];
	bytes.extend_from_slice(&(bp_gens.gens_capacity as u32).to_be_bytes());
	bytes.extend_from_slice(&(bp_gens.party_capacity as u32).to_be_bytes());
	bytes.extend_from_slice(&(g_vec_bytes.len() as u32).to_be_bytes());
	bytes.extend_from_slice(&g_vec_bytes);
	bytes.extend_from_slice(&(h_vec_bytes.len() as u32).to_be_bytes());
	bytes.extend_from_slice(&h_vec_bytes);
	bytes
}

pub fn from_bytes_to_bp_gens(mut input: &[u8]) -> BulletproofGens {
	let mut gens_capacity_bytes = [0u8; 4];
	let _ = input.read(&mut gens_capacity_bytes);
	let gens_capacity: usize = u32::from_be_bytes(gens_capacity_bytes) as usize;

	let mut party_capacity_bytes = [0u8; 4];
	let _ = input.read(&mut party_capacity_bytes);
	let party_capacity: usize = u32::from_be_bytes(party_capacity_bytes) as usize;

	let mut g_vec_len_bytes = [0u8; 4];
	let _ = input.read(&mut g_vec_len_bytes);
	let g_vec_len: usize = u32::from_be_bytes(g_vec_len_bytes) as usize;
	let mut g_vec = vec![0u8; g_vec_len];
	let _ = input.read(&mut g_vec);
	let mut g_slice = g_vec.as_slice();
	let mut vec_of_vecs_g = vec![];
	while g_slice.len() > 0 {
		let mut inner_vec_len = [0u8; 4];
		let _ = g_slice.read(&mut inner_vec_len);
		let inner_vec_len_u32 = u32::from_be_bytes(inner_vec_len) as usize;
		let mut inner_vec = vec![0u8; inner_vec_len_u32];
		let _ = g_slice.read(&mut inner_vec);
		let mut inner_g_slice = inner_vec.as_slice();
		let mut vec_of_points = vec![];
		while inner_g_slice.len() > 0 {
			let mut inside_inner_g_slice = [0u8; 32];
			let _ = inner_g_slice.read(&mut inside_inner_g_slice);
			vec_of_points.push(CompressedRistretto(inside_inner_g_slice).decompress().unwrap());
		}
		vec_of_vecs_g.push(vec_of_points);
	}

	let mut h_vec_len_bytes = [0u8; 4];
	let _ = input.read(&mut h_vec_len_bytes);
	let h_vec_len: usize = u32::from_be_bytes(h_vec_len_bytes) as usize;
	let mut h_vec = vec![0u8; h_vec_len];
	let _ = input.read(&mut h_vec);
	let mut h_slice = h_vec.as_slice();
	let mut vec_of_vecs_h = vec![];
	while h_slice.len() > 0 {
		let mut inner_vec_len = [0u8; 4];
		let _ = h_slice.read(&mut inner_vec_len);
		let inner_vec_len_u32 = u32::from_be_bytes(inner_vec_len) as usize;
		let mut inner_vec = vec![0u8; inner_vec_len_u32];
		let _ = h_slice.read(&mut inner_vec);
		let mut inner_h_slice = inner_vec.as_slice();
		let mut vec_of_points = vec![];
		while inner_h_slice.len() > 0 {
			let mut inside_inner_h_slice = [0u8; 32];
			let _ = inner_h_slice.read(&mut inside_inner_h_slice);
			vec_of_points.push(CompressedRistretto(inside_inner_h_slice).decompress().unwrap());
		}
		vec_of_vecs_h.push(vec_of_points);
	}

	BulletproofGens {
		gens_capacity,
		party_capacity,
		G_vec: vec_of_vecs_g,
		H_vec: vec_of_vecs_h,
	}
}
