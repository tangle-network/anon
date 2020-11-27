#[macro_use]
extern crate bencher;

use pallet_merkle::merkle::helper::{prove, verify};
use pallet_merkle::merkle::mimc::Mimc;
use pallet_merkle::merkle::poseidon::Poseidon;

use bencher::Bencher;

fn verify_32h_binary_poseidon(b: &mut Bencher) {
	let poseidon = Poseidon::new(6);
	let (lh, com_leaf, path, com_s, null, proof) = prove(&poseidon);
	b.bench_n(3, |new_b| {
		new_b.iter(|| verify(&poseidon, lh, com_leaf, &path, com_s, null, &proof))
	});
}

// fn verify_32h_binary_mimc(b: &mut Bencher) {
// 	let mimc = Mimc::new(162);
// 	let (lh, com_leaf, path, com_s, null, proof) = prove(&mimc);
// 	b.bench_n(1, |new_b| {
// 		new_b.iter(|| verify(&mimc, lh, com_leaf, &path, com_s, null, &proof))
// 	});
// }

benchmark_group!(benches, verify_32h_binary_poseidon);
benchmark_main!(benches);
