#[macro_use]
extern crate bencher;

use pallet_merkle::merkle::{
	helper::{prove_with_random_leaf, verify},
	mimc::Mimc,
	poseidon::Poseidon,
};

use bencher::Bencher;

fn verify_32h_binary_poseidon(b: &mut Bencher) {
	let poseidon = Poseidon::new(4);
	let (_, root, zk_proof) = prove_with_random_leaf(&poseidon);
	b.bench_n(3, |new_b| {
		new_b.iter(|| verify(root, zk_proof.clone(), &poseidon))
	});
}

benchmark_group!(benches, verify_32h_binary_poseidon);
benchmark_main!(benches);
