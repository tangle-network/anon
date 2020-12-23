#[macro_use]
extern crate bencher;

use pallet_merkle::merkle::helper::{prove, verify};
use pallet_merkle::merkle::mimc::Mimc;
use pallet_merkle::merkle::poseidon::Poseidon;

use bencher::Bencher;

fn verify_32h_binary_poseidon(b: &mut Bencher) {
	let poseidon = Poseidon::new(4);
	let (_, root, zk_proof) = prove(&poseidon);
	b.bench_n(3, |new_b| {
		new_b.iter(|| verify(root, zk_proof.clone(), &poseidon))
	});
}

benchmark_group!(benches, verify_32h_binary_poseidon);
benchmark_main!(benches);
