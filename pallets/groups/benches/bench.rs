#[macro_use]
extern crate bencher;

use pallet_groups::tests_helper::*;
use bencher::Bencher;

fn bench_verify_2(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 2;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_4(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 3;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_6(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 5;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_8(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 7;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_11(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 10;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_16(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 15;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_32(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 31;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_64(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 63;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_128(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 127;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_256(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 255;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

fn bench_verify_512(b: &mut Bencher) {
    let num_keys = 2;
    let num_decoys = 511;

    let mut clsag = generate_clsag_with(num_decoys, num_keys);
    clsag.add_member(generate_signer(num_keys));
    let sig = clsag.sign().unwrap();
    let mut pub_keys = clsag.public_keys();

    b.iter(|| sig.optimised_verify(&mut pub_keys));
}

benchmark_group!(benches,
    bench_verify_2,
    bench_verify_4,
    bench_verify_6,
    bench_verify_8,
    bench_verify_11,
    bench_verify_16,
    bench_verify_32,
    bench_verify_64,
    bench_verify_128,
    bench_verify_256,
    bench_verify_512,
);
benchmark_main!(benches);