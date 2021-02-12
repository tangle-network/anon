#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::RawOrigin;

benchmarks! {
	create_group {
		let caller = whitelisted_caller();
	}: _(RawOrigin::Signed(caller), false, None)
	verify {
		assert_eq!(1, 1);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::{new_test_ext, Test};
	use frame_support::assert_ok;

	#[test]
	fn test_benchmarks() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_create_group::<Test>());
		});
	}
}
