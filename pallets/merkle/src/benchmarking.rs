#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_system::RawOrigin;

use crate::Module as Merkle;

fn setup_tree<T: Config>(caller: T::AccountId) {
	let manager_required = true;
	let depth = 32;
	<Merkle<T> as Group<T::AccountId, T::BlockNumber, T::GroupId>>::create_group(caller, manager_required, depth);
}

benchmarks! {
	create_group {
		let caller = whitelisted_caller();
	}:
	// Creating a group with highest possible depth
	// TODO: figure out how to add weights based on tree depth
	_(RawOrigin::Signed(caller), false, None)
	verify {
		let next_id: T::GroupId = NextGroupId::<T>::get();
		assert_eq!(next_id, 1.into());
	}

	set_manager_required {
		let caller: T::AccountId = whitelisted_caller();
		// Tree is setup with manager required
		setup_tree::<T>(caller.clone());
		// Then we are setting in to false
	}: _(RawOrigin::Signed(caller.clone()), 0.into(), false)
	verify {
		// Checking if manager is caller and is not required
		let group_id: T::GroupId = 0.into();
		let manager = Managers::<T>::get(group_id).unwrap();
		assert_eq!(manager.required, false);
		assert_eq!(manager.account_id, caller.into());
	}

	// TBD
	set_manager {
		let caller: T::AccountId = whitelisted_caller();
	}: _(RawOrigin::Signed(caller.clone()), 0.into(), caller.clone())
	verify {
	}

	// TBD
	set_stopped {
		let caller: T::AccountId = whitelisted_caller();
	}: _(RawOrigin::Signed(caller.clone()), 0.into(), false)
	verify {
	}

	// TBD
	add_members {
		let caller: T::AccountId = whitelisted_caller();
	}: _(RawOrigin::Signed(caller.clone()), 0.into(), vec![])
	verify {
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::{new_test_ext, Test};
	use frame_support::assert_ok;

	#[test]
	fn test_create_group() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_create_group::<Test>());
		});
	}

	#[test]
	fn test_set_manager_required() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_set_manager_required::<Test>());
		});
	}

	#[test]
	fn test_set_manager() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_set_manager::<Test>());
		});
	}

	#[test]
	fn test_set_stopped() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_set_stopped::<Test>());
		});
	}

	#[test]
	fn test_add_members() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_add_members::<Test>());
		});
	}
}
