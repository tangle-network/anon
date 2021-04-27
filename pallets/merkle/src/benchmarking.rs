use super::*;
use bulletproofs_gadgets::poseidon::Poseidon_hash_2;
use frame_benchmarking::{account, benchmarks, whitelisted_caller};
use frame_support::traits::OnFinalize;
use frame_system::{Pallet as System, RawOrigin};
use utils::keys::ScalarData;

use crate::Pallet as Merkle;

const MAX_DEPTH: u8 = 32;
const NUM_LEAVES: u32 = 10;
const VERIFY_DEPTH: u8 = 10;

fn setup_tree<T: Config>(caller: T::AccountId, depth: u32) {
	let manager_required = true;
	<Merkle<T> as Tree<T::AccountId, T::BlockNumber, T::TreeId>>::create_tree(caller, manager_required, depth as u8)
		.unwrap();
}

fn get_proof(depth: u32) -> Vec<(bool, ScalarData)> {
	let hasher = default_hasher();
	let mut d = ScalarData::zero();
	let mut path = Vec::new();
	for i in 0..depth {
		path.push((true, d));
		d = ScalarData(Poseidon_hash_2(d.0, d.0, &hasher));
	}
	path
}

benchmarks! {
	create_tree {
		// Testing the function for all depths between 0 to 32
		// Creates a weight function that accepts tree depth
		// and calculates the weights on the run
		let d in 1 .. MAX_DEPTH as u32;
		let caller = whitelisted_caller();
	}: _(RawOrigin::Signed(caller), false, Some(d as u8))
	verify {
		let next_id: T::TreeId = Merkle::<T>::next_tree_id();
		let curr_id = next_id - 1u32.into();
		let tree: MerkleTree = Trees::<T>::get(curr_id).unwrap();
		assert_eq!(tree.depth, d as u8);
	}

	set_manager_required {
		let caller: T::AccountId = whitelisted_caller();
		// Tree is setup with manager required
		setup_tree::<T>(caller.clone(), 32);
	}:
	// Manager is not required initially
	_(RawOrigin::Signed(caller.clone()), 0u32.into(), false)
	verify {
		// Checking if manager is caller and is not required
		let tree_id: T::TreeId = 0u32.into();
		let manager = Managers::<T>::get(tree_id).unwrap();
		assert_eq!(manager.required, false);
		assert_eq!(manager.account_id, caller.into());
	}

	set_manager {
		let caller: T::AccountId = whitelisted_caller();
		// Making an account id for new admin
		let new_admin: T::AccountId = account("new_admin", 0, 0);
		setup_tree::<T>(caller.clone(), 32);
	}:
	// Transfering the admin role to `new_admin`
	_(RawOrigin::Signed(caller), 0u32.into(), new_admin.clone())
	verify {
		let tree_id: T::TreeId = 0u32.into();
		let manager = Managers::<T>::get(tree_id).unwrap();
		assert_eq!(manager.required, true);
		assert_eq!(manager.account_id, new_admin);
	}

	set_stopped {
		let caller: T::AccountId = whitelisted_caller();
		setup_tree::<T>(caller.clone(), 32);
	}:
	// Setting the stopped storage item, this doesnt't effect
	// any other functionality of the tree
	_(RawOrigin::Signed(caller.clone()), 0u32.into(), true)
	verify {
		let tree_id: T::TreeId = 0u32.into();
		let stopped = Stopped::<T>::get(tree_id);
		assert!(stopped);
	}

	add_members {
		// This means that the test will run `NUM_LEAVES` times
		// Each time it runs, new value of `n` will be set
		// This will make weights function based on number of leaves
		let n in 1 .. NUM_LEAVES;
		let caller: T::AccountId = whitelisted_caller();
		// Create leaves based on `n`
		let leaves = vec![ScalarData::zero(); n as usize];

		setup_tree::<T>(caller.clone(), 32);
	}: _(RawOrigin::Signed(caller.clone()), 0u32.into(), leaves)
	verify {
		let tree_id: T::TreeId = 0u32.into();
		let tree: MerkleTree = Trees::<T>::get(tree_id).unwrap();
		assert_eq!(tree.leaf_count, n);
	}

	verify_path {
		let d in 1 .. VERIFY_DEPTH as u32;
		let caller: T::AccountId = whitelisted_caller();
		let leaf_data = ScalarData::zero();
		setup_tree::<T>(caller.clone(), d);
		let path = get_proof(d);
	}: verify(RawOrigin::Signed(caller), 0u32.into(), leaf_data, path)
	verify {
	}

	on_finalize {
		// For this test, runtime config has `CacheBlockLength` set to 10
		// We are running on_finalize more that 10 times to make sure
		// highest_block - lowest_block is > 10 so that
		// CachedRoots::<T>::remove_prefix is called
		let num_blocks = 13u32;

		let caller: T::AccountId = whitelisted_caller();
		setup_tree::<T>(caller.clone(), 32);
		for n in 0..num_blocks {
			let last_block_number: T::BlockNumber = n.into();
			let curr_block_number: T::BlockNumber = (n + 1).into();

			// We are doing on_finalize before the deposit
			// so that the last on_finalize can be benchmarked as a stand-alone
			Merkle::<T>::on_finalize(last_block_number);
			// Bumping the block number so that we can add cached roots to it
			System::<T>::set_block_number(curr_block_number);
			// Adding 100 leaves every block
			let leaves = vec![ScalarData::from([42; 32]); 100];
			Merkle::<T>::add_members(RawOrigin::Signed(caller.clone()).into(), 0u32.into(), leaves).unwrap();
		}
	}: {
		// Calling on finalize
		let last_block: T::BlockNumber = num_blocks.into();
		Merkle::<T>::on_finalize(last_block);
	}
	verify {
		let latest_block: T::BlockNumber = HighestCachedBlock::<T>::get();
		let block_number: T::BlockNumber = num_blocks.into();
		assert_eq!(latest_block, block_number);
	}

}

// TODO: replace with impl_benchmark_test_suite macro:
// https://github.com/paritytech/substrate/blob/master/frame/lottery/src/benchmarking.rs#L173-L177
#[cfg(test)]
mod bench_tests {
	use super::*;
	use crate::mock::{new_test_ext, Test};
	use frame_support::assert_ok;

	#[test]
	fn test_create_tree() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_create_tree::<Test>());
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

	#[test]
	fn test_verify_path() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_verify_path::<Test>());
		});
	}

	#[test]
	fn test_on_finalize() {
		new_test_ext().execute_with(|| {
			assert_ok!(test_benchmark_on_finalize::<Test>());
		});
	}
}
