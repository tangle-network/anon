// This file is part of Substrate.

// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tests for Tokens pallet.

use super::*;
use crate::{Error, mock::*};
use frame_support::{assert_ok, assert_noop, traits::Currency};
use pallet_balances::Error as BalancesError;

/**
 * @brief      Assets tests (mostly from pallet-assets)
 */


#[test]
fn basic_minting_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 2, 100));
		assert_eq!(Tokens::free_balance(0, &2), 100);
	});
}

#[test]
fn approval_lifecycle_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		Balances::make_free_balance_be(&1, 1);
		assert_ok!(Tokens::approve_transfer(Origin::signed(1), 0, 2, 50));
		assert_eq!(Balances::reserved_balance(&1), 1);
		assert_ok!(Tokens::transfer_approved(Origin::signed(2), 0, 1, 3, 40));
		assert_ok!(Tokens::cancel_approval(Origin::signed(1), 0, 2));
		assert_eq!(Tokens::free_balance(0, &1), 60);
		assert_eq!(Tokens::free_balance(0, &3), 40);
		assert_eq!(Balances::reserved_balance(&1), 0);
	});
}

#[test]
fn approval_deposits_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 10, 1));
		assert_ok!(Tokens::mint(Origin::signed(10), 0, 1, 100));
		let e = BalancesError::<Test>::InsufficientBalance;
		assert_noop!(Tokens::approve_transfer(Origin::signed(10), 0, 2, 50), e);

		Balances::make_free_balance_be(&1, 1);
		assert_ok!(Tokens::approve_transfer(Origin::signed(1), 0, 2, 50));
		assert_eq!(Balances::reserved_balance(&1), 1);

		assert_ok!(Tokens::transfer_approved(Origin::signed(2), 0, 1, 3, 50));
		assert_eq!(Balances::reserved_balance(&1), 0);

		assert_ok!(Tokens::approve_transfer(Origin::signed(1), 0, 2, 50));
		assert_ok!(Tokens::cancel_approval(Origin::signed(1), 0, 2));
		assert_eq!(Balances::reserved_balance(&1), 0);
	});
}

#[test]
fn cannot_transfer_more_than_approved() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		Balances::make_free_balance_be(&1, 1);
		assert_ok!(Tokens::approve_transfer(Origin::signed(1), 0, 2, 50));
		let e = Error::<Test>::Unapproved;
		assert_noop!(Tokens::transfer_approved(Origin::signed(2), 0, 1, 3, 51), e);
	});
}

#[test]
fn cannot_transfer_more_than_exists() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		Balances::make_free_balance_be(&1, 1);
		assert_ok!(Tokens::approve_transfer(Origin::signed(1), 0, 2, 101));
		let e = Error::<Test>::BalanceLow;
		assert_noop!(Tokens::transfer_approved(Origin::signed(2), 0, 1, 3, 101), e);
	});
}

#[test]
fn cancel_approval_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		Balances::make_free_balance_be(&1, 1);
		assert_ok!(Tokens::approve_transfer(Origin::signed(1), 0, 2, 50));
		assert_noop!(Tokens::cancel_approval(Origin::signed(1), 1, 2), Error::<Test>::Unknown);
		assert_noop!(Tokens::cancel_approval(Origin::signed(2), 0, 2), Error::<Test>::Unknown);
		assert_noop!(Tokens::cancel_approval(Origin::signed(1), 0, 3), Error::<Test>::Unknown);
		assert_ok!(Tokens::cancel_approval(Origin::signed(1), 0, 2));
		assert_noop!(Tokens::cancel_approval(Origin::signed(1), 0, 2), Error::<Test>::Unknown);
	});
}

#[test]
fn force_cancel_approval_works() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		Balances::make_free_balance_be(&1, 1);
		assert_ok!(Tokens::approve_transfer(Origin::signed(1), 0, 2, 50));
		let e = Error::<Test>::NoPermission;
		assert_noop!(Tokens::force_cancel_approval(Origin::signed(2), 0, 1, 2), e);
		assert_noop!(Tokens::force_cancel_approval(Origin::signed(1), 1, 1, 2), Error::<Test>::Unknown);
		assert_noop!(Tokens::force_cancel_approval(Origin::signed(1), 0, 2, 2), Error::<Test>::Unknown);
		assert_noop!(Tokens::force_cancel_approval(Origin::signed(1), 0, 1, 3), Error::<Test>::Unknown);
		assert_ok!(Tokens::force_cancel_approval(Origin::signed(1), 0, 1, 2));
		assert_noop!(Tokens::force_cancel_approval(Origin::signed(1), 0, 1, 2), Error::<Test>::Unknown);
	});
}

#[test]
fn lifecycle_should_work() {
	new_test_ext().execute_with(|| {
		Balances::make_free_balance_be(&1, 100);
		assert_ok!(Tokens::create(Origin::signed(1), 0, 1, 1));
		assert_eq!(Balances::reserved_balance(&1), 1);
		assert!(Token::<Test>::contains_key(0));

		assert_ok!(Tokens::set_metadata(Origin::signed(1), 0, vec![0], vec![0], 12));
		assert_eq!(Balances::reserved_balance(&1), 4);
		assert!(Metadata::<Test>::contains_key(0));

		Balances::make_free_balance_be(&10, 100);
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 10, 100));
		Balances::make_free_balance_be(&20, 100);
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 20, 100));
		assert_eq!(Accounts::<Test>::iter_prefix(0).count(), 2);

		assert_ok!(Tokens::destroy(Origin::signed(1), 0));
		assert_eq!(Balances::reserved_balance(&1), 0);

		assert!(!Token::<Test>::contains_key(0));
		assert!(!Metadata::<Test>::contains_key(0));
		assert_eq!(Accounts::<Test>::iter_prefix(0).count(), 0);

		assert_ok!(Tokens::create(Origin::signed(1), 0, 1, 1));
		assert_eq!(Balances::reserved_balance(&1), 1);
		assert!(Token::<Test>::contains_key(0));

		assert_ok!(Tokens::set_metadata(Origin::signed(1), 0, vec![0], vec![0], 12));
		assert_eq!(Balances::reserved_balance(&1), 4);
		assert!(Metadata::<Test>::contains_key(0));

		assert_ok!(Tokens::mint(Origin::signed(1), 0, 10, 100));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 20, 100));
		assert_eq!(Accounts::<Test>::iter_prefix(0).count(), 2);

		assert_ok!(Tokens::destroy(Origin::root(), 0));
		assert_eq!(Balances::reserved_balance(&1), 0);

		assert!(!Token::<Test>::contains_key(0));
		assert!(!Metadata::<Test>::contains_key(0));
		assert_eq!(Accounts::<Test>::iter_prefix(0).count(), 0);
	});
}

#[test]
fn min_balance_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 10));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Accounts::<Test>::iter_prefix_values(0).into_iter().map(|e| e).collect::<Vec<AccountData<Balance>>>().len(), 1);

		// Cannot create a new account with a balance that is below minimum...
		assert_noop!(Tokens::mint(Origin::signed(1), 0, 2, 9), Error::<Test>::BelowMinimum);
		assert_noop!(Tokens::transfer(Origin::signed(1), 0, 2, 9), Error::<Test>::BelowMinimum);
		assert_noop!(Tokens::force_transfer(Origin::signed(1), 0, 1, 2, 9), Error::<Test>::BelowMinimum);

		// When deducting from an account to below minimum, it should be reaped.
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 100));
		assert!(Tokens::free_balance(0, &1).is_zero());
		assert_eq!(Tokens::free_balance(0, &2), 100);
		assert_eq!(Tokens::total_issuance(0), 100);
		assert_eq!(Accounts::<Test>::iter_prefix_values(0).into_iter().map(|e| e).collect::<Vec<AccountData<Balance>>>().len(), 1);

		assert_ok!(Tokens::force_transfer(Origin::signed(1), 0, 2, 1, 100));
		assert!(Tokens::free_balance(0, &2).is_zero());
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_eq!(Accounts::<Test>::iter_prefix_values(0).into_iter().map(|e| e).collect::<Vec<AccountData<Balance>>>().len(), 1);

		assert_ok!(Tokens::burn(Origin::signed(1), 0, 1, 100));
		assert!(Tokens::free_balance(0, &1).is_zero());
		assert_eq!(Accounts::<Test>::iter_prefix_values(0).into_iter().map(|e| e).collect::<Vec<AccountData<Balance>>>().len(), 0);
	});
}

#[test]
fn querying_total_supply_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 50));
		assert_eq!(Tokens::free_balance(0, &1), 50);
		assert_eq!(Tokens::free_balance(0, &2), 50);
		assert_ok!(Tokens::transfer(Origin::signed(2), 0, 3, 31));
		assert_eq!(Tokens::free_balance(0, &1), 50);
		assert_eq!(Tokens::free_balance(0, &2), 19);
		assert_eq!(Tokens::free_balance(0, &3), 31);
		assert_ok!(Tokens::burn(Origin::signed(1), 0, 3, u64::max_value()));
		assert_eq!(Tokens::total_issuance(0), 69);
	});
}

#[test]
fn transferring_amount_below_available_balance_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 50));
		assert_eq!(Tokens::free_balance(0, &1), 50);
		assert_eq!(Tokens::free_balance(0, &2), 50);
	});
}

#[test]
fn transferring_enough_to_kill_source_when_keep_alive_should_fail() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 10));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_noop!(Tokens::transfer_keep_alive(Origin::signed(1), 0, 2, 91), Error::<Test>::WouldDie);
		assert_ok!(Tokens::transfer_keep_alive(Origin::signed(1), 0, 2, 90));
		assert_eq!(Tokens::free_balance(0, &1), 10);
		assert_eq!(Tokens::free_balance(0, &2), 90);
	});
}

#[test]
fn transferring_frozen_user_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_ok!(Tokens::freeze(Origin::signed(1), 0, 1));
		assert_noop!(Tokens::transfer(Origin::signed(1), 0, 2, 50), Error::<Test>::Frozen);
		assert_ok!(Tokens::thaw(Origin::signed(1), 0, 1));
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 50));
	});
}

#[test]
fn transferring_frozen_asset_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_ok!(Tokens::freeze_asset(Origin::signed(1), 0));
		assert_noop!(Tokens::transfer(Origin::signed(1), 0, 2, 50), Error::<Test>::TokenIsFrozen);
		assert_ok!(Tokens::thaw_asset(Origin::signed(1), 0));
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 50));
	});
}

#[test]
fn origin_guards_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_noop!(Tokens::transfer_ownership(Origin::signed(2), 0, 2), Error::<Test>::NoPermission);
		assert_noop!(Tokens::set_team(Origin::signed(2), 0, 2, 2, 2), Error::<Test>::NoPermission);
		assert_noop!(Tokens::freeze(Origin::signed(2), 0, 1), Error::<Test>::NoPermission);
		assert_noop!(Tokens::thaw(Origin::signed(2), 0, 2), Error::<Test>::NoPermission);
		assert_noop!(Tokens::mint(Origin::signed(2), 0, 2, 100), Error::<Test>::NoPermission);
		assert_noop!(Tokens::burn(Origin::signed(2), 0, 1, 100), Error::<Test>::NoPermission);
		assert_noop!(Tokens::force_transfer(Origin::signed(2), 0, 1, 2, 100), Error::<Test>::NoPermission);
		assert_noop!(Tokens::destroy(Origin::signed(2), 0), Error::<Test>::NoPermission);
	});
}

#[test]
fn transfer_owner_should_work() {
	new_test_ext().execute_with(|| {
		Balances::make_free_balance_be(&1, 100);
		Balances::make_free_balance_be(&2, 100);
		assert_ok!(Tokens::create(Origin::signed(1), 0, 1, 1));

		assert_eq!(Balances::reserved_balance(&1), 1);

		assert_ok!(Tokens::transfer_ownership(Origin::signed(1), 0, 2));
		assert_eq!(Balances::reserved_balance(&2), 1);
		assert_eq!(Balances::reserved_balance(&1), 0);

		assert_noop!(Tokens::transfer_ownership(Origin::signed(1), 0, 1), Error::<Test>::NoPermission);

		// Set metadata now and make sure that deposit gets transferred back.
		assert_ok!(Tokens::set_metadata(Origin::signed(2), 0, vec![0u8; 10], vec![0u8; 10], 12));
		assert_ok!(Tokens::transfer_ownership(Origin::signed(2), 0, 1));
		assert_eq!(Balances::reserved_balance(&1), 22);
		assert_eq!(Balances::reserved_balance(&2), 0);
	});
}

#[test]
fn set_team_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::set_team(Origin::signed(1), 0, 2, 3, 4));

		assert_ok!(Tokens::mint(Origin::signed(2), 0, 2, 100));
		assert_ok!(Tokens::freeze(Origin::signed(4), 0, 2));
		assert_ok!(Tokens::thaw(Origin::signed(3), 0, 2));
		assert_ok!(Tokens::force_transfer(Origin::signed(3), 0, 2, 3, 100));
		assert_ok!(Tokens::burn(Origin::signed(3), 0, 3, 100));
	});
}

#[test]
fn transferring_to_frozen_account_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 2, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_eq!(Tokens::free_balance(0, &2), 100);
		assert_ok!(Tokens::freeze(Origin::signed(1), 0, 2));
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 50));
		assert_eq!(Tokens::free_balance(0, &2), 150);
	});
}

#[test]
fn transferring_amount_more_than_available_balance_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 50));
		assert_eq!(Tokens::free_balance(0, &1), 50);
		assert_eq!(Tokens::free_balance(0, &2), 50);
		assert_ok!(Tokens::burn(Origin::signed(1), 0, 1, u64::max_value()));
		assert_eq!(Tokens::free_balance(0, &1), 0);
		assert_noop!(Tokens::transfer(Origin::signed(2), 0, 1, 51), Error::<Test>::BalanceLow);
	});
}

#[test]
fn transferring_less_than_one_unit_is_fine() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 0));
	});
}

#[test]
fn transferring_more_units_than_total_supply_should_not_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_noop!(Tokens::transfer(Origin::signed(1), 0, 2, 101), Error::<Test>::BalanceLow);
	});
}

#[test]
fn burning_asset_balance_with_positive_balance_should_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_ok!(Tokens::burn(Origin::signed(1), 0, 1, u64::max_value()));
		assert_eq!(Tokens::free_balance(0, &1), 0);
	});
}

#[test]
fn burning_asset_balance_with_zero_balance_does_nothing() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 100));
		assert_eq!(Tokens::free_balance(0, &1), 100);
		assert_eq!(Tokens::free_balance(0, &2), 0);
		assert_ok!(Tokens::burn(Origin::signed(1), 0, 2, u64::max_value()));
		assert_eq!(Tokens::free_balance(0, &2), 0);
		assert_eq!(Tokens::total_supply(0), 100);
	});
}

#[test]
fn set_metadata_should_work() {
	new_test_ext().execute_with(|| {
		// Cannot add metadata to unknown asset
		assert_noop!(
				Tokens::set_metadata(Origin::signed(1), 0, vec![0u8; 10], vec![0u8; 10], 12),
				Error::<Test>::Unknown,
			);
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		// Cannot add metadata to unowned asset
		assert_noop!(
				Tokens::set_metadata(Origin::signed(2), 0, vec![0u8; 10], vec![0u8; 10], 12),
				Error::<Test>::NoPermission,
			);

		// Cannot add oversized metadata
		assert_noop!(
				Tokens::set_metadata(Origin::signed(1), 0, vec![0u8; 100], vec![0u8; 10], 12),
				Error::<Test>::BadMetadata,
			);
		assert_noop!(
				Tokens::set_metadata(Origin::signed(1), 0, vec![0u8; 10], vec![0u8; 100], 12),
				Error::<Test>::BadMetadata,
			);

		// Successfully add metadata and take deposit
		Balances::make_free_balance_be(&1, 30);
		assert_ok!(Tokens::set_metadata(Origin::signed(1), 0, vec![0u8; 10], vec![0u8; 10], 12));
		assert_eq!(Balances::free_balance(&1), 9);

		// Update deposit
		assert_ok!(Tokens::set_metadata(Origin::signed(1), 0, vec![0u8; 10], vec![0u8; 5], 12));
		assert_eq!(Balances::free_balance(&1), 14);
		assert_ok!(Tokens::set_metadata(Origin::signed(1), 0, vec![0u8; 10], vec![0u8; 15], 12));
		assert_eq!(Balances::free_balance(&1), 4);

		// Cannot over-reserve
		assert_noop!(
				Tokens::set_metadata(Origin::signed(1), 0, vec![0u8; 20], vec![0u8; 20], 12),
				BalancesError::<Test, _>::InsufficientBalance,
			);

		// Clear Metadata
		assert!(Metadata::<Test>::contains_key(0));
		assert_noop!(Tokens::clear_metadata(Origin::signed(2), 0), Error::<Test>::NoPermission);
		assert_noop!(Tokens::clear_metadata(Origin::signed(1), 1), Error::<Test>::Unknown);
		assert_ok!(Tokens::clear_metadata(Origin::signed(1), 0));
		assert!(!Metadata::<Test>::contains_key(0));
	});
}

#[test]
fn force_metadata_should_work() {
	new_test_ext().execute_with(|| {
		//force set metadata works
		assert_ok!(Tokens::force_create(Origin::root(), 0, 1, 1));
		assert_ok!(Tokens::force_set_metadata(Origin::root(), 0, vec![0u8; 10], vec![0u8; 10], 8, false));
		assert!(Metadata::<Test>::contains_key(0));

		//overwrites existing metadata
		let asset_original_metadata = Metadata::<Test>::get(0);
		assert_ok!(Tokens::force_set_metadata(Origin::root(), 0, vec![1u8; 10], vec![1u8; 10], 8, false));
		assert_ne!(Metadata::<Test>::get(0), asset_original_metadata);

		//attempt to set metadata for non-existent asset class
		assert_noop!(
			Tokens::force_set_metadata(Origin::root(), 1, vec![0u8; 10], vec![0u8; 10], 8, false),
			Error::<Test>::Unknown
		);

		//string length limit check
		let limit = StringLimit::get() as usize;
		assert_noop!(
			Tokens::force_set_metadata(Origin::root(), 0, vec![0u8; limit + 1], vec![0u8; 10], 8, false),
			Error::<Test>::BadMetadata
		);
		assert_noop!(
			Tokens::force_set_metadata(Origin::root(), 0, vec![0u8; 10], vec![0u8; limit + 1], 8, false),
			Error::<Test>::BadMetadata
		);

		//force clear metadata works
		assert!(Metadata::<Test>::contains_key(0));
		assert_ok!(Tokens::force_clear_metadata(Origin::root(), 0));
		assert!(!Metadata::<Test>::contains_key(0));

		//Error handles clearing non-existent asset class
		assert_noop!(Tokens::force_clear_metadata(Origin::root(), 1), Error::<Test>::Unknown);
	});
}


#[test]
fn force_asset_status_should_work(){
	new_test_ext().execute_with(|| {
		Balances::make_free_balance_be(&1, 10);
		Balances::make_free_balance_be(&2, 10);
		assert_ok!(Tokens::create(Origin::signed(1), 0, 1, 30));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 1, 50));
		assert_ok!(Tokens::mint(Origin::signed(1), 0, 2, 150));

		//force asset status to change min_balance > balance 
		assert_ok!(Tokens::force_asset_status(Origin::root(), 0, 1, 1, 1, 1, 100, false));
		assert_eq!(Tokens::free_balance(0, &1), 50);

		//account can NOT receive Tokens for balance < min_balance
		assert_noop!(Tokens::transfer(Origin::signed(2), 0, 1, 1), Error::<Test>::BelowMinimum);
		assert_eq!(Tokens::free_balance(0, &1), 50);

		//account can send tokens for balance < min_balance
		assert_ok!(Tokens::transfer(Origin::signed(1), 0, 2, 50));
		assert_eq!(Tokens::free_balance(0, &1), 0);
		assert_eq!(Tokens::free_balance(0, &2), 200);
		assert_eq!(Tokens::total_supply(0), 200);

		//won't create new account with balance below min_balance
		assert_noop!(Tokens::transfer(Origin::signed(2), 0, 3, 50), Error::<Test>::BelowMinimum);

		//force asset status will not execute for non-existent class
		assert_noop!(
			Tokens::force_asset_status(Origin::root(), 1, 1, 1, 1, 1, 90, false),
			Error::<Test>::Unknown
		);

		//account drains to completion when funds dip below min_balance
		assert_ok!(Tokens::force_asset_status(Origin::root(), 0, 1, 1, 1, 1, 110, false));
		assert_eq!(Tokens::total_supply(0), 200);
		assert_ok!(Tokens::transfer(Origin::signed(2), 0, 1, 110));
		assert_eq!(Tokens::free_balance(0, &1), 200);
		assert_eq!(Tokens::free_balance(0, &2), 0);
		assert_eq!(Tokens::total_supply(0), 200);
	});
}

/**
 * @brief      Tokens tests (mostly from orml-tokens)
 */
 #[test]
fn minimum_balance_work() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
		assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));
		assert_eq!(Tokens::minimum_balance(BTC), 1);
		assert_eq!(Tokens::minimum_balance(DOT), 2);
	});
}

#[test]
fn remove_dust_work() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);
		assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));
		assert_ok!(Tokens::deposit(DOT, &DAVE, 100));
		assert_eq!(Tokens::total_issuance(DOT), 100);
		assert_eq!(Accounts::<Test>::contains_key(DOT, DAVE), true);
		assert_eq!(Tokens::free_balance(DOT, &DAVE), 100);
		assert_eq!(System::providers(&DAVE), 1);
		assert_eq!(Accounts::<Test>::contains_key(DOT, DustAccount::get()), false);
		assert_eq!(Tokens::free_balance(DOT, &DustAccount::get()), 0);
		assert_eq!(System::providers(&DustAccount::get()), 0);

		// total is gte ED, will not handle dust
		assert_ok!(Tokens::withdraw(DOT, &DAVE, 98));
		assert_eq!(Tokens::total_issuance(DOT), 2);
		assert_eq!(Accounts::<Test>::contains_key(DOT, DAVE), true);
		assert_eq!(Tokens::free_balance(DOT, &DAVE), 2);
		assert_eq!(System::providers(&DAVE), 1);
		assert_eq!(Accounts::<Test>::contains_key(DOT, DustAccount::get()), false);
		assert_eq!(Tokens::free_balance(DOT, &DustAccount::get()), 0);
		assert_eq!(System::providers(&DustAccount::get()), 0);

		assert_ok!(Tokens::withdraw(DOT, &DAVE, 1));
		assert_eq!(Tokens::free_balance(DOT, &DAVE), 1);
		assert_eq!(Tokens::free_balance(DOT, &DustAccount::get()), 1);
		// total is lte ED, will handle dust
		assert_eq!(Tokens::total_issuance(DOT), 1);
		assert_eq!(Accounts::<Test>::contains_key(DOT, DAVE), false);
		assert_eq!(Tokens::free_balance(DOT, &DAVE), 0);
		assert_eq!(System::providers(&DAVE), 0);

		// will not handle dust for module account
		assert_eq!(Accounts::<Test>::contains_key(DOT, DustAccount::get()), true);
		assert_eq!(Tokens::free_balance(DOT, &DustAccount::get()), 1);
		assert_eq!(System::providers(&DustAccount::get()), 1);

		let dust_lost_event = mock::Event::tokens(crate::Event::DustLost(DAVE, DOT, 1));
		assert!(System::events().iter().any(|record| record.event == dust_lost_event));
	});
}

#[test]
fn set_lock_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::set_lock(ID_1, DOT, &ALICE, 10));
			assert_eq!(Tokens::accounts(&ALICE, DOT).frozen, 10);
			assert_eq!(Tokens::accounts(&ALICE, DOT).frozen(), 10);
			assert_eq!(Tokens::locks(ALICE, DOT).len(), 1);
			assert_ok!(Tokens::set_lock(ID_1, DOT, &ALICE, 50));
			assert_eq!(Tokens::accounts(&ALICE, DOT).frozen, 50);
			assert_eq!(Tokens::locks(ALICE, DOT).len(), 1);
			assert_ok!(Tokens::set_lock(ID_2, DOT, &ALICE, 60));
			assert_eq!(Tokens::accounts(&ALICE, DOT).frozen, 60);
			assert_eq!(Tokens::locks(ALICE, DOT).len(), 2);
		});
}

#[test]
fn extend_lock_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::set_lock(ID_1, DOT, &ALICE, 10));
			assert_eq!(Tokens::locks(ALICE, DOT).len(), 1);
			assert_eq!(Tokens::accounts(&ALICE, DOT).frozen, 10);
			assert_ok!(Tokens::extend_lock(ID_1, DOT, &ALICE, 20));
			assert_eq!(Tokens::locks(ALICE, DOT).len(), 1);
			assert_eq!(Tokens::accounts(&ALICE, DOT).frozen, 20);
			assert_ok!(Tokens::extend_lock(ID_2, DOT, &ALICE, 10));
			assert_ok!(Tokens::extend_lock(ID_1, DOT, &ALICE, 20));
			assert_eq!(Tokens::locks(ALICE, DOT).len(), 2);
		});
}

#[test]
fn remove_lock_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::set_lock(ID_1, DOT, &ALICE, 10));
			assert_ok!(Tokens::set_lock(ID_2, DOT, &ALICE, 20));
			assert_eq!(Tokens::locks(ALICE, DOT).len(), 2);
			assert_ok!(Tokens::remove_lock(ID_2, DOT, &ALICE));
			assert_eq!(Tokens::locks(ALICE, DOT).len(), 1);
		});
}

#[test]
fn frozen_can_limit_liquidity() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::set_lock(ID_1, DOT, &ALICE, 90));
			assert_noop!(
				<Tokens as MultiCurrency<_>>::transfer(DOT, &ALICE, &BOB, 11),
				Error::<Test>::LiquidityRestrictions,
			);
			assert_ok!(Tokens::set_lock(ID_1, DOT, &ALICE, 10));
			assert_ok!(<Tokens as MultiCurrency<_>>::transfer(DOT, &ALICE, &BOB, 11),);
		});
}

#[test]
fn can_reserve_is_correct() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_eq!(Tokens::can_reserve(DOT, &ALICE, 0), true);
			assert_eq!(Tokens::can_reserve(DOT, &ALICE, 101), false);
			assert_eq!(Tokens::can_reserve(DOT, &ALICE, 100), true);
		});
}

#[test]
fn reserve_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_noop!(Tokens::reserve(DOT, &ALICE, 101), Error::<Test>::BalanceLow,);
			assert_ok!(Tokens::reserve(DOT, &ALICE, 0));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::total_balance(DOT, &ALICE), 100);
			assert_ok!(Tokens::reserve(DOT, &ALICE, 50));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::total_balance(DOT, &ALICE), 100);
		});
}

#[test]
fn unreserve_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::unreserve(DOT, &ALICE, 0), 0);
			assert_eq!(Tokens::unreserve(DOT, &ALICE, 50), 50);
			assert_ok!(Tokens::reserve(DOT, &ALICE, 30));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 70);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 30);
			assert_eq!(Tokens::unreserve(DOT, &ALICE, 15), 0);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 85);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 15);
			assert_eq!(Tokens::unreserve(DOT, &ALICE, 30), 15);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 0);
		});
}

#[test]
fn slash_reserved_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::reserve(DOT, &ALICE, 50));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::total_issuance(DOT), 200);
			assert_eq!(Tokens::slash_reserved(DOT, &ALICE, 0), 0);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::total_issuance(DOT), 200);
			assert_eq!(Tokens::slash_reserved(DOT, &ALICE, 100), 50);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::total_issuance(DOT), 150);
		});
}

#[test]
fn repatriate_reserved_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 0);
			assert_eq!(
				Tokens::repatriate_reserved(DOT, &ALICE, &ALICE, 0, BalanceStatus::Free),
				Ok(0)
			);
			assert_eq!(
				Tokens::repatriate_reserved(DOT, &ALICE, &ALICE, 50, BalanceStatus::Free),
				Ok(50)
			);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 0);

			assert_eq!(Tokens::free_balance(DOT, &BOB), 100);
			assert_eq!(Tokens::reserved_balance(DOT, &BOB), 0);
			assert_ok!(Tokens::reserve(DOT, &BOB, 50));
			assert_eq!(Tokens::free_balance(DOT, &BOB), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &BOB), 50);
			assert_eq!(
				Tokens::repatriate_reserved(DOT, &BOB, &BOB, 60, BalanceStatus::Reserved),
				Ok(10)
			);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &BOB), 50);

			assert_eq!(
				Tokens::repatriate_reserved(DOT, &BOB, &ALICE, 30, BalanceStatus::Reserved),
				Ok(0)
			);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 30);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &BOB), 20);

			assert_eq!(
				Tokens::repatriate_reserved(DOT, &BOB, &ALICE, 30, BalanceStatus::Free),
				Ok(10)
			);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 120);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 30);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &BOB), 0);
		});
}

#[test]
fn slash_draw_reserved_correct() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::reserve(DOT, &ALICE, 50));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::total_issuance(DOT), 200);

			assert_eq!(Tokens::slash(DOT, &ALICE, 80), 0);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 20);
			assert_eq!(Tokens::total_issuance(DOT), 120);

			assert_eq!(Tokens::slash(DOT, &ALICE, 50), 30);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::reserved_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::total_issuance(DOT), 100);
		});
}

#[test]
fn genesis_issuance_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 100);
			assert_eq!(Tokens::total_issuance(DOT), 200);
		});
}

#[test]
fn transfer_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 100);
			System::set_block_number(1);

			assert_ok!(Tokens::transfer(Some(ALICE).into(), DOT, BOB, 50));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 150);
			assert_eq!(Tokens::total_issuance(DOT), 200);

			let transferred_event = mock::Event::tokens(crate::Event::Transferred(DOT, ALICE, BOB, 50));
			assert!(System::events().iter().any(|record| record.event == transferred_event));

			assert_noop!(
				Tokens::transfer(Some(ALICE).into(), DOT, BOB, 60),
				Error::<Test>::BalanceLow,
			);
		});
}

#[test]
fn transfer_all_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			System::set_block_number(1);

			assert_ok!(Tokens::transfer_all(Some(ALICE).into(), DOT, BOB));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 200);

			let transferred_event = mock::Event::tokens(crate::Event::Transferred(DOT, ALICE, BOB, 100));
			assert!(System::events().iter().any(|record| record.event == transferred_event));
		});
}

#[test]
fn deposit_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 200);
			assert_eq!(Tokens::total_issuance(DOT), 300);

			assert_noop!(
				Tokens::deposit(DOT, &ALICE, Balance::max_value()),
				Error::<Test>::TotalIssuanceOverflow,
			);
		});
}

#[test]
fn withdraw_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::withdraw(DOT, &ALICE, 50));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::total_issuance(DOT), 150);

			assert_noop!(Tokens::withdraw(DOT, &ALICE, 60), Error::<Test>::BalanceLow);
		});
}

#[test]
fn slash_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			// slashed_amount < amount
			assert_eq!(Tokens::slash(DOT, &ALICE, 50), 0);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 50);
			assert_eq!(Tokens::total_issuance(DOT), 150);

			// slashed_amount == amount
			assert_eq!(Tokens::slash(DOT, &ALICE, 51), 1);
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::total_issuance(DOT), 100);
		});
}

#[test]
fn update_balance_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_ok!(Tokens::update_balance(DOT, &ALICE, 50));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 150);
			assert_eq!(Tokens::total_issuance(DOT), 250);

			assert_ok!(Tokens::update_balance(DOT, &BOB, -50));
			assert_eq!(Tokens::free_balance(DOT, &BOB), 50);
			assert_eq!(Tokens::total_issuance(DOT), 200);

			assert_noop!(Tokens::update_balance(DOT, &BOB, -60), Error::<Test>::BalanceLow);
		});
}

#[test]
fn ensure_can_withdraw_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));

			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));
			assert_ok!(Tokens::deposit(DOT, &BOB, 100));

			assert_noop!(
				Tokens::ensure_can_withdraw(DOT, &ALICE, 101),
				Error::<Test>::BalanceLow
			);

			assert_ok!(Tokens::ensure_can_withdraw(DOT, &ALICE, 1));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
		});
}

#[test]
fn no_op_if_amount_is_zero() {
	new_test_ext().execute_with(|| {
		assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));
		assert_ok!(Tokens::ensure_can_withdraw(DOT, &ALICE, 0));
		assert_ok!(Tokens::transfer(Some(ALICE).into(), DOT, BOB, 0));
		assert_ok!(Tokens::transfer(Some(ALICE).into(), DOT, ALICE, 0));
		assert_ok!(Tokens::deposit(DOT, &ALICE, 0));
		assert_ok!(Tokens::withdraw(DOT, &ALICE, 0));
		assert_eq!(Tokens::slash(DOT, &ALICE, 0), 0);
		assert_eq!(Tokens::slash(DOT, &ALICE, 1), 1);
		assert_ok!(Tokens::update_balance(DOT, &ALICE, 0));
	});
}

#[test]
fn merge_account_should_work() {
	new_test_ext().execute_with(|| {
			assert_ok!(Tokens::force_create(Origin::root(), BTC, 1, 1));
			assert_ok!(Tokens::force_create(Origin::root(), DOT, 1, 2));
			assert_ok!(Tokens::deposit(BTC, &ALICE, 200));
			assert_ok!(Tokens::deposit(DOT, &ALICE, 100));

			assert_eq!(Tokens::free_balance(DOT, &ALICE), 100);
			assert_eq!(Tokens::free_balance(BTC, &ALICE), 200);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 0);

			assert_ok!(Tokens::reserve(DOT, &ALICE, 1));
			assert_noop!(
				Tokens::merge_account(&ALICE, &BOB),
				Error::<Test>::StillHasActiveReserved
			);
			Tokens::unreserve(DOT, &ALICE, 1);

			assert_ok!(Tokens::merge_account(&ALICE, &BOB));
			assert_eq!(Tokens::free_balance(DOT, &ALICE), 0);
			assert_eq!(Tokens::free_balance(BTC, &ALICE), 0);
			assert_eq!(Tokens::free_balance(DOT, &BOB), 100);
			assert_eq!(Tokens::free_balance(BTC, &BOB), 200);
		});
}
