//! Utility functions for authorizations and permissions

use frame_system::RawOrigin;
use sp_runtime::traits::BadOrigin;

pub fn ensure_admin<OuterOrigin, AccountId>(o: OuterOrigin, admin: &AccountId) -> Result<(), BadOrigin>
where
	OuterOrigin: Into<Result<RawOrigin<AccountId>, OuterOrigin>>,
	AccountId: PartialEq,
{
	match o.into() {
		Ok(RawOrigin::Root) => Ok(()),
		Ok(RawOrigin::Signed(acc)) => {
			if &acc == admin {
				Ok(())
			} else {
				Err(BadOrigin)
			}
		}
		_ => Err(BadOrigin),
	}
}
