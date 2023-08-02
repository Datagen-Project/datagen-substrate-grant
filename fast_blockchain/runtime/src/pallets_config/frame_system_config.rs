use sp_runtime::{
	generic, Perbill,
	traits::{AccountIdLookup, BlakeTwo256},
};

pub use frame_support::{
	construct_runtime, parameter_types,
	weights::constants::RocksDbWeight,
	traits::Everything
};

use frame_system::Config;

use crate::*;

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
// pub type Weight = u64;
pub const WEIGHT_PER_SECOND_INT:u64 = 1_000_000_000_000;

pub const WEIGHT_PER_SECOND: Weight = Weight::from_all(WEIGHT_PER_SECOND_INT);
parameter_types! {

	pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights::with_sensible_defaults(
		Weight::from_all(2 * WEIGHT_PER_SECOND_INT), NORMAL_DISPATCH_RATIO
	);
	pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
		::max_with_normal_ratio(
			5 * 1024 * 1024, NORMAL_DISPATCH_RATIO
	);
	pub const Version: RuntimeVersion = VERSION;
	pub const SS58Prefix: u8 = 42;

	pub const BlockHashCount: BlockNumber = 2400;
	
	
}
pub type Nonce = u32;
impl frame_system::Config for Runtime {
	/// The basic call filter to use in dispatchable.
	type BaseCallFilter = frame_support::traits::Everything;
	/// The block type for the runtime.
	type Block = Block;
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = BlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = BlockLength;
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The aggregated dispatch type that is available for extrinsics.
	type RuntimeCall = RuntimeCall;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = AccountIdLookup<AccountId, ()>;
	/// The type for storing how many extrinsics an account has signed.
	type Nonce = Nonce;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = BlakeTwo256;
	/// The ubiquitous event type.
	type RuntimeEvent = RuntimeEvent;
	/// The ubiquitous origin type.
	type RuntimeOrigin = RuntimeOrigin;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RocksDbWeight;
	/// Version of the runtime.
	type Version = Version;
	/// Converts a module to the index of the module in `construct_runtime!`.
	///
	/// This type is being generated by `construct_runtime!`.
	type PalletInfo = PalletInfo;
	/// What to do if a new account is created.
	type OnNewAccount = ();
	/// What to do if an account is fully reaped from the system.
	type OnKilledAccount = ();
	/// The data to be stored in an account.
	type AccountData = pallet_balances::AccountData<Balance>;
	/// Weight information for the extrinsics of this pallet.
	type SystemWeightInfo = ();
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	/// The set code logic, just the default since we're not a parachain.
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}
