// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Parity Bridges Common.

// Parity Bridges Common is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Bridges Common is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Bridges Common.  If not, see <http://www.gnu.org/licenses/>.

//! The Rococo parachain runtime. This can be compiled with `#[no_std]`, ready for Wasm.
//!
//! Originally a copy of runtime from <https://github.com/substrate-developer-hub/substrate-parachain-template>.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use bridge_runtime_common::generate_bridge_reject_obsolete_headers_and_messages;
use parity_scale_codec::{Decode, Encode};
use cumulus_pallet_parachain_system::AnyRelayNumber;
use scale_info::TypeInfo;
use sp_api::impl_runtime_apis;
use sp_core::{crypto::KeyTypeId, ConstBool, OpaqueMetadata};
use sp_runtime::{
	create_runtime_str, generic, impl_opaque_keys,
	traits::{AccountIdLookup, Block as BlockT, ConstU64, ConstU128, DispatchInfoOf, SignedExtension},
	transaction_validity::{
		TransactionSource, TransactionPriority, TransactionValidity, TransactionValidityError
	},
	ApplyExtrinsicResult,
};

use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

// A few exports that help ease life for downstream crates.
use bp_runtime::HeaderId;
use bridge_hub_rococo_runtime::xcm_config::XcmOriginToTransactDispatchOrigin;
pub use frame_support::{
	derive_impl,
	construct_runtime,
	dispatch::DispatchClass,
	match_types, parameter_types,
	traits::{ConstU32, Everything, IsInVec, Nothing, Randomness},
	weights::{
		constants::{
			BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND,
		},
		IdentityFee, Weight, WeightToFee as _,
	},
	StorageValue,
};
pub use frame_system::{
	Call as SystemCall,
	limits::{BlockWeights, BlockLength},
	EnsureRoot
};
use pallet_session::historical as pallet_session_historical;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_sudo::Call as SudoCall;
pub use pallet_timestamp::Call as TimestampCall;
pub use sp_consensus_aura::sr25519::AuthorityId as AuraId;
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;
pub use sp_runtime::{MultiAddress, Perbill, Permill};

pub use parachains_common::{
	AccountId, Balance, BlockNumber, Hash, Header, Nonce, Signature, MAXIMUM_BLOCK_WEIGHT,
	NORMAL_DISPATCH_RATIO, AVERAGE_ON_INITIALIZE_RATIO,
};

use polkadot_runtime_parachains::{
	dmp as parachains_dmp, hrmp as parachains_hrmp, origin as parachains_origin,
	configuration as parachains_configuration, shared as parachains_shared, paras as parachains_paras,
	inclusion as parachains_inclusion, scheduler as parachains_scheduler, initializer as parachains_initializer,
	assigner_coretime as parachains_assigner_coretime, assigner_on_demand as parachains_assigner_on_demand,
	disputes as parachains_disputes, session_info as parachains_session_info,
};

pub use pallet_bridge_grandpa::Call as BridgeGrandpaCall;
pub use pallet_bridge_messages::Call as MessagesCall;
pub use pallet_xcm::Call as XcmCall;

// Polkadot & XCM imports
use pallet_xcm::XcmPassthrough;
use polkadot_parachain_primitives::primitives::Sibling;
use staging_xcm as xcm;
use staging_xcm_builder as xcm_builder;
use staging_xcm_executor as xcm_executor;
use xcm::latest::prelude::*;
use xcm_builder::{
	Account32Hash, AccountId32Aliases, CurrencyAdapter, EnsureXcmOrigin, FixedWeightBounds,
	IsConcrete, NativeAsset, ParentAsSuperuser, ParentIsPreset, RelayChainAsNative,
	SiblingParachainAsNative, SiblingParachainConvertsVia, SignedAccountId32AsNative,
	SignedToAccountId32, SovereignSignedViaLocation, TakeWeightCredit, UsingComponents,
};
use xcm_executor::{Config, XcmExecutor};
use polkadot_primitives::Id as ParaId;
use polkadot_runtime_parachains::paras::Call;
use rococo_runtime_constants::fee::WeightToFee;
pub use crate::xcm_config::XcmRouter;

pub mod westend_messages;
mod xcm_config;

/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;
/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;
/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);
/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
>;

impl_opaque_keys! {
	pub struct SessionKeys {
		pub aura: Aura,
	}
}

/// This runtime version.
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: create_runtime_str!("rococo-parachain"),
	impl_name: create_runtime_str!("rococo-parachain"),
	authoring_version: 1,
	spec_version: 1,
	impl_version: 0,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 1,
	state_version: 1,
};

/// This determines the average expected block time that we are targeting.
/// Blocks will be produced at a minimum duration defined by `SLOT_DURATION`.
/// `SLOT_DURATION` is picked up by `pallet_timestamp` which is in turn picked
/// up by `pallet_aura` to implement `fn slot_duration()`.
///
/// Change this to adjust the block time.
pub const MILLISECS_PER_BLOCK: u64 = 12000;

pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

pub const EPOCH_DURATION_IN_BLOCKS: u32 = 10 * MINUTES;

// Time is measured by number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// Unit = the base number of indivisible units for balances
pub const UNIT: Balance = 1_000_000_000_000;
pub const MILLIUNIT: Balance = 1_000_000_000;
pub const MICROUNIT: Balance = 1_000_000;

// 1 in 4 blocks (on average, not counting collisions) will be primary babe blocks.
pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
	NativeVersion { runtime_version: VERSION, can_author_with: Default::default() }
}

parameter_types! {
	pub const BlockHashCount: BlockNumber = 250;
	pub const Version: RuntimeVersion = VERSION;
	pub const SS58Prefix: u8 = 48;

	pub RuntimeBlockLength: BlockLength =
		BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
	pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
		.base_block(BlockExecutionWeight::get())
		.for_class(DispatchClass::all(), |weights| {
			weights.base_extrinsic = ExtrinsicBaseWeight::get();
		})
		.for_class(DispatchClass::Normal, |weights| {
			weights.max_total = Some(NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT);
		})
		.for_class(DispatchClass::Operational, |weights| {
			weights.max_total = Some(MAXIMUM_BLOCK_WEIGHT);
			// Operational transactions have some extra reserved space, so that they
			// are included even if block reached `MAXIMUM_BLOCK_WEIGHT`.
			weights.reserved = Some(
				MAXIMUM_BLOCK_WEIGHT - NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT
			);
		})
		.avg_block_initialization(AVERAGE_ON_INITIALIZE_RATIO)
		.build_or_panic();
}

pub struct IsIdentityCall;
impl frame_support::traits::Contains<RuntimeCall> for IsIdentityCall {
	fn contains(c: &RuntimeCall) -> bool {
		matches!(c, RuntimeCall::Identity(_))
	}
}

// Configure FRAME pallets to include in runtime.

#[derive_impl(frame_system::config_preludes::RelayChainDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Runtime {
	type BaseCallFilter = frame_support::traits::EverythingBut<IsIdentityCall> ;
	type BlockWeights = RuntimeBlockWeights;
	type BlockLength = RuntimeBlockLength;
	type Nonce = Nonce;
	type Hash = Hash;
	type AccountId = AccountId;
	type Block = Block;
	type AccountData = pallet_balances::AccountData<Balance>;
	type SystemWeightInfo = frame_system::weights::SubstrateWeight<Runtime>;
	type SS58Prefix = frame_support::traits::ConstU16<42>;
	type OnSetCode = cumulus_pallet_parachain_system::ParachainSetCode<Self>;
	type MaxConsumers = ConstU32<16>;
}

parameter_types! {
	pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
	/// A timestamp: milliseconds since the Unix epoch.
	type Moment = u64;
	type OnTimestampSet = ();
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = pallet_timestamp::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	pub const ExistentialDeposit: u128 = MILLIUNIT;
	pub const TransferFee: u128 = MILLIUNIT;
	pub const CreationFee: u128 = MILLIUNIT;
	pub const TransactionByteFee: u128 = MICROUNIT;
	pub const OperationalFeeMultiplier: u8 = 5;
}

impl pallet_balances::Config for Runtime {
	/// The ubiquitous event type.
	type RuntimeEvent = RuntimeEvent;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
	/// The type for recording an account's balance.
	type Balance = Balance;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type ReserveIdentifier = [u8; 8];
	type FreezeIdentifier = ();
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ConstU32<50>;
	type MaxFreezes = ConstU32<1>;
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = pallet_transaction_payment::CurrencyAdapter<
		Balances, polkadot_runtime_common::ToAuthor<Runtime>
	>;
	type WeightToFee = WeightToFee;
	type LengthToFee = IdentityFee<Balance>;
	type FeeMultiplierUpdate = polkadot_runtime_common::SlowAdjustingFeeUpdate<Self>;
	type OperationalFeeMultiplier = OperationalFeeMultiplier;
}

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	pub const ReservedXcmpWeight: Weight = MAXIMUM_BLOCK_WEIGHT.saturating_div(4);
	pub const ReservedDmpWeight: Weight = MAXIMUM_BLOCK_WEIGHT.saturating_div(4);
}

impl cumulus_pallet_parachain_system::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnSystemEvent = ();
	type SelfParaId = staging_parachain_info::Pallet<Runtime>;
	type OutboundXcmpMessageSource = XcmpQueue;
	type DmpQueue = ();
	type ReservedDmpWeight = ReservedDmpWeight;
	type XcmpMessageHandler = XcmpQueue;
	type ReservedXcmpWeight = ReservedXcmpWeight;
	type CheckAssociatedRelayNumber = AnyRelayNumber;
	type WeightInfo = ();
	type ConsensusHook = ();
}

impl staging_parachain_info::Config for Runtime {}

impl cumulus_pallet_aura_ext::Config for Runtime {}

impl cumulus_pallet_xcm::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type XcmExecutor = XcmExecutor<xcm_config::XcmConfig>;
}

impl cumulus_pallet_xcmp_queue::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ChannelInfo = ParachainSystem;
	type VersionWrapper = ();
	type XcmpQueue = ();
	type MaxInboundSuspended = ();
	type ControllerOrigin = EnsureRoot<AccountId>;
	type ControllerOriginConverter = XcmOriginToTransactDispatchOrigin;
	type PriceForSiblingDelivery = ();
	type WeightInfo = ();
}

impl cumulus_pallet_dmp_queue::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type DmpSink = ();
	type WeightInfo = ();
}

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type MaxAuthorities = frame_support::traits::ConstU16<50>;
	type DisabledValidators = ();
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type SlotDuration = ConstU64<SLOT_DURATION>;
}

parameter_types! {
	pub const BasicDeposit: Balance = 1000 * MILLIUNIT;
	pub const ByteDeposit: Balance = rococo_runtime_constants::currency::deposit(0, 1);
	pub const SubAccountDeposit: Balance = 200 * MILLIUNIT;
	pub const MaxSubAccounts: u32 = 100;
	pub const MaxAdditionalFields: u32 = 100;
	pub const MaxRegistrars: u32 = 20;
}

impl pallet_identity::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type BasicDeposit = BasicDeposit;
	type ByteDeposit = ByteDeposit;
	type SubAccountDeposit = SubAccountDeposit;
	type MaxSubAccounts = MaxSubAccounts;
	type IdentityInformation = pallet_identity::legacy::IdentityInfo<MaxAdditionalFields>;
	type MaxRegistrars = MaxRegistrars;
	type Slashed = Treasury;
	type ForceOrigin = EnsureRootOrHalfCouncil;
	type RegistrarOrigin = EnsureRootOrHalfCouncil;
	type OffchainSignature = Signature;
	type SigningPublicKey = <Signature as sp_runtime::traits::Verify>::Signer;
	type UsernameAuthorityOrigin = EnsureRoot<Self::AccountId>;
	type PendingUsernameExpiration = ConstU32<{ 7 * DAYS }>;
	type MaxSuffixLength = ConstU32<7>;
	type MaxUsernameLength = ConstU32<32>;
	type WeightInfo = pallet_identity::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	pub MaxCollectivesProposalWeight: Weight = Perbill::from_percent(50) * RuntimeBlockWeights::get().max_block;
	pub const CouncilMotionDuration: BlockNumber = 5 * DAYS;
	pub const CouncilMaxProposals: u32 = 100;
	pub const CouncilMaxMembers: u32 = 100;
}

type CouncilCollective = pallet_collective::Instance1;
impl pallet_collective::Config<CouncilCollective> for Runtime {
	type RuntimeOrigin = RuntimeOrigin;
	type Proposal = RuntimeCall;
	type RuntimeEvent = RuntimeEvent;
	type MotionDuration = CouncilMotionDuration;
	type MaxProposals = CouncilMaxProposals;
	type MaxMembers = CouncilMaxMembers;
	type DefaultVote = pallet_collective::PrimeDefaultVote;
	type WeightInfo = pallet_collective::weights::SubstrateWeight<Runtime>;
	type SetMembersOrigin = EnsureRoot<Self::AccountId>;
	type MaxProposalWeight = MaxCollectivesProposalWeight;
}

parameter_types! {
	pub const TechnicalMotionDuration: BlockNumber = 5 * DAYS;
	pub const TechnicalMaxProposals: u32 = 100;
	pub const TechnicalMaxMembers: u32 = 100;
}

type TechnicalCollective = pallet_collective::Instance2;
impl pallet_collective::Config<TechnicalCollective> for Runtime {
	type RuntimeOrigin = RuntimeOrigin;
	type Proposal = RuntimeCall;
	type RuntimeEvent = RuntimeEvent;
	type MotionDuration = TechnicalMotionDuration;
	type MaxProposals = TechnicalMaxProposals;
	type MaxMembers = TechnicalMaxMembers;
	type DefaultVote = pallet_collective::PrimeDefaultVote;
	type WeightInfo = pallet_collective::weights::SubstrateWeight<Runtime>;
	type SetMembersOrigin = EnsureRoot<Self::AccountId>;
	type MaxProposalWeight = MaxCollectivesProposalWeight;
}

type EnsureRootOrHalfCouncil = frame_support::traits::EitherOfDiverse<
	EnsureRoot<AccountId>,
	pallet_collective::EnsureProportionMoreThan<AccountId, CouncilCollective, 1, 2>,
>;

parameter_types! {
	pub const TreasuryModuleId: frame_support::PalletId = frame_support::PalletId(*b"py/trsry");
	pub const ProposalBond: Permill = Permill::from_percent(5);
	pub const ProposalBondMinimum: Balance = 1 * UNIT;
	pub const SpendPeriod: BlockNumber = 7 * DAYS;
	pub const SpendPayoutPeriod: BlockNumber = 30 * DAYS;
	pub const Burn: Permill = Permill::from_percent(1);
	pub const MaximumBalance: Balance = Balance::MAX;
}

impl pallet_treasury::Config for Runtime {
	type Currency = Balances;
	type ApproveOrigin = EnsureRootOrHalfCouncil;
	type RejectOrigin = EnsureRootOrHalfCouncil;
	type RuntimeEvent = RuntimeEvent;
	type OnSlash = ();
	type ProposalBond = ProposalBond;
	type ProposalBondMinimum = ProposalBondMinimum;
	type ProposalBondMaximum = ();
	type SpendPeriod = SpendPeriod;
	type Burn = Burn;
	type PalletId = TreasuryModuleId;
	type BurnDestination = ();
	type WeightInfo = pallet_treasury::weights::SubstrateWeight<Runtime>;
	type SpendFunds = ();
	type MaxApprovals = ConstU32<100>;
	type SpendOrigin = frame_system::EnsureWithSuccess<
		frame_system::EnsureRoot<AccountId>,
		AccountId,
		MaximumBalance
	>;
	type AssetKind = u32;
	type Beneficiary = AccountId;
	type BeneficiaryLookup = ();
	type Paymaster = ();
	type BalanceConverter = ();
	type PayoutPeriod = SpendPayoutPeriod;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = ();
}

impl pallet_bridge_relayers::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Reward = Balance;
	type PaymentProcedure =
		bp_relayers::PayRewardFromAccount<pallet_balances::Pallet<Runtime>, AccountId>;
	type StakeAndSlash = ();
	type WeightInfo = pallet_bridge_relayers::weights::BridgeWeight<Runtime>;
}

pub type WestendGrandpaInstance = pallet_bridge_grandpa::Instance3;
impl pallet_bridge_grandpa::Config<WestendGrandpaInstance> for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type BridgedChain = bp_westend::Westend;
	type MaxFreeMandatoryHeadersPerBlock = ConstU32<4>;
	type HeadersToKeep = ConstU32<{ bp_westend::DAYS as u32 }>;
	type WeightInfo = pallet_bridge_grandpa::weights::BridgeWeight<Runtime>;
}

/// Add GRANDPA bridge pallet to track Rococo Bulletin chain.
pub type BridgeGrandpaRococoBulletinInstance = pallet_bridge_grandpa::Instance4;
impl pallet_bridge_grandpa::Config<BridgeGrandpaRococoBulletinInstance> for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type BridgedChain = bp_polkadot_bulletin::PolkadotBulletin;
	type MaxFreeMandatoryHeadersPerBlock = ConstU32<4>;
	type HeadersToKeep = ConstU32<1024>;
	type WeightInfo = pallet_bridge_grandpa::weights::BridgeWeight<Runtime>;
}

pub type BridgeParachainWestendInstance = pallet_bridge_parachains::Instance3;
impl pallet_bridge_parachains::Config<BridgeParachainWestendInstance> for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = pallet_bridge_parachains::weights::BridgeWeight<Runtime>;
	type BridgesGrandpaPalletInstance = WestendGrandpaInstance;
	type ParasPalletName = WestendBridgeParachainPalletName;
	type ParaStoredHeaderDataBuilder =
		bp_parachains::SingleParaStoredHeaderDataBuilder<bp_bridge_hub_westend::BridgeHubWestend>;
	type HeadsToKeep = ConstU32<32>;
	type MaxParaHeadDataSize = ConstU32<bp_westend::MAX_NESTED_PARACHAIN_HEAD_DATA_SIZE>;
}

parameter_types! {
	pub const MaxMessagesToPruneAtOnce: bp_messages::MessageNonce = 8;
	pub const RootAccountForPayments: Option<AccountId> = None;

	pub const WestendBridgeParachainPalletName: &'static str = bp_westend::PARAS_PALLET_NAME;

	pub const BridgeHubWestendChainId: bp_runtime::ChainId =
}

impl pallet_xcm_handler::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type XcmSender = XcmRouter;
}

impl parachains_configuration::Config for Runtime { type WeightInfo = (); }

impl parachains_shared::Config for Runtime { type DisabledValidators = Session; }

impl parachains_dmp::Config for Runtime {}

impl frame_system::offchain::SendTransactionTypes<Call<Self>> for Runtime {
	type Extrinsic = UncheckedExtrinsic;
	type OverarchingCall = RuntimeCall;
}

impl parachains_scheduler::Config for Runtime {
	type AssignmentProvider = AssignerCoretime;
}

pub struct RewardValidators;
impl polkadot_runtime_parachains::inclusion::RewardValidators for RewardValidators {
	fn reward_backing(_: impl IntoIterator<Item = polkadot_primitives::ValidatorIndex>) {}
	fn reward_bitfields(_: impl IntoIterator<Item = polkadot_primitives::ValidatorIndex>) {}
}

impl parachains_inclusion::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type DisputesHandler = Disputes;
	type RewardValidators = RewardValidators;
	type MessageQueue = ();
	type WeightInfo = ();
}

parameter_types! {
	pub const ParasUnsignedPriority: TransactionPriority = TransactionPriority::MAX;
}

impl parachains_paras::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type UnsignedPriority = ParasUnsignedPriority;
	type NextSessionRotation = ();
	type QueueFootprinter = ParasInclusion;
	type OnNewHead = ();
	type WeightInfo = ();
	type AssignCoretime = AssignerCoretime;
}

parameter_types! {
	pub const OnDemandDefaultValue: sp_runtime::FixedU128 = sp_runtime::FixedU128::from_u32(1);
}

impl parachains_assigner_on_demand::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type WeightInfo = ();
	type TrafficDefaultValue = OnDemandDefaultValue;
}

impl parachains_assigner_coretime::Config for Runtime {}

impl parachains_session_info::Config for Runtime {
	type ValidatorSet = Historical;
}

impl parachains_initializer::Config for Runtime {
	type Randomness = ();
	type ForceOrigin = EnsureRoot<AccountId>;
	type CoretimeOnNewSession = ();
	type WeightInfo = ();
}

impl parachains_disputes::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RewardValidators = ();
	type SlashingHandler = ();
	type WeightInfo = ();
}
impl parachains_hrmp::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeOrigin = RuntimeOrigin;
	type ChannelManager = EnsureRoot<AccountId>;
	type Currency = Balances;
	type WeightInfo = ();
}

pub struct ValidatorIdOf;
impl sp_runtime::traits::Convert<AccountId, Option<AccountId>> for ValidatorIdOf {
	fn convert(a: AccountId) -> Option<AccountId> {
		Some(a)
	}
}

parameter_types! {
	pub const Offset: u32 = 0;
	pub const SessionPeriod: u32 = 900;
}

impl pallet_session::pallet::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = AccountId;
	type ValidatorIdOf = ValidatorIdOf;
	type ShouldEndSession = pallet_session::PeriodicSessions<Offset, SessionPeriod>;
	type NextSessionRotation = pallet_session::PeriodicSessions<Offset, SessionPeriod>;
	type SessionManager = ();
	type SessionHandler = <SessionKeys as sp_runtime::traits::OpaqueKeys>::KeyTypeIdProviders;
	type Keys = SessionKeys;
	type WeightInfo = pallet_session::weights::SubstrateWeight<Runtime>;
}

impl pallet_authority_discovery::Config for Runtime {
	type MaxAuthorities = ConstU32<100>;
}

impl pallet_insecure_randomness_collective_flip::Config for Runtime {}

impl pallet_random_node_selector::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Randomness = RandomnessCollectiveFlip;
}

#[frame_support::runtime]
mod runtime {
	#[runtime::runtime]
	#[runtime::derive(
		RuntimeCall,
		RuntimeEvent,
		RuntimeError,
		RuntimeOrigin,
		RuntimeFreezeReason,
		RuntimeHoldReason,
		RuntimeSlashReason,
		RuntimeLockId,
		RuntimeTask
	)]
	pub struct Runtime;

	#[runtime::pallet_index(0)]
	pub type System = frame_system;

	#[runtime::pallet_index(1)]
	pub type Timestamp = pallet_timestamp;

	#[runtime::pallet_index(2)]
	pub type Balances = pallet_balances;

	#[runtime::pallet_index(3)]
	pub type TransactionPayment = pallet_transaction_payment;

	#[runtime::pallet_index(4)]
	pub type Sudo = pallet_sudo;

	#[runtime::pallet_index(5)]
	pub type Aura = pallet_aura;

	#[runtime::pallet_index(6)]
	pub type AuraExt = cumulus_pallet_aura_ext;

	#[runtime::pallet_index(7)]
	pub type Historical = pallet_session_historical;

	#[runtime::pallet_index(8)]
	pub type Session = pallet_session;

	#[runtime::pallet_index(9)]
	pub type AuthorityDiscovery = pallet_authority_discovery;

	#[runtime::pallet_index(15)]
	pub type ParachainSystem = cumulus_pallet_parachain_system;

	#[runtime::pallet_index(16)]
	pub type ParachainInfo = staging_parachain_info;

	#[runtime::pallet_index(17)]
	pub type RandomnessCollectiveFlip = pallet_insecure_randomness_collective_flip;

	#[runtime::pallet_index(18)]
	pub type Council = pallet_collective<Instance1>;

	#[runtime::pallet_index(19)]
	pub type TechnicalCommittee = pallet_collective<Instance2>;

	#[runtime::pallet_index(20)]
	pub type Identity = pallet_identity;

	#[runtime::pallet_index(21)]
	pub type Treasury = pallet_treasury;

	#[runtime::pallet_index(22)]
	pub type XcmpQueue = cumulus_pallet_xcmp_queue;

	#[runtime::pallet_index(23)]
	pub type XCMPallet = pallet_xcm;

	#[runtime::pallet_index(24)]
	pub type CumulusXcm = cumulus_pallet_xcm;

	#[runtime::pallet_index(25)]
	pub type DmpQueue = cumulus_pallet_dmp_queue;

	#[runtime::pallet_index(26)]
	pub type XcmHandler = pallet_xcm_handler;

	#[runtime::pallet_index(27)]
	pub type RandomNodeSelector = pallet_random_node_selector;

	#[runtime::pallet_index(28)]
	pub type BridgeRelayers = pallet_bridge_relayers;

	#[runtime::pallet_index(29)]
	pub type BridgeWestendGrandpa = pallet_bridge_grandpa;

	#[runtime::pallet_index(30)]
	pub type BridgeWestendMessages = pallet_bridge_messages;

	#[runtime::pallet_index(31)]
	pub type XcmOverBridgeHubWestend = pallet_xcm_bridge_hub;

	// parachains pallets
	#[runtime::pallet_index(40)]
	pub type ParachainsOrigin = parachains_origin;

	#[runtime::pallet_index(41)]
	pub type Configuration = parachains_configuration;

	#[runtime::pallet_index(42)]
	pub type ParachainsShared = parachains_shared;

	#[runtime::pallet_index(43)]
	pub type ParasInclusion = parachains_inclusion;

	#[runtime::pallet_index(44)]
	pub type ParasScheduler = parachains_scheduler;

	#[runtime::pallet_index(45)]
	pub type Paras = parachains_paras;

	#[runtime::pallet_index(46)]
	pub type ParachainsInitiliazer = parachains_initializer;

	#[runtime::pallet_index(47)]
	pub type Dmp = parachains_dmp;

	#[runtime::pallet_index(48)]
	pub type Hrmp = parachains_hrmp;

	#[runtime::pallet_index(49)]
	pub type AssignerCoretime = parachains_assigner_coretime;

	#[runtime::pallet_index(50)]
	pub type AssignerOnDemand = parachains_assigner_on_demand;

	#[runtime::pallet_index(51)]
	pub type Disputes = parachains_disputes;

	#[runtime::pallet_index(52)]
	pub type ParaSessionInfo = parachains_session_info;
}

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: Block) {
			Executive::execute_block(block)
		}

		fn initialize_block(header: &<Block as BlockT>::Header) -> sp_runtime::ExtrinsicInclusionMode {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> sp_std::vec::Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(
			extrinsic: <Block as BlockT>::Extrinsic,
		) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: Block,
			data: sp_inherents::InherentData,
		) -> sp_inherents::CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
			SessionKeys::decode_into_raw_public_keys(&encoded)
		}

		fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
			SessionKeys::generate(seed)
		}
	}

	impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
		fn slot_duration() -> sp_consensus_aura::SlotDuration {
			sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
		}

		fn authorities() -> Vec<AuraId> {
			Aura::authorities().into_inner()
		}
	}

	impl cumulus_primitives_core::CollectCollationInfo<Block> for Runtime {
		fn collect_collation_info(header: &<Block as BlockT>::Header) -> cumulus_primitives_core::CollationInfo {
			ParachainSystem::collect_collation_info(header)
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
		fn account_nonce(account: AccountId) -> Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
		fn query_info(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}
		fn query_fee_details(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment::FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}
		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}
		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}


	#[cfg(feature = "runtime-benchmarks")]
	impl frame_benchmarking::Benchmark<Block> for Runtime {
		fn benchmark_metadata(_extra: bool) -> (
			Vec<frame_benchmarking::BenchmarkList>,
			Vec<frame_support::traits::StorageInfo>,
		) {
			todo!("TODO: fix or remove")
		}

		fn dispatch_benchmark(
			config: frame_benchmarking::BenchmarkConfig
		) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
			use frame_benchmarking::{Benchmarking, BenchmarkBatch, add_benchmark};
			use frame_support::traits::TrackedStorageKey;

			use frame_system_benchmarking::Pallet as SystemBench;
			impl frame_system_benchmarking::Config for Runtime {}

			let mut whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);

			add_benchmark!(params, batches, frame_system, SystemBench::<Runtime>);
			add_benchmark!(params, batches, pallet_balances, Balances);
			add_benchmark!(params, batches, pallet_timestamp, Timestamp);

			Ok(batches)
		}
	}
}

struct CheckInherents;

impl cumulus_pallet_parachain_system::CheckInherents<Block> for CheckInherents {
	fn check_inherents(
		block: &Block,
		relay_state_proof: &cumulus_pallet_parachain_system::RelayChainStateProof,
	) -> sp_inherents::CheckInherentsResult {
		let relay_chain_slot = relay_state_proof
			.read_slot()
			.expect("Could not read the relay chain slot from the proof");

		let inherent_data =
			cumulus_primitives_timestamp::InherentDataProvider::from_relay_chain_slot_and_duration(
				relay_chain_slot,
				sp_std::time::Duration::from_secs(6),
			)
			.create_inherent_data()
			.expect("Could not create the timestamp inherent data");

		inherent_data.check_extrinsics(block)
	}
}

cumulus_pallet_parachain_system::register_validate_block!(
	Runtime = Runtime,
	BlockExecutor = cumulus_pallet_aura_ext::BlockExecutor::<Runtime, Executive>,
	CheckInherents = CheckInherents,
);

// #[cfg(test)]
// mod tests {
// 	use super::*;
// 	use bp_messages::{
// 		target_chain::{DispatchMessage, DispatchMessageData, MessageDispatch},
// 		MessageKey, OutboundLaneData,
// 	};
// 	use bp_runtime::Chain;
// 	use bp_xcm_bridge_hub::{Bridge, BridgeState};
// 	use parity_scale_codec::Encode;
// 	use pallet_bridge_messages::OutboundLanes;
// 	use pallet_xcm_bridge_hub::Bridges;
// 	use sp_runtime::{generic::Era, traits::Zero};
// 	use xcm_executor::XcmExecutor;
//
// 	fn new_test_ext() -> sp_io::TestExternalities {
// 		sp_io::TestExternalities::new(
// 			frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap(),
// 		)
// 	}
//
// 	fn prepare_outbound_xcm_message(destination: NetworkId) -> Xcm<RuntimeCall> {
// 		vec![ExportMessage {
// 			network: destination,
// 			destination: destination.into(),
// 			xcm: vec![Instruction::Trap(42)].into(),
// 		}]
// 		.into()
// 	}
//
// 	#[test]
// 	fn runtime_version() {
// 		assert_eq!(
// 			VERSION.state_version,
// 			bp_rialto_parachain::RialtoParachain::STATE_VERSION as u8
// 		);
// 	}
//
// 	#[test]
// 	fn xcm_messages_to_millau_are_sent_using_bridge_exporter() {
// 		new_test_ext().execute_with(|| {
// 			// ensure that the there are no messages queued
// 			let bridge_id = crate::millau_messages::Bridge::get();
// 			let lane_id = bridge_id.lane_id();
// 			Bridges::<Runtime, WithMillauXcmBridgeHubInstance>::insert(
// 				bridge_id,
// 				Bridge {
// 					bridge_origin_relative_location: Box::new(MultiLocation::new(0, Here).into()),
// 					state: BridgeState::Opened,
// 					bridge_owner_account: [0u8; 32].into(),
// 					reserve: 0,
// 				},
// 			);
// 			OutboundLanes::<Runtime, WithMillauMessagesInstance>::insert(
// 				lane_id,
// 				OutboundLaneData::opened(),
// 			);
// 			assert_eq!(
// 				OutboundLanes::<Runtime, WithMillauMessagesInstance>::get(lane_id)
// 					.unwrap()
// 					.latest_generated_nonce,
// 				0,
// 			);
//
// 			// export message instruction "sends" message to Rialto
// 			XcmExecutor::<XcmConfig>::execute_xcm_in_credit(
// 				Here,
// 				prepare_outbound_xcm_message(MillauNetwork::get()),
// 				Default::default(),
// 				Weight::MAX,
// 				Weight::MAX,
// 			)
// 			.ensure_complete()
// 			.expect("runtime configuration must be correct");
//
// 			// ensure that the message has been queued
// 			assert_eq!(
// 				OutboundLanes::<Runtime, WithMillauMessagesInstance>::get(lane_id)
// 					.unwrap()
// 					.latest_generated_nonce,
// 				1,
// 			);
// 		})
// 	}
//
// 	fn prepare_inbound_bridge_message() -> DispatchMessage<Vec<u8>> {
// 		let xcm = xcm::VersionedXcm::<RuntimeCall>::V3(vec![Instruction::Trap(42)].into());
// 		let location =
// 			xcm::VersionedInteriorMultiLocation::V3(X1(GlobalConsensus(ThisNetwork::get())));
// 		// this is the `BridgeMessage` from polkadot xcm builder, but it has no constructor
// 		// or public fields, so just tuple
// 		let xcm_lane = crate::millau_messages::Bridge::get().lane_id();
// 		let bridge_message = (location, xcm).encode();
// 		DispatchMessage {
// 			key: MessageKey { lane_id: xcm_lane, nonce: 1 },
// 			data: DispatchMessageData { payload: Ok(bridge_message) },
// 		}
// 	}
//
// 	#[test]
// 	fn xcm_messages_from_millau_are_dispatched() {
// 		new_test_ext().execute_with(|| {
// 			let incoming_message = prepare_inbound_bridge_message();
//
// 			// we care only about handing message to the XCM dispatcher, so we don't care about its
// 			// actual dispatch
// 			let dispatch_result = XcmMillauBridgeHub::dispatch(incoming_message);
// 			assert!(matches!(
// 				dispatch_result.dispatch_level_result,
// 				pallet_xcm_bridge_hub::XcmBlobMessageDispatchResult::NotDispatched(_),
// 			));
// 		});
// 	}
//
// 	#[test]
// 	fn ensure_signed_extension_definition_is_correct() {
// 		use bp_polkadot_core::SuffixedCommonSignedExtensionExt;
//
// 		sp_io::TestExternalities::default().execute_with(|| {
// 			frame_system::BlockHash::<Runtime>::insert(BlockNumber::zero(), Hash::default());
// 			let payload: SignedExtra = (
// 				frame_system::CheckNonZeroSender::new(),
// 				frame_system::CheckSpecVersion::new(),
// 				frame_system::CheckTxVersion::new(),
// 				frame_system::CheckGenesis::new(),
// 				frame_system::CheckEra::from(Era::Immortal),
// 				frame_system::CheckNonce::from(10),
// 				frame_system::CheckWeight::new(),
// 				pallet_transaction_payment::ChargeTransactionPayment::from(10),
// 				BridgeRejectObsoleteHeadersAndMessages,
// 				DummyBridgeRefundMillauMessages,
// 			);
// 			let indirect_payload = bp_rialto_parachain::SignedExtension::from_params(
// 				VERSION.spec_version,
// 				VERSION.transaction_version,
// 				bp_runtime::TransactionEra::Immortal,
// 				System::block_hash(BlockNumber::zero()),
// 				10,
// 				10,
// 				(((), ()), ((), ())),
// 			);
// 			assert_eq!(payload.encode(), indirect_payload.encode());
// 			assert_eq!(
// 				payload.additional_signed().unwrap().encode(),
// 				indirect_payload.additional_signed().unwrap().encode()
// 			)
// 		});
// 	}
// }
