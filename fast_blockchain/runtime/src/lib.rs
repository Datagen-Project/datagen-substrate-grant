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

//! The Westend runtime. This can be compiled with `#[no_std]`, ready for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursions and requires us to increase the limit to 256.
#![recursion_limit = "256"]
// Runtime-generated enums
#![allow(clippy::large_enum_variant)]
// From construct_runtime macro
#![allow(clippy::from_over_into)]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));
pub mod weights;
pub mod xcm_config;

#[cfg(feature = "runtime-benchmarks")]
use bp_relayers::{RewardsAccountOwner, RewardsAccountParams};
use bp_runtime::HeaderId;
use bridge_hub_rococo_runtime::{
    bridge_to_westend_config::BridgeHubWestendLocation,
    bridge_to_bulletin_config::WithRococoBulletinMessagesInstance
};
use bridge_hub_rococo_runtime::bridge_to_westend_config::XCM_LANE_FOR_ASSET_HUB_ROCOCO_TO_ASSET_HUB_WESTEND;
use bridge_hub_westend_runtime::{
    bridge_common_config::DeliveryRewardInBalance,
    bridge_to_rococo_config::{
        ActiveOutboundLanesToBridgeHubRococo, AssetHubWestendParaId,
        MaxUnconfirmedMessagesAtInboundLane, MaxUnrewardedRelayerEntriesAtInboundLane,
        ToBridgeHubRococoXcmBlobHauler,
        WithBridgeHubRococoMessageBridge, BridgeHubRococo, BridgeHubWestend, BridgeParachainRococoInstance,
        OnBridgeHubWestendRefundBridgeHubRococoMessages,
        BridgeWestendToRococoMessagesPalletInstance,
    },
    xcm_config::XcmRouter,
    BridgeRejectObsoleteHeadersAndMessages, CollatorSelection, XcmpQueue,
};
use bridge_runtime_common::{
    messages::source::{TargetHeaderChainAdapter, FromThisChainMaximalOutboundPayloadSize},
    messages::target::SourceHeaderChainAdapter,
    messages_xcm_extension::{XcmAsPlainPayload, XcmBlobHaulerAdapter, XcmBlobMessageDispatch},
};
use pallet_grandpa::{
    fg_primitives, AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList,
};
use pallet_transaction_payment::{FeeDetails, Multiplier, RuntimeDispatchInfo};
use pallet_xcm::EnsureXcm;
use parachains_common::HOURS;
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_beefy::{ecdsa_crypto::AuthorityId as BeefyId, mmr::MmrLeafVersion, ValidatorSet};
use sp_core::{ConstBool, OpaqueMetadata};
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    traits::{Block as BlockT, IdentityLookup, Keccak256, NumberFor, OpaqueKeys},
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, FixedPointNumber, Perquintill,
};
use staging_xcm_builder::BridgeBlobDispatcher;

use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
// to be able to use Westend runtime in `bridge-runtime-common` tests
pub use bridge_runtime_common;

// A few exports that help ease life for downstream crates.
pub use frame_support::{
    construct_runtime,
    dispatch::DispatchClass,
    parameter_types,
    traits::{
        ConstU32, ConstU64, ConstU8, Currency, Equals, ExistenceRequirement, Imbalance,
        KeyOwnerProofSystem,
    },
    weights::{
        constants::WEIGHT_REF_TIME_PER_SECOND, ConstantMultiplier, IdentityFee, RuntimeDbWeight,
        Weight,
    },
    StorageValue,
};

pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_bridge_grandpa::Call as BridgeGrandpaCall;
pub use pallet_bridge_messages::Call as MessagesCall;
pub use pallet_bridge_parachains::Call as BridgeParachainsCall;
pub use pallet_sudo::Call as SudoCall;
pub use pallet_timestamp::Call as TimestampCall;
pub use pallet_xcm::Call as XcmCall;

use bridge_runtime_common::generate_bridge_reject_obsolete_headers_and_messages;
use bridge_runtime_common::messages_xcm_extension::SenderAndLane;
use frame_support::traits::EitherOfDiverse;
use frame_system::EnsureRoot;

#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;
pub use sp_runtime::{Perbill, Permill};
use staging_xcm::prelude::{Parachain, ParentThen};

/// An index to a block.
pub type BlockNumber = bp_westend::BlockNumber;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = bp_westend::Signature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = bp_westend::AccountId;

/// The type for looking up accounts. We don't expect more than 4 billion of them, but you
/// never know...
pub type AccountIndex = u32;

/// Balance of an account.
pub type Balance = bp_westend::Balance;

/// Nonce of a transaction in the chain.
pub type Nonce = bp_westend::Nonce;

/// A hash of some data used by the chain.
pub type Hash = bp_westend::Hash;

/// Hashing algorithm used by the chain.
pub type Hashing = bp_westend::Hasher;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;

    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, Hashing>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;
}

impl_opaque_keys! {
    pub struct SessionKeys {
        pub aura: Aura,
        pub grandpa: Grandpa,
    }
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("westend-runtime"),
    impl_name: create_runtime_str!("westend-runtime"),
    authoring_version: 1,
    spec_version: 1,
    impl_version: 1,
    apis: westend_runtime::RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 0,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

/// Money matters.
pub mod currency {
    use super::Balance;

    /// The existential deposit.
    pub const EXISTENTIAL_DEPOSIT: Balance = 1 * CENTS;

    pub const UNITS: Balance = 1_000_000_000_000;
    pub const CENTS: Balance = UNITS / 100;
    pub const MILLICENTS: Balance = CENTS / 1_000;
    pub const GRAND: Balance = CENTS * 100_000;

    pub const fn deposit(items: u32, bytes: u32) -> Balance {
        items as Balance * 100 * CENTS + (bytes as Balance) * 5 * MILLICENTS
    }
}

parameter_types! {
    pub const BlockHashCount: BlockNumber = 250;
    pub const Version: RuntimeVersion = VERSION;
    pub const DbWeight: RuntimeDbWeight = RuntimeDbWeight {
        read: 60_000_000, // ~0.06 ms = ~60 µs
        write: 200_000_000, // ~0.2 ms = 200 µs
    };
    pub const SS58Prefix: u8 = 60;
    pub const BridgeHubRococoChainId: bp_runtime::ChainId = bridge_hub_westend_runtime::bridge_to_rococo_config::BridgeHubRococoChainId::get();
}

impl frame_system::Config for Runtime {
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    /// The basic call filter to use in dispatchable.
    type BaseCallFilter = frame_support::traits::Everything;
    /// Block and extrinsics weights: base values and limits.
    type BlockWeights = bp_westend::BlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = bp_westend::BlockLength;
    /// The ubiquitous origin type.
    type RuntimeOrigin = RuntimeOrigin;
    /// The aggregated dispatch type that is available for extrinsics.
    type RuntimeCall = RuntimeCall;
    type RuntimeTask = ();
    /// The index type for storing how many extrinsics an account has signed.
    type Nonce = Nonce;
    /// The type for hashing blocks and tries.
    type Hash = Hash;
    /// The hashing algorithm used.
    type Hashing = Hashing;
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
    type Lookup = IdentityLookup<AccountId>;
    /// The header type.
    type Block = Block;
    /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
    type BlockHashCount = BlockHashCount;
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = DbWeight;
    /// Version of the runtime.
    type Version = Version;
    /// Provides information about the pallet setup in the runtime.
    type PalletInfo = PalletInfo;
    /// The data to be stored in an account.
    type AccountData = pallet_balances::AccountData<Balance>;
    /// What to do if a new account is created.
    type OnNewAccount = ();
    /// What to do if an account is fully reaped from the system.
    type OnKilledAccount = ();
    // TODO: update me (https://github.com/paritytech/parity-bridges-common/issues/78)
    /// Weight information for the extrinsics of this pallet.
    type SystemWeightInfo = ();
    /// The designated SS58 prefix of this chain.
    type SS58Prefix = SS58Prefix;
    /// The set code logic, just the default since we're not a parachain.
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

impl pallet_aura::Config for Runtime {
    type AuthorityId = AuraId;
    type MaxAuthorities = ConstU32<10>;
    type DisabledValidators = ();
    type AllowMultipleBlocksPerSlot = ConstBool<false>;
    type SlotDuration = ();
}

impl pallet_beefy::Config for Runtime {
    type BeefyId = BeefyId;
    type MaxAuthorities = ConstU32<10>;
    type MaxNominators = ConstU32<256>;
    type MaxSetIdSessionEntries = ConstU64<0>;
    type OnNewValidatorSet = MmrLeaf;
    type WeightInfo = ();
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

impl pallet_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    // TODO: update me (https://github.com/paritytech/parity-bridges-common/issues/78)
    type WeightInfo = ();
    type MaxAuthorities = ConstU32<10>;
    type MaxNominators = ConstU32<256>;
    type MaxSetIdSessionEntries = ConstU64<0>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

/// MMR helper types.
mod mmr {
    use super::Runtime;
    pub use pallet_mmr::primitives::*;

    pub type Leaf = <<Runtime as pallet_mmr::Config>::LeafData as LeafDataProvider>::LeafData;
    pub type Hashing = <Runtime as pallet_mmr::Config>::Hashing;
    pub type Hash = <Hashing as sp_runtime::traits::Hash>::Output;
}

impl pallet_mmr::Config for Runtime {
    const INDEXING_PREFIX: &'static [u8] = b"mmr";
    type Hashing = Keccak256;
    type LeafData = pallet_beefy_mmr::Pallet<Runtime>;
    type OnNewRoot = pallet_beefy_mmr::DepositBeefyDigest<Runtime>;
    type WeightInfo = ();
}

parameter_types! {
    /// Version of the produced MMR leaf.
    ///
    /// The version consists of two parts;
    /// - `major` (three bits)
    /// - `minor` (five bits)
    ///
    /// `Major` should be updated only if decoding the previous MMR Leaf format from the payload
    /// is not possible (i.e., backward incompatible change).
    /// `Minor` should be updated if fields are added to the previous MMR Leaf, which given SCALE
    /// encoding does not prevent old leaves from being decoded.
    ///
    /// Hence, we expect `major` to be changed really rarely (think never).
    /// See [`MmrLeafVersion`] type documentation for more details.
    pub LeafVersion: MmrLeafVersion = MmrLeafVersion::new(0, 0);
}

pub struct BeefyDummyDataProvider;

impl sp_consensus_beefy::mmr::BeefyDataProvider<()> for BeefyDummyDataProvider {
    fn extra_data() {}
}

impl pallet_beefy_mmr::Config for Runtime {
    type LeafVersion = LeafVersion;
    type BeefyAuthorityToMerkleLeaf = pallet_beefy_mmr::BeefyEcdsaToEthereum;
    type LeafExtra = ();
    type BeefyDataProvider = BeefyDummyDataProvider;
}

parameter_types! {
    pub const MinimumPeriod: u64 = bp_westend::SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the UNIX epoch.
    type Moment = u64;
    type OnTimestampSet = Aura;
    type MinimumPeriod = MinimumPeriod;
    // TODO: update me (https://github.com/paritytech/parity-bridges-common/issues/78)
    type WeightInfo = ();
}

parameter_types! {
    pub const ExistentialDeposit: bp_westend::Balance = 500;
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
    type MaxFreezes = ConstU32<0>;
}

parameter_types! {
    pub const TransactionBaseFee: Balance = 0;
    pub const TransactionByteFee: Balance = 1;
    // values for the following parameters are copied from polkadot repo, but it is fine
    // not to sync them - we're not going to make Rococo a full copy of one of Polkadot-like chains
    pub const TargetBlockFullness: Perquintill = Perquintill::from_percent(25);
    pub AdjustmentVariable: Multiplier = Multiplier::saturating_from_rational(3, 100_000);
    pub MinimumMultiplier: Multiplier = Multiplier::saturating_from_rational(1, 1_000_000u128);
    pub MaximumMultiplier: Multiplier = sp_runtime::traits::Bounded::max_value();
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = pallet_transaction_payment::CurrencyAdapter<Balances, ()>;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
    type FeeMultiplierUpdate = pallet_transaction_payment::TargetedFeeAdjustment<
        Runtime,
        TargetBlockFullness,
        AdjustmentVariable,
        MinimumMultiplier,
        MaximumMultiplier,
    >;
    type OperationalFeeMultiplier = ConstU8<5>;
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const RelayerStakeReserveId: [u8; 8] = *b"brdgrlrs";
}

pub const PERIOD: u32 = 6 * HOURS;
pub const OFFSET: u32 = 0;

impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = <Self as frame_system::Config>::AccountId;
    type ValidatorIdOf = ();
    type ShouldEndSession = pallet_session::PeriodicSessions<ConstU32<PERIOD>, ConstU32<OFFSET>>;
    type NextSessionRotation = pallet_session::PeriodicSessions<ConstU32<PERIOD>, ConstU32<OFFSET>>;
    type SessionManager = CollatorSelection;
    type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type Keys = SessionKeys;
    // TODO: update me (https://github.com/paritytech/parity-bridges-common/issues/78)
    type WeightInfo = ();
}

impl pallet_bridge_relayers::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Reward = Balance;
    type PaymentProcedure =
    bp_relayers::PayRewardFromAccount<pallet_balances::Pallet<Runtime>, AccountId>;
    type StakeAndSlash = pallet_bridge_relayers::StakeAndSlashNamed<
        AccountId,
        BlockNumber,
        Balances,
        RelayerStakeReserveId,
        ConstU64<1_000>,
        ConstU64<8>,
    >;
    type WeightInfo = ();
}

pub type RococoGrandpaInstance = ();

impl pallet_bridge_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type BridgedChain = bp_rococo::Rococo;
    type MaxFreeMandatoryHeadersPerBlock = ConstU32<4>;
    type HeadersToKeep = ConstU32<{ bp_westend::DAYS }>;
    type WeightInfo = pallet_bridge_grandpa::weights::BridgeWeight<Runtime>;
}

pub type WestendGrandpaInstance = pallet_bridge_grandpa::Instance1;

impl pallet_bridge_grandpa::Config<WestendGrandpaInstance> for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type BridgedChain = bp_westend::Westend;
    type MaxFreeMandatoryHeadersPerBlock = ConstU32<4>;
    type HeadersToKeep = ConstU32<{ bp_westend::DAYS }>;
    type WeightInfo = pallet_bridge_grandpa::weights::BridgeWeight<Runtime>;
}

parameter_types! {
    pub const MaxMessagesToPruneAtOnce: bp_messages::MessageNonce = 8;
    pub const RootAccountForPayments: Option<AccountId> = None;
    pub WestendGlobalConsensusNetwork: staging_xcm::prelude::NetworkId = staging_xcm::prelude::NetworkId::Westend;
    pub FromAssetHubRococoToAssetHubWestendRoute: SenderAndLane = SenderAndLane::new(
		ParentThen([BridgeHubRococoChainId.into()].into()).into(),
		XCM_LANE_FOR_ASSET_HUB_ROCOCO_TO_ASSET_HUB_WESTEND,
	);
    pub ActiveLanes: sp_std::vec::Vec<(SenderAndLane, (staging_xcm::prelude::NetworkId, staging_xcm::prelude::InteriorLocation))> = sp_std::vec![
			(
				FromAssetHubRococoToAssetHubWestendRoute::get(),
				(WestendGlobalConsensusNetwork::get(), [Parachain(AssetHubWestendParaId::get().into())].into())
			)
	];
}

/// On messages delivered callback.
type OnMessagesDelivered = XcmBlobHaulerAdapter<ToBridgeHubRococoXcmBlobHauler, ActiveLanes>;

// /// Message verifier for BridgeHubRococo messages sent from BridgeHubWestend
// type ToBridgeHubRococoMessageVerifier = FromThisChainMessageVerifier<
//     WithBridgeHubRococoMessageBridge,
// >;

/// Dispatches received XCM messages from another bridge
type FromRococoMessageBlobDispatcher = BridgeBlobDispatcher<
    XcmRouter,
    BridgeHubWestendLocation,
    BridgeWestendToRococoMessagesPalletInstance,
>;

/// Maximal outbound payload size of BridgeHubWestend -> BridgeHubRococo messages.
type ToBridgeHubRococoMaximalOutboundPayloadSize =
FromThisChainMaximalOutboundPayloadSize<WithBridgeHubRococoMessageBridge>;


/// Add XCM messages support for BridgeHubWestend to support Westend->Rococo XCM messages
pub type WithBridgeHubRococoMessagesInstance = pallet_bridge_messages::Instance1;

impl pallet_bridge_messages::Config<WithBridgeHubRococoMessagesInstance> for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type BridgedChainId = BridgeHubRococoChainId;
    type ActiveOutboundLanes = ActiveOutboundLanesToBridgeHubRococo;
    type MaxUnrewardedRelayerEntriesAtInboundLane = MaxUnrewardedRelayerEntriesAtInboundLane;
    type MaxUnconfirmedMessagesAtInboundLane = MaxUnconfirmedMessagesAtInboundLane;

    type MaximalOutboundPayloadSize = ToBridgeHubRococoMaximalOutboundPayloadSize;
    type OutboundPayload = XcmAsPlainPayload;

    type InboundPayload = XcmAsPlainPayload;
    type InboundRelayer = AccountId;
    type DeliveryPayments = ();

    type TargetHeaderChain = TargetHeaderChainAdapter<WithBridgeHubRococoMessageBridge>;
    type DeliveryConfirmationPayments = pallet_bridge_relayers::DeliveryConfirmationPaymentsAdapter<
        Runtime,
        WithBridgeHubRococoMessagesInstance,
        DeliveryRewardInBalance,
    >;

    type OnMessagesDelivered = OnMessagesDelivered;
    type SourceHeaderChain = SourceHeaderChainAdapter<WithBridgeHubRococoMessageBridge>;
    type MessageDispatch = XcmBlobMessageDispatch<
        FromRococoMessageBlobDispatcher,
        Self::WeightInfo,
        cumulus_pallet_xcmp_queue::bridging::OutXcmpChannelStatusProvider<
            AssetHubWestendParaId,
            Runtime,
        >,
    >;
}

/// XCM router instance to BridgeHub with bridging capabilities for `Westend` global
/// consensus with dynamic fees and back-pressure.
pub type ToWestendXcmRouterInstance = pallet_xcm_bridge_hub_router::Instance3;

impl pallet_xcm_bridge_hub_router::Config<ToWestendXcmRouterInstance> for Runtime {
    type WeightInfo =
        pallet_xcm_bridge_hub_router::weights::BridgeWeight<Runtime>;

    type UniversalLocation = xcm_config::UniversalLocation;
    type BridgedNetworkId = xcm_config::bridging::to_westend::WestendNetwork;
    type Bridges = xcm_config::bridging::NetworkExportTable;
    type DestinationVersion = ();

    #[cfg(not(feature = "runtime-benchmarks"))]
    type BridgeHubOrigin =
    EnsureXcm<Equals<asset_hub_westend_runtime::xcm_config::bridging::SiblingBridgeHub>>;
    #[cfg(feature = "runtime-benchmarks")]
    type BridgeHubOrigin = EitherOfDiverse<
        // for running benchmarks
        EnsureRoot<AccountId>,
        // for running tests with `--feature runtime-benchmarks`
        EnsureXcm<Equals<xcm_config::bridging::SiblingBridgeHub>>,
    >;

    type ToBridgeHubSender = XcmpQueue;
    type WithBridgeHubChannel =
    cumulus_pallet_xcmp_queue::bridging::InAndOutXcmpChannelStatusProvider<
        asset_hub_westend_runtime::xcm_config::bridging::SiblingBridgeHubParaId,
        Runtime,
    >;

    type ByteFee = asset_hub_westend_runtime::xcm_config::bridging::XcmBridgeHubRouterByteFee;
    type FeeAsset = asset_hub_westend_runtime::xcm_config::bridging::XcmBridgeHubRouterFeeAssetId;
}

// /// Instance of the XCM bridge hub pallet used to relay messages to/from Rococo chain.
// pub type WithRialtoXcmBridgeHubInstance = ();

// impl pallet_xcm_bridge_hub::Config<WithRialtoXcmBridgeHubInstance> for Runtime {
//     type RuntimeEvent = RuntimeEvent;

//     type UniversalLocation = xcm_config::UniversalLocation;
//     type BridgedNetworkId = xcm_config::RialtoNetwork;
//     type BridgeMessagesPalletInstance = WithRialtoMessagesInstance;

//     type OpenBridgeOrigin = frame_support::traits::NeverEnsureOrigin<xcm::latest::MultiLocation>;
//     type BridgeOriginAccountIdConverter = xcm_config::SovereignAccountOf;

//     type BridgeReserve = ConstU64<1_000_000_000>;
//     type NativeCurrency = Balances;

//     type LocalXcmChannelManager = ();
//     type BlobDispatcher = xcm_config::OnMillauBlobDispatcher;
//     type MessageExportPrice = ();
// }

// Configure the pallet-computational-work in pallets/computational_work.
impl pallet_computational_work::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Aura>;
}

impl pallet_check_node_computational_work::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Aura>;
}

construct_runtime!(
    pub enum Runtime {
        System: frame_system,
        Sudo: pallet_sudo,
        // Utility: pallet_utility,

        // Must be before session.
        Aura: pallet_aura,

        Timestamp: pallet_timestamp,
        Balances: pallet_balances,
        TransactionPayment: pallet_transaction_payment,

        // Consensus support.
        Session: pallet_session,
        Grandpa: pallet_grandpa,

        // BEEFY Bridges support.
        Beefy: pallet_beefy,
        Mmr: pallet_mmr,
        MmrLeaf: pallet_beefy_mmr,

        // Rococo bridge modules.
        BridgeRelayers: pallet_bridge_relayers,
        BridgeRococoGrandpa: pallet_bridge_grandpa,
        BridgeRococoMessages: pallet_bridge_messages::<Instance1>,

        // Check if it still relevant
        XcmRococoBridgeHub: pallet_xcm_bridge_hub,

        ComputationalWork: pallet_computational_work,
        CheckNodeComputationalWork: pallet_check_node_computational_work,

        // Westend bridge modules.
        BridgeWestendGrandpa: pallet_bridge_grandpa::<Instance1>,
        // BridgeWestendParachains: pallet_bridge_parachains::<Instance1>,

        // Pallet for sending XCM.
        XcmPallet: pallet_xcm,

        // Pallets that are not actually used here (yet?), but we need to run benchmarks on it.
        XcmBridgeHubRouter: pallet_xcm_bridge_hub_router::<Instance3>,
    }
);

// generate_bridge_reject_obsolete_headers_and_messages! {
//     Call, AccountId,
//     BridgeRococoGrandpa, BridgeRococoMessages,
//     BridgeRococoParachains
// }

/// The address format for describing accounts.
pub type Address = AccountId;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, Hashing>;
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
    BridgeRejectObsoleteHeadersAndMessages,
    (OnBridgeHubWestendRefundBridgeHubRococoMessages,),
);
/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
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

#[cfg(feature = "runtime-benchmarks")]
mod benches {
    frame_benchmarking::define_benchmarks!(
        [pallet_bridge_messages, MessagesBench::<Runtime, WithRococoBulletinMessagesInstance>]
        [pallet_bridge_grandpa, BridgeRococoGrandpa]
        [pallet_bridge_relayers, RelayersBench::<Runtime>]
        [pallet_xcm_bridge_hub_router, XcmBridgeHubRouterBench::<Runtime>]
    );
}

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block);
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
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
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

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
        fn account_nonce(account: AccountId) -> Nonce {
            System::account_nonce(account)
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

    impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
        fn slot_duration() -> sp_consensus_aura::SlotDuration {
            sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
        }

        fn authorities() -> Vec<AuraId> {
            Aura::authorities().to_vec()
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
        Block,
        Balance,
    > for Runtime {
        fn query_info(uxt: <Block as BlockT>::Extrinsic, len: u32) -> RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }
        fn query_fee_details(uxt: <Block as BlockT>::Extrinsic, len: u32) -> FeeDetails<Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }
        fn query_weight_to_fee(weight: Weight) -> Balance {
            TransactionPayment::weight_to_fee(weight)
        }
        fn query_length_to_fee(length: u32) -> Balance {
            TransactionPayment::length_to_fee(length)
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, sp_core::crypto::KeyTypeId)>> {
            SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl sp_consensus_beefy::BeefyApi<Block, BeefyId> for Runtime {
        fn beefy_genesis() -> Option<BlockNumber> {
            Beefy::genesis_block()
        }

        fn validator_set() -> Option<ValidatorSet<BeefyId>> {
            Beefy::validator_set()
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            _equivocation_proof: sp_consensus_beefy::EquivocationProof<
                NumberFor<Block>,
                sp_consensus_beefy::ecdsa_crypto::AuthorityId,
                sp_consensus_beefy::ecdsa_crypto::Signature
            >,
            _key_owner_proof: sp_consensus_beefy::OpaqueKeyOwnershipProof,
        ) -> Option<()> { None }

        fn generate_key_ownership_proof(
            _set_id: sp_consensus_beefy::ValidatorSetId,
            _authority_id: sp_consensus_beefy::ecdsa_crypto::AuthorityId,
        ) -> Option<sp_consensus_beefy::OpaqueKeyOwnershipProof> { None }
    }

    impl pallet_mmr::primitives::MmrApi<
        Block,
        mmr::Hash,
        BlockNumber,
    > for Runtime {
        fn mmr_root() -> Result<mmr::Hash, mmr::Error> {
            Ok(Mmr::mmr_root())
        }

        fn mmr_leaf_count() -> Result<mmr::LeafIndex, mmr::Error> {
            Ok(Mmr::mmr_leaves())
        }

        fn generate_proof(
            block_numbers: Vec<BlockNumber>,
            best_known_block_number: Option<BlockNumber>,
        ) -> Result<(Vec<mmr::EncodableOpaqueLeaf>, mmr::Proof<mmr::Hash>), mmr::Error> {
            Mmr::generate_proof(block_numbers, best_known_block_number).map(
                |(leaves, proof)| {
                    (
                        leaves
                            .into_iter()
                            .map(|leaf| mmr::EncodableOpaqueLeaf::from_leaf(&leaf))
                            .collect(),
                        proof,
                    )
                },
            )
        }

        fn verify_proof(leaves: Vec<mmr::EncodableOpaqueLeaf>, proof: mmr::Proof<mmr::Hash>)
            -> Result<(), mmr::Error>
        {
            let leaves = leaves.into_iter().map(|leaf|
                leaf.into_opaque_leaf()
                .try_decode()
                .ok_or(mmr::Error::Verify)).collect::<Result<Vec<mmr::Leaf>, mmr::Error>>()?;
            Mmr::verify_leaves(leaves, proof)
        }

        fn verify_proof_stateless(
            root: mmr::Hash,
            leaves: Vec<mmr::EncodableOpaqueLeaf>,
            proof: mmr::Proof<mmr::Hash>
        ) -> Result<(), mmr::Error> {
            let nodes = leaves.into_iter().map(|leaf|mmr::DataOrHash::Data(leaf.into_opaque_leaf())).collect();
            pallet_mmr::verify_leaves_proof::<mmr::Hashing, _>(root, nodes, proof)
        }
    }

    impl fg_primitives::GrandpaApi<Block> for Runtime {
        fn current_set_id() -> fg_primitives::SetId {
            Grandpa::current_set_id()
        }

        fn grandpa_authorities() -> GrandpaAuthorityList {
            Grandpa::grandpa_authorities()
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            equivocation_proof: fg_primitives::EquivocationProof<
                <Block as BlockT>::Hash,
                NumberFor<Block>,
            >,
            key_owner_proof: fg_primitives::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            let key_owner_proof = key_owner_proof.decode()?;

            Grandpa::submit_unsigned_equivocation_report(
                equivocation_proof,
                key_owner_proof,
            )
        }

        fn generate_key_ownership_proof(
            _set_id: fg_primitives::SetId,
            _authority_id: GrandpaId,
        ) -> Option<fg_primitives::OpaqueKeyOwnershipProof> {
            // NOTE: this is the only implementation possible since we've
            // defined our key owner proof type as a bottom type (i.e. a type
            // with no values).
            None
        }
    }

    impl bp_rococo::RococoFinalityApi<Block> for Runtime {
        fn best_finalized() -> Option<HeaderId<bp_rococo::Hash, bp_rococo::BlockNumber>> {
            BridgeRococoGrandpa::best_finalized()
        }

        fn synced_headers_grandpa_info(
        ) -> Vec<bp_header_chain::StoredHeaderGrandpaInfo<bp_rococo::Header>> {
            BridgeRococoGrandpa::synced_headers_grandpa_info()
        }
    }

    impl bp_westend::WestendFinalityApi<Block> for Runtime {
        fn best_finalized() -> Option<HeaderId<bp_westend::Hash, bp_westend::BlockNumber>> {
            BridgeWestendGrandpa::best_finalized()
        }

        fn synced_headers_grandpa_info(
        ) -> Vec<bp_header_chain::StoredHeaderGrandpaInfo<bp_westend::Header>> {
            BridgeWestendGrandpa::synced_headers_grandpa_info()
        }
    }

    // impl bp_westend::WestendFinalityApi<Block> for Runtime {
    //     fn best_finalized() -> Option<HeaderId<bp_westend::Hash, bp_westend::BlockNumber>> {
    //         pallet_bridge_parachains::Pallet::<
    //             Runtime,
    //             WithWestendParachainsInstance,
    //         >::best_parachain_head_id::<AssetHubWestend>().unwrap_or(None)
    //     }
    // }

    impl bp_bridge_hub_rococo::ToBridgeHubRococoOutboundLaneApi<Block> for Runtime {
        fn message_details(
            lane: bp_messages::LaneId,
            begin: bp_messages::MessageNonce,
            end: bp_messages::MessageNonce,
        ) -> Vec<bp_messages::OutboundMessageDetails> {
            bridge_runtime_common::messages_api::outbound_message_details::<
                Runtime,
                WithRococoBulletinMessagesInstance,
            >(lane, begin, end)
        }
    }

    impl bp_bridge_hub_rococo::FromBridgeHubRococoInboundLaneApi<Block> for Runtime {
        fn message_details(
            lane: bp_messages::LaneId,
            messages: Vec<(bp_messages::MessagePayload, bp_messages::OutboundMessageDetails)>,
        ) -> Vec<bp_messages::InboundMessageDetails> {
            bridge_runtime_common::messages_api::inbound_message_details::<
                Runtime,
                WithRococoBulletinMessagesInstance,
            >(lane, messages)
        }
    }


    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame_benchmarking::{Benchmarking, BenchmarkList};
            use frame_support::traits::StorageInfoTrait;

            use pallet_bridge_messages::benchmarking::Pallet as MessagesBench;
            use pallet_bridge_parachains::benchmarking::Pallet as ParachainsBench;
            use pallet_bridge_relayers::benchmarking::Pallet as RelayersBench;
            use pallet_xcm_bridge_hub_router::benchmarking::Pallet as XcmBridgeHubRouterBench;

            let mut list = Vec::<BenchmarkList>::new();
            list_benchmarks!(list, extra);

            let storage_info = AllPalletsWithSystem::storage_info();
            return (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig,
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame_benchmarking::{Benchmarking, BenchmarkBatch};
            use frame_support::traits::TrackedStorageKey;

            let whitelist: Vec<TrackedStorageKey> = vec![
                // Block Number
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac").to_vec().into(),
                // Execution Phase
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef7ff553b5a9862a516939d82b3d3d8661a").to_vec().into(),
                // Event Count
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef70a98fdbe9ce6c55837576c60c7af3850").to_vec().into(),
                // System Events
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7").to_vec().into(),
                // Caller 0 Account
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da946c154ffd9992e395af90b5b13cc6f295c77033fce8a9045824a6690bbf99c6db269502f0a8d1d2a008542d5690a0749").to_vec().into(),
            ];

            use bp_messages::{
                source_chain::FromBridgedChainMessagesDeliveryProof,
                target_chain::FromBridgedChainMessagesProof,
                LaneId,
            };
            use bp_runtime::Chain;
            use bridge_runtime_common::messages_benchmarking::{
                generate_xcm_builder_bridge_message_sample,
                prepare_message_delivery_proof_from_grandpa_chain,
                prepare_message_delivery_proof_from_parachain,
                prepare_message_proof_from_grandpa_chain,
                prepare_message_proof_from_parachain,
            };
            use pallet_bridge_messages::benchmarking::{
                Pallet as MessagesBench,
                Config as MessagesConfig,
                MessageDeliveryProofParams,
                MessageProofParams,
            };
            use pallet_bridge_parachains::benchmarking::{
                Pallet as ParachainsBench,
                Config as ParachainsConfig,
            };
            use pallet_bridge_relayers::benchmarking::{
                Pallet as RelayersBench,
                Config as RelayersConfig,
            };
            use pallet_xcm_bridge_hub_router::benchmarking::{
                Pallet as XcmBridgeHubRouterBench,
                Config as XcmBridgeHubRouterConfig,
            };

            impl MessagesConfig<WithRialtoParachainMessagesInstance> for Runtime {
                fn bench_lane_id() -> LaneId {
                    rialto_parachain_messages::Lane::get()
                }

                fn prepare_message_proof(
                    params: MessageProofParams,
                ) -> (FromBridgedChainMessagesProof<bp_rialto_parachain::Hash>, Weight) {
                    prepare_message_proof_from_parachain::<
                        Runtime,
                        WithRialtoParachainsInstance,
                        WithRialtoParachainMessagesInstance,
                    >(params, generate_xcm_builder_bridge_message_sample(xcm::v3::Junctions::Here))
                }

                fn prepare_message_delivery_proof(
                    params: MessageDeliveryProofParams<Self::AccountId>,
                ) -> FromBridgedChainMessagesDeliveryProof<bp_rialto_parachain::Hash> {
                    prepare_message_delivery_proof_from_parachain::<
                        Runtime,
                        WithRialtoParachainsInstance,
                        WithRialtoParachainMessagesInstance,
                    >(params)
                }

                fn is_relayer_rewarded(relayer: &Self::AccountId) -> bool {
                    let lane = <Self as MessagesConfig<WithRialtoParachainMessagesInstance>>::bench_lane_id();
                    let bridged_chain_id = bp_rialto_parachain::RialtoParachain::ID;
                    pallet_bridge_relayers::Pallet::<Runtime>::relayer_reward(
                        relayer,
                        RewardsAccountParams::new(lane, bridged_chain_id, RewardsAccountOwner::BridgedChain)
                    ).is_some()
                }
            }

            impl MessagesConfig<WithRialtoMessagesInstance> for Runtime {
                fn bench_lane_id() -> LaneId {
                    rialto_messages::Lane::get()
                }

                fn prepare_message_proof(
                    params: MessageProofParams,
                ) -> (FromBridgedChainMessagesProof<bp_rococo::Hash>, Weight) {
                    prepare_message_proof_from_grandpa_chain::<
                        Runtime,
                        RialtoGrandpaInstance,
                        WithRialtoMessagesInstance,
                    >(params, generate_xcm_builder_bridge_message_sample(xcm::v3::Junctions::Here))
                }

                fn prepare_message_delivery_proof(
                    params: MessageDeliveryProofParams<Self::AccountId>,
                ) -> FromBridgedChainMessagesDeliveryProof<bp_rococo::Hash> {
                    prepare_message_delivery_proof_from_grandpa_chain::<
                        Runtime,
                        RialtoGrandpaInstance,
                        WithRialtoMessagesInstance,
                    >(params)
                }

                fn is_relayer_rewarded(relayer: &Self::AccountId) -> bool {
                    let lane = <Self as MessagesConfig<WithRialtoMessagesInstance>>::bench_lane_id();
                    let bridged_chain_id = bp_rococo::Rococo::ID;
                    pallet_bridge_relayers::Pallet::<Runtime>::relayer_reward(
                        relayer,
                        RewardsAccountParams::new(lane, bridged_chain_id, RewardsAccountOwner::BridgedChain)
                    ).is_some()
                }
            }

            // TODO: check if it is needed
            // impl ParachainsConfig<WithRialtoParachainsInstance> for Runtime {
            //     fn parachains() -> Vec<bp_polkadot_core::parachains::ParaId> {
            //         use bp_runtime::Parachain;
            //         vec![bp_polkadot_core::parachains::ParaId(bp_rialto_parachain::RialtoParachain::PARACHAIN_ID)]
            //     }

            //     fn prepare_parachain_heads_proof(
            //         parachains: &[bp_polkadot_core::parachains::ParaId],
            //         parachain_head_size: u32,
            //         proof_params: bp_runtime::UnverifiedStorageProofParams,
            //     ) -> (
            //         bp_parachains::RelayBlockNumber,
            //         bp_parachains::RelayBlockHash,
            //         bp_polkadot_core::parachains::ParaHeadsProof,
            //         Vec<(bp_polkadot_core::parachains::ParaId, bp_polkadot_core::parachains::ParaHash)>,
            //     ) {
            //         bridge_runtime_common::parachains_benchmarking::prepare_parachain_heads_proof::<
            //             Runtime,
            //             WithRialtoParachainsInstance,
            //         >(
            //             parachains,
            //             parachain_head_size,
            //             proof_params,
            //         )
            //     }
            // }

            impl RelayersConfig for Runtime {
                fn prepare_rewards_account(
                    account_params: RewardsAccountParams,
                    reward: Balance,
                ) {
                    let rewards_account = bp_relayers::PayRewardFromAccount::<
                        Balances,
                        AccountId
                    >::rewards_account(account_params);
                    Self::deposit_account(rewards_account, reward);
                }

                fn deposit_account(account: AccountId, balance: Balance) {
                    use frame_support::traits::fungible::Mutate;
                    Balances::mint_into(&account, balance.saturating_add(ExistentialDeposit::get())).unwrap();
                }
            }

            impl XcmBridgeHubRouterConfig<()> for Runtime {
                fn make_congested() {
                    xcm_config::EmulatedSiblingXcmpChannel::make_congested()
                }
            }

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);

            add_benchmarks!(params, batches);

            Ok(batches)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bp_runtime::Chain;

    #[test]
    fn runtime_version() {
        assert_eq!(
            VERSION.state_version,
            bp_millau::Millau::STATE_VERSION as u8
        );
    }

    #[test]
    fn call_size() {
        const BRIDGES_PALLETS_MAX_CALL_SIZE: usize = 200;
        assert!(
            core::mem::size_of::<pallet_bridge_grandpa::Call<Runtime>>()
                <= BRIDGES_PALLETS_MAX_CALL_SIZE
        );
        assert!(
            core::mem::size_of::<pallet_bridge_messages::Call<Runtime>>()
                <= BRIDGES_PALLETS_MAX_CALL_SIZE
        );
        const MAX_CALL_SIZE: usize = 230; // value from polkadot-runtime tests
        assert!(core::mem::size_of::<RuntimeCall>() <= MAX_CALL_SIZE);
    }
}
