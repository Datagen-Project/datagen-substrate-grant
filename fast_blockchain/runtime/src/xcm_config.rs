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

//! XCM configurations for the Millau runtime.

use super::{
    AccountId, Balances, Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin, XcmPallet, Balance,
    TransactionByteFee,
};

use frame_support::{
    parameter_types,
    traits::{ConstU32, Everything, Nothing},
    weights::Weight,
};
use frame_system::EnsureRoot;
// TODO: Check how to gather all and if we keep them
use bridge_hub_westend_runtime::{
    xcm_config::{SafeCallFilter, WestendLocation},
    PolkadotXcm,
};
use parachains_common::impls::ToStakingPot;
use westend_runtime::{xcm_config::ThisNetwork, AllPalletsWithSystem};
use staging_xcm::latest::prelude::*;
use staging_xcm::v3::{InteriorMultiLocation};
use staging_xcm_builder::{
    Account32Hash, AccountId32Aliases, CurrencyAdapter as XcmCurrencyAdapter, IsConcrete,
    MintLocation, SignedAccountId32AsNative, SignedToAccountId32, SovereignSignedViaLocation,
    TakeWeightCredit, UsingComponents, WeightInfoBounds,
};
use staging_xcm_executor::traits::{WithOriginFilter};

parameter_types! {
    /// The location of the `MLAU` token, from the context of this chain. Since this token is native to this
    /// chain, we make it synonymous with it, and thus it is the `Here` location, which means "equivalent to
    /// the context".
    pub const TokenLocation: Location = Here.into_location();
    /// Token asset identifier.
    pub TokenAssetId: AssetId = TokenLocation::get().into();

    /// Our XCM location ancestry - i.e. our location within the Consensus Universe.
    ///
    /// Since Kusama is a top-level relay-chain with its own consensus, it's just our network ID.
    pub UniversalLocation: InteriorMultiLocation = ThisNetwork::get().into();
    /// The check account, which holds any native assets that have been teleported out and not back in (yet).
    pub CheckAccount: (AccountId, MintLocation) = (XcmPallet::check_account(), MintLocation::Local);
}

/// The canonical means of converting a `MultiLocation` into an `AccountId`, used when we want to
/// determine the sovereign account controlled by a location.
pub type SovereignAccountOf = (
    // We can directly alias an `AccountId32` into a local account.
    AccountId32Aliases<ThisNetwork, AccountId>,
    // Dummy stuff for our tests.
    Account32Hash<ThisNetwork, AccountId>,
);

/// Our asset transactor. This is what allows us to interest with the runtime facilities from the
/// point of view of XCM-only concepts like `MultiLocation` and `MultiAsset`.
///
/// Ours is only aware of the Balances pallet, which is mapped to `TokenLocation`.
pub type LocalAssetTransactor = XcmCurrencyAdapter<
    // Use this currency:
    Balances,
    // Use this currency when it is a fungible asset matching the given location or name:
    IsConcrete<TokenLocation>,
    // We can convert the MultiLocations with our converter above:
    SovereignAccountOf,
    // Our chain's account ID type (we can't get away without mentioning it explicitly):
    AccountId,
    // We track our teleports in/out to keep total issuance correct.
    CheckAccount,
>;

/// The means that we convert the XCM message origin location into a local dispatch origin.
type LocalOriginConverter = (
    // A `Signed` origin of the sovereign account that the original location controls.
    SovereignSignedViaLocation<SovereignAccountOf, RuntimeOrigin>,
    // The AccountId32 location type can be expressed natively as a `Signed` origin.
    SignedAccountId32AsNative<ThisNetwork, RuntimeOrigin>,
);

parameter_types! {
    /// The amount of weight an XCM operation takes. This is a safe overestimate.
    pub const BaseXcmWeight: Weight = Weight::from_parts(1_000_000_000, 64 * 1024);
    /// Maximum number of instructions in a single XCM fragment. A sanity check against weight
    /// calculations getting too crazy.
    pub const MaxInstructions: u32 = 100;
}

/// The XCM router. We are not sending messages to sibling/parent/child chains here.
pub type XcmRouter = ();

/// The barriers one of which must be passed for an XCM message to be executed.
pub type Barrier = (
    // Weight that is paid for may be consumed.
    TakeWeightCredit,
);

/// Dispatches received XCM messages from other chain.
pub type OnMillauBlobDispatcher = staging_xcm_builder::BridgeBlobDispatcher<
    crate::xcm_config::XcmRouter,
    crate::xcm_config::UniversalLocation,
    (),
>;

/// Handles converting a weight scalar to a fee value, based on the scale and granularity of the
/// node's balance type.
///
/// This should typically create a mapping between the following ranges:
///   - `[0, MAXIMUM_BLOCK_WEIGHT]`
///   - `[Balance::min, Balance::max]`
///
/// Yet, it can be used for any other sort of change to weight-fee. Some examples being:
///   - Setting it to `0` will essentially disable the weight fee.
///   - Setting it to `1` will cause the literal `#[weight = x]` values to be charged.
pub struct WeightToFee;

impl frame_support::weights::WeightToFeePolynomial for WeightToFee {
    type Balance = super::Balance;
    fn polynomial() -> frame_support::weights::WeightToFeeCoefficients<Self::Balance> {
        let p = super::currency::CENTS;
        let q = 10 * super::Balance::from(frame_support::weights::constants::ExtrinsicBaseWeight::get().ref_time());
        smallvec::smallvec![frame_support::weights::WeightToFeeCoefficient {
            degree: 1,
            negative: false,
            coeff_frac: sp_runtime::Perbill::from_rational(p % q, q),
            coeff_integer: p / q,
        }]
    }
}

/// XCM weigher type.
pub type XcmWeigher = staging_xcm_builder::FixedWeightBounds<BaseXcmWeight, RuntimeCall, MaxInstructions>;

pub struct XcmConfig;
impl staging_xcm_executor::Config for XcmConfig {
    type RuntimeCall = RuntimeCall;
    type XcmSender = XcmRouter;
    type AssetTransactor = LocalAssetTransactor;
    type OriginConverter = LocalOriginConverter;
    type IsReserve = ();
    type IsTeleporter = ();
    type Aliasers = Nothing;
    type UniversalLocation = UniversalLocation;
    type Barrier = Barrier;
    type Weigher = WeightInfoBounds<
collectives_westend_runtime::xcm_config::TempFixedXcmWeight,
        RuntimeCall,
        MaxInstructions,
    >;
    type Trader =
        UsingComponents<WeightToFee, WestendLocation, AccountId, Balances, ToStakingPot<Runtime>>;
    type ResponseHandler = PolkadotXcm;
    type AssetTrap = PolkadotXcm;
    type AssetLocker = ();
    type AssetExchanger = ();
    type AssetClaims = PolkadotXcm;
    type SubscriptionService = PolkadotXcm;
    type PalletInstancesInfo = AllPalletsWithSystem;
    type MaxAssetsIntoHolding = ConstU32<64>;
    type FeeManager = ();
    type MessageExporter =
        bridge_hub_westend_runtime::bridge_to_rococo_config::ToBridgeHubRococoHaulBlobExporter;
    type UniversalAliases = Nothing;
    type CallDispatcher = WithOriginFilter<SafeCallFilter>;
    type SafeCallFilter = SafeCallFilter;
    type TransactionalProcessor = ();
    type HrmpNewChannelOpenRequestHandler = ();
    type HrmpChannelAcceptedHandler = ();
    type HrmpChannelClosingHandler = ();
}

/// Type to convert an `Origin` type value into a `MultiLocation` value which represents an interior
/// location of this chain.
pub type LocalOriginToLocation = (
    // Usual Signed origin to be used in XCM as a corresponding AccountId32
    SignedToAccountId32<RuntimeOrigin, AccountId, ThisNetwork>,
);

#[cfg(feature = "runtime-benchmarks")]
parameter_types! {
    pub ReachableDest: Option<MultiLocation> = None;
}

impl pallet_xcm::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type CurrencyMatcher = ();
    // We don't allow any messages to be sent via the transaction yet. This is basically safe to
    // enable, (safe the possibility of someone spamming the parachain if they're willing to pay
    // the DOT to send from the Relay-chain). But it's useless until we bring in XCM v3 which will
    // make `DescendOrigin` a bit more useful.
    type SendXcmOrigin = staging_xcm_builder::EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>;
    type XcmRouter = ();
    // Anyone can execute XCM messages locally.
    type ExecuteXcmOrigin = staging_xcm_builder::EnsureXcmOrigin<RuntimeOrigin, LocalOriginToLocation>;
    type XcmExecuteFilter = Everything;
    type XcmExecutor = staging_xcm_executor::XcmExecutor<XcmConfig>;
    // Anyone is able to use teleportation regardless of who they are and what they want to
    // teleport.
    type XcmTeleportFilter = Everything;
    // Anyone is able to use reserve transfers regardless of who they are and what they want to
    // transfer.
    type XcmReserveTransferFilter = Everything;
    type Weigher = XcmWeigher;
    type UniversalLocation = UniversalLocation;
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    const VERSION_DISCOVERY_QUEUE_SIZE: u32 = 100;
    type AdvertisedXcmVersion = pallet_xcm::CurrentXcmVersion;
    type AdminOrigin = EnsureRoot<AccountId>;
    type TrustedLockers = ();
    type SovereignAccountOf = SovereignAccountOf;
    type MaxLockers = ConstU32<8>;
    type MaxRemoteLockConsumers = ConstU32<0>;
    type RemoteLockConsumerIdentifier = ();
    type WeightInfo = pallet_xcm::TestWeightInfo;
}

/// All configuration related to bridging
pub mod bridging {
    use super::*;
    use assets_common::matching;
    use sp_std::collections::btree_set::BTreeSet;
    use staging_xcm_builder::NetworkExportTableItem;

    // common/shared parameters
    parameter_types! {
		/// Base price of every byte of the Rococo -> Westend message. Can be adjusted via
        /// governance `set_storage` call.
        ///
        /// Default value is our estimation of the:
        ///
        /// 1) an approximate cost of XCM execution (`ExportMessage` and surroundings) at Rococo bridge hub;
        ///
        /// 2) the approximate cost of Rococo -> Westend message delivery transaction on Westend Bridge Hub,
        ///    converted into ROCs using 1:1 conversion rate;
        ///
        /// 3) the approximate cost of Rococo -> Westend message confirmation transaction on Rococo Bridge Hub.
		pub storage XcmBridgeHubRouterBaseFee: Balance =
			bp_bridge_hub_rococo::BridgeHubRococoBaseXcmFeeInRocs::get()
				.saturating_add(bp_bridge_hub_westend::BridgeHubWestendBaseDeliveryFeeInWnds::get())
				.saturating_add(bp_bridge_hub_rococo::BridgeHubRococoBaseConfirmationFeeInRocs::get());
		/// Price of every byte of the Rococo -> Westend message. Can be adjusted via
        /// governance `set_storage` call.
		pub storage XcmBridgeHubRouterByteFee: Balance = TransactionByteFee::get();

		pub SiblingBridgeHubParaId: u32 = bp_bridge_hub_rococo::BRIDGE_HUB_ROCOCO_PARACHAIN_ID;
		pub SiblingBridgeHub: Location = Location::new(1, [Parachain(SiblingBridgeHubParaId::get())]);
		/// Router expects payment with this `AssetId`.
        /// (`AssetId` has to be aligned with `BridgeTable`)
		pub XcmBridgeHubRouterFeeAssetId: AssetId = TokenLocation::get().into();

		pub BridgeTable: sp_std::vec::Vec<NetworkExportTableItem> =
			sp_std::vec::Vec::new().into_iter()
			.chain(to_westend::BridgeTable::get())
			.collect();
	}

    pub type NetworkExportTable = staging_xcm_builder::NetworkExportTable<BridgeTable>;

    pub mod to_westend {
        use frame_support::traits::Contains;
        use staging_xcm_builder::NetworkExportTableItem;
        use crate::XcmBridgeHubRouter;
        use super::*;

        parameter_types! {
			pub SiblingBridgeHubWithBridgeHubWestendInstance: Location = Location::new(
				1,
				[
					Parachain(SiblingBridgeHubParaId::get()),
					PalletInstance(bp_bridge_hub_rococo::WITH_BRIDGE_ROCOCO_TO_WESTEND_MESSAGES_PALLET_INDEX)
				]
			);

			pub const WestendNetwork: NetworkId = NetworkId::Westend;
			pub AssetHubWestend: Location = Location::new(2, [GlobalConsensus(WestendNetwork::get()), Parachain(bp_asset_hub_westend::ASSET_HUB_WESTEND_PARACHAIN_ID)]);
			pub WndLocation: Location = Location::new(2, [GlobalConsensus(WestendNetwork::get())]);

			pub WndFromAssetHubWestend: (AssetFilter, Location) = (
				Wild(AllOf { fun: WildFungible, id: AssetId(WndLocation::get()) }),
				AssetHubWestend::get()
			);

			/// Set up exporters' configuration.
            /// `Option<Asset>` represents static "base fee" which is used for total delivery fee calculation.
			pub BridgeTable: sp_std::vec::Vec<NetworkExportTableItem> = sp_std::vec![
				NetworkExportTableItem::new(
					WestendNetwork::get(),
					Some(sp_std::vec![
						AssetHubWestend::get().interior.split_global().expect("invalid configuration for AssetHubWestend").1,
					]),
					SiblingBridgeHub::get(),
					// base delivery fee to local `BridgeHub`
					Some((
						XcmBridgeHubRouterFeeAssetId::get(),
						XcmBridgeHubRouterBaseFee::get(),
					).into())
				)
			];

			/// Universal aliases
			pub UniversalAliases: BTreeSet<(Location, Junction)> = BTreeSet::from_iter(
				sp_std::vec![
					(SiblingBridgeHubWithBridgeHubWestendInstance::get(), GlobalConsensus(WestendNetwork::get()))
				]
			);
		}

        impl Contains<(Location, Junction)> for UniversalAliases {
            fn contains(alias: &(Location, Junction)) -> bool {
                UniversalAliases::get().contains(alias)
            }
        }

        /// Trusted reserve locations filter for `xcm_executor::Config::IsReserve`.
        /// Locations from which the runtime accepts reserved assets.
        pub type IsTrustedBridgedReserveLocationForConcreteAsset =
        matching::IsTrustedBridgedReserveLocationForConcreteAsset<
            UniversalLocation,
            (
                // allow to receive WND from AssetHubWestend
                staging_xcm_builder::Case<WndFromAssetHubWestend>,
                // and nothing else
            ),
        >;

        impl Contains<RuntimeCall> for XcmBridgeHubRouter {
            fn contains(call: &RuntimeCall) -> bool {
                matches!(
					call,
					RuntimeCall::XcmBridgeHubRouter(
						pallet_xcm_bridge_hub_router::Call::report_bridge_status { .. }
					)
				)
            }
        }
    }
}
