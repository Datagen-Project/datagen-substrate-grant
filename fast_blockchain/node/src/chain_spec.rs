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

use bridge_hub_westend_runtime::{RuntimeGenesisConfig, BridgeRococoMessagesConfig};
use pallet_im_online::sr25519::AuthorityId as ImOnlineId;
use polkadot_primitives::{AssignmentId, ValidatorId};
use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_babe::AuthorityId as BabeId;
use sp_consensus_beefy::ecdsa_crypto::AuthorityId as BeefyId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    AccountId32 as AccountId, MultiSignature as Signature,
};
use westend_runtime::{
    StakerStatus,
    BalancesConfig, BeefyConfig, GrandpaConfig, SessionConfig, SessionKeys, SudoConfig,
    SystemConfig, WASM_BINARY, BABE_GENESIS_EPOCH_CONFIG,
};
use staging_xcm::v3::{NetworkId::Rococo as RococoId, NetworkId::Westend as WestendId};
use pallet_staking::Forcing;
use sp_arithmetic::per_things::Perbill;

/// The default XCM version to set in genesis config.
pub const SAFE_XCM_VERSION: u32 = staging_xcm::prelude::XCM_VERSION;

/// "Names" of the authorities accounts at local testnet.
const LOCAL_AUTHORITIES_ACCOUNTS: [&str; 5] = ["Alice", "Bob", "Charlie", "Dave", "Eve"];
/// "Names" of the authorities accounts at development testnet.
const DEV_AUTHORITIES_ACCOUNTS: [&str; 1] = [LOCAL_AUTHORITIES_ACCOUNTS[0]];
/// "Names" of all possible authorities accounts.
const ALL_AUTHORITIES_ACCOUNTS: [&str; 5] = LOCAL_AUTHORITIES_ACCOUNTS;
/// "Name" of the `sudo` account.
const SUDO_ACCOUNT: &str = "Sudo";
/// "Name" of the account, which owns the with-Westend GRANDPA pallet.
const WESTEND_GRANDPA_PALLET_OWNER: &str = "Westend.GrandpaOwner";
/// "Name" of the account, which owns the with-Rococo messages pallet.
const ROCOCO_MESSAGES_PALLET_OWNER: &str = "Rococo.MessagesOwner";
/// "Name" of the account, which owns the with-RococoParachain messages pallet.
const ROCOCO_PARACHAIN_MESSAGES_PALLET_OWNER: &str = "RococoParachain.MessagesOwner";

use parachains_common::Balance;
use westend_runtime_constants::currency::UNITS as WND;

pub const ED: Balance = westend_runtime_constants::currency::EXISTENTIAL_DEPOSIT;
const ENDOWMENT: u128 = 1_000_000 * WND;
const STASH: u128 = 100 * WND;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<RuntimeGenesisConfig>;

/// The chain specification option. This is expected to come in from the CLI and
/// is little more than one of a number of alternatives which can easily be converted
/// from a string (`--chain=...`) into a `ChainSpec`.
#[derive(Clone, Debug)]
pub enum Alternative {
    /// Whatever the current runtime is, with just Alice as an auth.
    Development,
    /// Whatever the current runtime is, with simple Alice/Bob/Charlie/Dave/Eve auths.
    LocalTestnet,
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{seed}"), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
    where
        AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate an authority key for Aura
pub fn get_authority_keys_from_seed(
    s: &str
) -> (
    AccountId,
    AccountId,
    BabeId,
    GrandpaId,
    ImOnlineId,
    ValidatorId,
    AssignmentId,
    AuthorityDiscoveryId,
    BeefyId
) {
    (
        get_account_id_from_seed::<sr25519::Public>(s),
        get_account_id_from_seed::<sr25519::Public>(s),
        get_from_seed::<BabeId>(s),
        get_from_seed::<GrandpaId>(s),
        get_from_seed::<ImOnlineId>(s),
        get_from_seed::<ValidatorId>(s),
        get_from_seed::<AssignmentId>(s),
        get_from_seed::<AuthorityDiscoveryId>(s),
        get_from_seed::<BeefyId>(s),
    )
}

impl Alternative {
    /// Get an actual chain config from one of the alternatives.
    pub(crate) fn load(self) -> ChainSpec {
        let properties = Some(
            serde_json::json!({
                "tokenDecimals": 9,
                "tokenSymbol": "MLAU"
            })
                .as_object()
                .expect("Map given; qed")
                .clone(),
        );
        match self {
            Alternative::Development => ChainSpec::builder(
                WASM_BINARY.ok_or_else(|| {
                    "Development chain spec not available: wasm binary not available".to_string()
                }).unwrap(),
                None)
                .with_name("Westend Development")
                .with_id("westend_dev")
                .with_chain_type(sc_service::ChainType::Development)
                .with_genesis_config_patch(
                    westend_testnet_genesis(
                        DEV_AUTHORITIES_ACCOUNTS
                            .into_iter()
                            .map(|seed| get_authority_keys_from_seed(seed))
                            .collect(),
                        get_account_id_from_seed::<sr25519::Public>(SUDO_ACCOUNT),
                        Some(endowed_accounts()),
                    ))
                .build(),
            Alternative::LocalTestnet => ChainSpec::builder(
                WASM_BINARY.ok_or_else(|| {
                    "Local testnet chain spec not available: wasm binary not available".to_string()
                }).unwrap(),
                None)
                .with_name("Westend Local")
                .with_id("westend_local")
                .with_chain_type(sc_service::ChainType::Local)
                .with_genesis_config_patch(
                    westend_testnet_genesis(
                        LOCAL_AUTHORITIES_ACCOUNTS
                            .into_iter()
                            .map(|seed| get_authority_keys_from_seed(seed))
                            .collect(),
                        get_account_id_from_seed::<sr25519::Public>(SUDO_ACCOUNT),
                        Some(endowed_accounts()),
                    ))
                .build(),
        }
    }
}

/// We're using the same set of endowed accounts on all Westend chains (dev/local) to make
/// sure that all accounts, required for bridge to be functional (e.g. relayers fund account,
/// accounts used by relayers in our test deployments, accounts used for demonstration
/// purposes), are all available on these chains.
fn endowed_accounts() -> Vec<AccountId> {
    let all_authorities = ALL_AUTHORITIES_ACCOUNTS.iter().flat_map(|x| {
        [
            get_account_id_from_seed::<sr25519::Public>(x),
            get_account_id_from_seed::<sr25519::Public>(&format!("{x}//stash")),
        ]
    });
    vec![
        // Sudo account
        get_account_id_from_seed::<sr25519::Public>(SUDO_ACCOUNT),
        // Regular (unused) accounts
        get_account_id_from_seed::<sr25519::Public>("Ferdie"),
        get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
        // Accounts, used by Rococo<>Westend bridge
        get_account_id_from_seed::<sr25519::Public>(WESTEND_GRANDPA_PALLET_OWNER),
        get_account_id_from_seed::<sr25519::Public>("Westend.HeadersRelay1"),
        get_account_id_from_seed::<sr25519::Public>("Westend.HeadersRelay2"),
        get_account_id_from_seed::<sr25519::Public>("Westend.AssetHubWestendHeaders1"),
        get_account_id_from_seed::<sr25519::Public>("Westend.AssetHubWestendHeaders2"),
        // Accounts, used by Rococo<>Westend bridge
        get_account_id_from_seed::<sr25519::Public>(ROCOCO_MESSAGES_PALLET_OWNER),
        get_account_id_from_seed::<sr25519::Public>("Rococo.HeadersAndMessagesRelay"),
        get_account_id_from_seed::<sr25519::Public>("Rococo.OutboundMessagesRelay.Lane00000001"),
        get_account_id_from_seed::<sr25519::Public>("Rococo.InboundMessagesRelay.Lane00000001"),
        get_account_id_from_seed::<sr25519::Public>("Rococo.MessagesSender"),
        // Accounts, used by RococoParachain<>Westend bridge
        get_account_id_from_seed::<sr25519::Public>(ROCOCO_PARACHAIN_MESSAGES_PALLET_OWNER),
        get_account_id_from_seed::<sr25519::Public>("RococoParachain.HeadersAndMessagesRelay1"),
        get_account_id_from_seed::<sr25519::Public>("RococoParachain.HeadersAndMessagesRelay2"),
        get_account_id_from_seed::<sr25519::Public>("RococoParachain.RococoHeadersRelay1"),
        get_account_id_from_seed::<sr25519::Public>("RococoParachain.RococoHeadersRelay2"),
        get_account_id_from_seed::<sr25519::Public>("RococoParachain.MessagesSender"),
    ]
        .into_iter()
        .chain(all_authorities)
        .collect()
}

fn westend_session_keys(
    babe: BabeId,
    grandpa: GrandpaId,
    im_online: ImOnlineId,
    para_validator: ValidatorId,
    para_assignment: AssignmentId,
    authority_discovery: AuthorityDiscoveryId,
    beefy: BeefyId,
) -> westend_runtime::SessionKeys {
    westend_runtime::SessionKeys {
        babe,
        grandpa,
        im_online,
        para_validator,
        para_assignment,
        authority_discovery,
        beefy,
    }
}

// #[cfg(any(feature = "westend-native", feature = "rococo-native"))]
fn testnet_accounts() -> Vec<AccountId> {
    vec![
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        get_account_id_from_seed::<sr25519::Public>("Bob"),
        get_account_id_from_seed::<sr25519::Public>("Charlie"),
        get_account_id_from_seed::<sr25519::Public>("Dave"),
        get_account_id_from_seed::<sr25519::Public>("Eve"),
        get_account_id_from_seed::<sr25519::Public>("Ferdie"),
        get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
        get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
        get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
        get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
        get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
        get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
    ]
}

/// Helper function to create westend runtime `GenesisConfig` patch for testing
// #[cfg(feature = "westend-native")]
pub fn westend_testnet_genesis(
    initial_authorities: Vec<(
        AccountId,
        AccountId,
        BabeId,
        GrandpaId,
        ImOnlineId,
        ValidatorId,
        AssignmentId,
        AuthorityDiscoveryId,
        BeefyId,
    )>,
    root_key: AccountId,
    endowed_accounts: Option<Vec<AccountId>>,
) -> serde_json::Value {
    let endowed_accounts: Vec<AccountId> = endowed_accounts.unwrap_or_else(testnet_accounts);

    const ENDOWMENT: u128 = 1_000_000 * WND;
    const STASH: u128 = 100 * WND;

    serde_json::json!({
		"balances": {
			"balances": endowed_accounts.iter().map(|k| (k.clone(), ENDOWMENT)).collect::<Vec<_>>(),
		},
		"session": {
			"keys": initial_authorities
				.iter()
				.map(|x| {
					(
						x.0.clone(),
						x.0.clone(),
						westend_session_keys(
							x.2.clone(),
							x.3.clone(),
							x.4.clone(),
							x.5.clone(),
							x.6.clone(),
							x.7.clone(),
							x.8.clone(),
						),
					)
				})
				.collect::<Vec<_>>(),
		},
		"staking": {
			"minimumValidatorCount": 1,
			"validatorCount": initial_authorities.len() as u32,
			"stakers": initial_authorities
				.iter()
				.map(|x| (x.0.clone(), x.0.clone(), STASH, StakerStatus::<AccountId>::Validator))
				.collect::<Vec<_>>(),
			"invulnerables": initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
			"forceEra": Forcing::NotForcing,
			"slashRewardFraction": Perbill::from_percent(10),
		},
		"babe": {
			"epochConfig": Some(BABE_GENESIS_EPOCH_CONFIG),
		},
		"sudo": { "key": Some(root_key) },
		// "configuration": {
		// 	"config": default_parachains_host_configuration(),
		// },
		"registrar": {
			"nextFreeParaId": polkadot_primitives::LOWEST_PUBLIC_ID,
		},
	})
}
