use crate as pallet_check_node_computational_work;
use frame_support::construct_runtime;
use frame_support::traits::FindAuthor;
use frame_support::traits::{ConstU16, ConstU64, OnFinalize, OnInitialize};
use sp_core::{
    crypto::{Pair, Public},
    sr25519, H256,
};
use sp_runtime::{
    traits::{BlakeTwo256, Hash, IdentifyAccount, IdentityLookup, Verify},
    MultiSignature,
};
use sp_runtime::{BuildStorage, ConsensusEngineId, SaturatedConversion};

type Block = frame_system::mocking::MockBlock<TestRuntime>;

pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

// Configure a mock runtime to TestRuntime the pallet.
construct_runtime!(
    pub enum TestRuntime
    {
        System: frame_system,
        ComputationalWork: pallet_computational_work,
        CheckNodeComputationalWork: pallet_check_node_computational_work,
    }
);

impl frame_system::Config for TestRuntime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type Block = Block;
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type RuntimeEvent = RuntimeEvent;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
}

impl pallet_computational_work::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type FindAuthor = AuthorGiven;
}

impl pallet_check_node_computational_work::Config for TestRuntime {
    type RuntimeEvent = RuntimeEvent;
    type FindAuthor = AuthorGiven;
}

pub struct AuthorGiven;
impl FindAuthor<AccountId> for AuthorGiven {
    fn find_author<'a, I>(_digests: I) -> Option<AccountId>
    where
        I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
    {
        Some(set_author())
    }
}

// Simulate the author of the blocks.
pub fn set_author() -> AccountId {
    let n = System::block_number().saturated_into::<u32>();
    match n % 4 {
        0 => get_account_id_from_seed::<sr25519::Public>("Alice"),
        1 => get_account_id_from_seed::<sr25519::Public>("Bob"),
        2 => get_account_id_from_seed::<sr25519::Public>("Charlie"),
        _ => get_account_id_from_seed::<sr25519::Public>("Dave"),
    }
}

/// Return test externalities to use in tests.
pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<TestRuntime>::default()
        .build_storage()
        .unwrap();
    sp_io::TestExternalities::new(t)
}

/// Helper function to run a block.
#[allow(dead_code)]
pub fn run_to_block(n: u64) {
    while System::block_number() < n {
        if System::block_number() > 1 {
            ComputationalWork::on_finalize(System::block_number());
            CheckNodeComputationalWork::on_finalize(System::block_number());
            System::on_finalize(System::block_number());
        }
        System::set_block_number(System::block_number() + 1);
        System::on_initialize(System::block_number());
        ComputationalWork::on_initialize(System::block_number());
        CheckNodeComputationalWork::on_initialize(System::block_number());
    }
}

/// Helper function that hash a number to a H256.
pub fn hash_number(n: u32) -> H256 {
    BlakeTwo256::hash_of(&n)
}

pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type Signature = MultiSignature;
type AccountPublic = <Signature as Verify>::Signer;

pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}
