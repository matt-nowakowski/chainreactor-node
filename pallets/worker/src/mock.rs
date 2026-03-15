use crate as pallet_worker;
use frame_support::{
	construct_runtime, parameter_types,
	traits::{ConstU32, ConstU64, ConstU128, Everything},
	PalletId,
};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};

type Block = frame_system::mocking::MockBlock<TestRuntime>;

construct_runtime!(
	pub enum TestRuntime {
		System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		Worker: pallet_worker::{Pallet, Call, Storage, Event<T>},
	}
);

impl frame_system::Config for TestRuntime {
	type BaseCallFilter = Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type RuntimeOrigin = RuntimeOrigin;
	type Nonce = u64;
	type RuntimeCall = RuntimeCall;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ConstU64<250>;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u128>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
}

impl pallet_balances::Config for TestRuntime {
	type MaxLocks = ConstU32<50>;
	type Balance = u128;
	type DustRemoval = ();
	type RuntimeEvent = RuntimeEvent;
	type ExistentialDeposit = ConstU128<1>;
	type AccountStore = System;
	type MaxReserves = ConstU32<50>;
	type ReserveIdentifier = [u8; 8];
	type WeightInfo = ();
	type RuntimeHoldReason = RuntimeHoldReason;
	type FreezeIdentifier = ();
	type MaxHolds = ConstU32<0>;
	type MaxFreezes = ConstU32<0>;
}

parameter_types! {
	pub const WorkerPalletId: PalletId = PalletId(*b"cr/workr");
}

impl pallet_worker::Config for TestRuntime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type WorkerPalletId = WorkerPalletId;
	type MaxNameLen = ConstU32<128>;
	type MaxMetadataLen = ConstU32<512>;
	type MaxSolutionGroups = ConstU32<256>;
	type MaxVotesPerRound = ConstU32<1024>;
	type WeightInfo = ();
}

// Test accounts
pub const ALICE: u64 = 1;
pub const BOB: u64 = 2;
pub const CHARLIE: u64 = 3;
pub const DAVE: u64 = 4;
pub const EVE: u64 = 5;
pub const GROUP_OWNER: u64 = 10;

pub const INITIAL_BALANCE: u128 = 1_000_000;

pub struct ExtBuilder;

impl ExtBuilder {
	pub fn build() -> sp_io::TestExternalities {
		let storage = frame_system::GenesisConfig::<TestRuntime>::default()
			.build_storage()
			.unwrap();

		let mut ext = sp_io::TestExternalities::from(storage);
		ext.execute_with(|| {
			System::set_block_number(1);

			// No cooldown for tests
			pallet_worker::SubscriptionCooldownBlocks::<TestRuntime>::put(0u32);

			// Fund test accounts
			for &(who, amount) in &[
				(ALICE, INITIAL_BALANCE),
				(BOB, INITIAL_BALANCE),
				(CHARLIE, INITIAL_BALANCE),
				(DAVE, INITIAL_BALANCE),
				(EVE, INITIAL_BALANCE),
				(GROUP_OWNER, INITIAL_BALANCE),
			] {
				let _ = <Balances as frame_support::traits::Currency<_>>::deposit_creating(&who, amount);
			}
		});
		ext
	}
}

/// Advance to a specific block, running on_initialize hooks.
pub fn run_to_block(n: u64) {
	use frame_support::traits::Hooks;
	while System::block_number() < n {
		let block = System::block_number();
		Worker::on_initialize(block);
		System::set_block_number(block + 1);
	}
}
