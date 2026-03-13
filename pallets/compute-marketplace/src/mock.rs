use crate as pallet_compute_marketplace;
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
		ComputeMarketplace: pallet_compute_marketplace::{Pallet, Call, Storage, Event<T>},
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
	pub const ComputePalletId: PalletId = PalletId(*b"cr/compu");
}

impl pallet_compute_marketplace::Config for TestRuntime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type ComputePalletId = ComputePalletId;
	type MaxUriLen = ConstU32<256>;
	type MaxWorkers = ConstU32<1024>;
	type MaxJobs = ConstU32<4096>;
	type MaxCommitteeSize = ConstU32<5>;
	type WeightInfo = ();
}

// Test accounts
pub const REQUESTER: u64 = 1;
pub const WORKER_A: u64 = 2;
pub const WORKER_B: u64 = 3;
pub const WORKER_C: u64 = 4;
pub const WORKER_D: u64 = 5;
pub const WORKER_E: u64 = 6;
pub const CHALLENGER: u64 = 7;
pub const FUNDER: u64 = 8;

pub const INITIAL_BALANCE: u128 = 10_000_000;

pub fn default_capabilities() -> pallet_compute_marketplace::Capabilities {
	pallet_compute_marketplace::Capabilities {
		cpu_cores: 8,
		memory_mb: 16384,
		gpu: pallet_compute_marketplace::GpuClass::None,
		storage_mb: 100_000,
	}
}

pub fn gpu_capabilities() -> pallet_compute_marketplace::Capabilities {
	pallet_compute_marketplace::Capabilities {
		cpu_cores: 16,
		memory_mb: 65536,
		gpu: pallet_compute_marketplace::GpuClass::Compute,
		storage_mb: 500_000,
	}
}

pub fn weak_capabilities() -> pallet_compute_marketplace::Capabilities {
	pallet_compute_marketplace::Capabilities {
		cpu_cores: 2,
		memory_mb: 4096,
		gpu: pallet_compute_marketplace::GpuClass::None,
		storage_mb: 20_000,
	}
}

pub struct ExtBuilder;

impl ExtBuilder {
	pub fn build() -> sp_io::TestExternalities {
		let storage = frame_system::GenesisConfig::<TestRuntime>::default()
			.build_storage()
			.unwrap();

		let mut ext = sp_io::TestExternalities::from(storage);
		ext.execute_with(|| {
			System::set_block_number(1);

			// Set low minimums for tests
			pallet_compute_marketplace::MinWorkerStake::<TestRuntime>::put(100u128);
			pallet_compute_marketplace::ChallengeBondAmount::<TestRuntime>::put(50u128);
			pallet_compute_marketplace::ChallengePeriodBlocks::<TestRuntime>::put(10u32);
			pallet_compute_marketplace::HeartbeatInterval::<TestRuntime>::put(1000u32);

			// Fund test accounts
			for &(who, amount) in &[
				(REQUESTER, INITIAL_BALANCE),
				(WORKER_A, INITIAL_BALANCE),
				(WORKER_B, INITIAL_BALANCE),
				(WORKER_C, INITIAL_BALANCE),
				(WORKER_D, INITIAL_BALANCE),
				(WORKER_E, INITIAL_BALANCE),
				(CHALLENGER, INITIAL_BALANCE),
				(FUNDER, INITIAL_BALANCE),
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
		ComputeMarketplace::on_initialize(block);
		System::set_block_number(block + 1);
	}
}
