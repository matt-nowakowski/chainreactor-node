use crate::{mock::*, *};
use frame_support::{assert_noop, assert_ok};
use sp_core::H256;
use sp_runtime::Perbill;

fn test_spec_hash() -> H256 {
	H256::from_low_u64_be(42)
}

fn test_result_hash() -> H256 {
	H256::from_low_u64_be(99)
}

fn test_uri() -> Vec<u8> {
	b"ipfs://QmTestSpecCID123456789".to_vec()
}

fn test_result_uri() -> Vec<u8> {
	b"ipfs://QmTestResultCID987654321".to_vec()
}

fn default_requirements() -> JobRequirements {
	JobRequirements {
		min_cpu_cores: 4,
		min_memory_mb: 8192,
		gpu_required: GpuClass::None,
		min_storage_mb: 50_000,
	}
}

fn gpu_requirements() -> JobRequirements {
	JobRequirements {
		min_cpu_cores: 8,
		min_memory_mb: 32768,
		gpu_required: GpuClass::Compute,
		min_storage_mb: 100_000,
	}
}

/// Helper: register a worker with default capabilities and 1000 stake.
fn register_worker(who: u64) {
	assert_ok!(ComputeMarketplace::register_worker(
		RuntimeOrigin::signed(who),
		1000,
		default_capabilities(),
	));
}

/// Helper: register a worker with GPU capabilities.
fn register_gpu_worker(who: u64) {
	assert_ok!(ComputeMarketplace::register_worker(
		RuntimeOrigin::signed(who),
		1000,
		gpu_capabilities(),
	));
}

/// Helper: submit a heartbeat so the worker is "available".
fn heartbeat(who: u64) {
	assert_ok!(ComputeMarketplace::submit_heartbeat(RuntimeOrigin::signed(who)));
}

/// Helper: submit a default job from REQUESTER, returns job_id.
fn submit_default_job() -> JobId {
	let job_id = NextJobId::<TestRuntime>::get();
	assert_ok!(ComputeMarketplace::submit_job(
		RuntimeOrigin::signed(REQUESTER),
		test_spec_hash(),
		test_uri(),
		5000,
		100, // deadline in 100 blocks
		default_requirements(),
	));
	job_id
}

// ─── Worker Registration Tests ────────────────────────────

#[test]
fn register_worker_works() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);

		let profile = Workers::<TestRuntime>::get(WORKER_A).unwrap();
		assert_eq!(profile.stake_locked, 1000);
		assert_eq!(profile.capabilities.cpu_cores, 8);
		assert_eq!(profile.active_jobs, 0);
		assert_eq!(profile.reputation, Perbill::from_percent(100));
		assert_eq!(WorkerCount::<TestRuntime>::get(), 1);
	});
}

#[test]
fn register_worker_insufficient_stake() {
	ExtBuilder::build().execute_with(|| {
		assert_noop!(
			ComputeMarketplace::register_worker(
				RuntimeOrigin::signed(WORKER_A),
				50, // below MinWorkerStake of 100
				default_capabilities(),
			),
			Error::<TestRuntime>::InsufficientStake
		);
	});
}

#[test]
fn register_worker_duplicate_rejected() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		assert_noop!(
			ComputeMarketplace::register_worker(
				RuntimeOrigin::signed(WORKER_A),
				1000,
				default_capabilities(),
			),
			Error::<TestRuntime>::AlreadyRegistered
		);
	});
}

#[test]
fn deregister_worker_works() {
	ExtBuilder::build().execute_with(|| {
		let balance_before = Balances::free_balance(WORKER_A);
		register_worker(WORKER_A);
		assert_eq!(Balances::reserved_balance(WORKER_A), 1000);

		assert_ok!(ComputeMarketplace::deregister_worker(RuntimeOrigin::signed(WORKER_A)));

		assert!(!Workers::<TestRuntime>::contains_key(WORKER_A));
		assert_eq!(WorkerCount::<TestRuntime>::get(), 0);
		assert_eq!(Balances::free_balance(WORKER_A), balance_before);
		assert_eq!(Balances::reserved_balance(WORKER_A), 0);
	});
}

#[test]
fn deregister_worker_with_active_jobs_rejected() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));

		assert_noop!(
			ComputeMarketplace::deregister_worker(RuntimeOrigin::signed(WORKER_A)),
			Error::<TestRuntime>::HasActiveJobs
		);
	});
}

#[test]
fn update_capabilities_works() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);

		let new_caps = gpu_capabilities();
		assert_ok!(ComputeMarketplace::update_capabilities(
			RuntimeOrigin::signed(WORKER_A),
			new_caps,
		));

		let profile = Workers::<TestRuntime>::get(WORKER_A).unwrap();
		assert_eq!(profile.capabilities.gpu, GpuClass::Compute);
		assert_eq!(profile.capabilities.cpu_cores, 16);
	});
}

// ─── Job Submission Tests ─────────────────────────────────

#[test]
fn submit_job_works() {
	ExtBuilder::build().execute_with(|| {
		let balance_before = Balances::free_balance(REQUESTER);
		let job_id = submit_default_job();

		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.requester, REQUESTER);
		assert_eq!(job.status, JobStatus::Open);
		assert_eq!(job.budget, 5000);
		assert_eq!(job.spec_hash, test_spec_hash());
		assert_eq!(Escrows::<TestRuntime>::get(job_id), 5000);
		assert_eq!(Balances::free_balance(REQUESTER), balance_before - 5000);
	});
}

#[test]
fn submit_job_zero_budget_rejected() {
	ExtBuilder::build().execute_with(|| {
		assert_noop!(
			ComputeMarketplace::submit_job(
				RuntimeOrigin::signed(REQUESTER),
				test_spec_hash(),
				test_uri(),
				0,
				100,
				default_requirements(),
			),
			Error::<TestRuntime>::InvalidBudget
		);
	});
}

#[test]
fn submit_job_zero_spec_hash_rejected() {
	ExtBuilder::build().execute_with(|| {
		assert_noop!(
			ComputeMarketplace::submit_job(
				RuntimeOrigin::signed(REQUESTER),
				H256::zero(),
				test_uri(),
				5000,
				100,
				default_requirements(),
			),
			Error::<TestRuntime>::InvalidSpecHash
		);
	});
}

#[test]
fn submit_job_empty_uri_rejected() {
	ExtBuilder::build().execute_with(|| {
		assert_noop!(
			ComputeMarketplace::submit_job(
				RuntimeOrigin::signed(REQUESTER),
				test_spec_hash(),
				vec![],
				5000,
				100,
				default_requirements(),
			),
			Error::<TestRuntime>::InvalidUri
		);
	});
}

#[test]
fn cancel_job_works() {
	ExtBuilder::build().execute_with(|| {
		let balance_before = Balances::free_balance(REQUESTER);
		let job_id = submit_default_job();
		assert_eq!(Balances::free_balance(REQUESTER), balance_before - 5000);

		assert_ok!(ComputeMarketplace::cancel_job(RuntimeOrigin::signed(REQUESTER), job_id));

		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Cancelled);
		assert_eq!(Escrows::<TestRuntime>::get(job_id), 0);
		assert_eq!(Balances::free_balance(REQUESTER), balance_before);
	});
}

#[test]
fn cancel_job_not_requester_rejected() {
	ExtBuilder::build().execute_with(|| {
		let job_id = submit_default_job();
		assert_noop!(
			ComputeMarketplace::cancel_job(RuntimeOrigin::signed(WORKER_A), job_id),
			Error::<TestRuntime>::NotRequester
		);
	});
}

#[test]
fn cancel_assigned_job_rejected() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));

		assert_noop!(
			ComputeMarketplace::cancel_job(RuntimeOrigin::signed(REQUESTER), job_id),
			Error::<TestRuntime>::InvalidJobStatus
		);
	});
}

// ─── Job Acceptance Tests ─────────────────────────────────

#[test]
fn accept_job_works() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		let job_id = submit_default_job();

		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));

		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Assigned);
		assert_eq!(job.worker, Some(WORKER_A));

		let profile = Workers::<TestRuntime>::get(WORKER_A).unwrap();
		assert_eq!(profile.active_jobs, 1);
	});
}

#[test]
fn accept_job_insufficient_capabilities_rejected() {
	ExtBuilder::build().execute_with(|| {
		// Register with weak capabilities
		assert_ok!(ComputeMarketplace::register_worker(
			RuntimeOrigin::signed(WORKER_A),
			1000,
			weak_capabilities(),
		));

		let job_id = submit_default_job(); // requires 4 CPU, 8GB RAM

		assert_noop!(
			ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id),
			Error::<TestRuntime>::InsufficientCapabilities
		);
	});
}

#[test]
fn accept_job_gpu_requirement_enforced() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A); // No GPU
		register_gpu_worker(WORKER_B); // Has Compute GPU

		// Submit a GPU job
		let job_id = NextJobId::<TestRuntime>::get();
		assert_ok!(ComputeMarketplace::submit_job(
			RuntimeOrigin::signed(REQUESTER),
			test_spec_hash(),
			test_uri(),
			5000,
			100,
			gpu_requirements(),
		));

		// Worker without GPU can't accept
		assert_noop!(
			ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id),
			Error::<TestRuntime>::InsufficientCapabilities
		);

		// Worker with GPU can accept
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_B), job_id));
	});
}

#[test]
fn accept_own_job_rejected() {
	ExtBuilder::build().execute_with(|| {
		register_worker(REQUESTER);
		let job_id = submit_default_job();

		assert_noop!(
			ComputeMarketplace::accept_job(RuntimeOrigin::signed(REQUESTER), job_id),
			Error::<TestRuntime>::CannotAcceptOwnJob
		);
	});
}

#[test]
fn accept_job_at_max_capacity_rejected() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A); // max_concurrent_jobs = 1

		let job1 = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job1));

		let job2 = submit_default_job();
		assert_noop!(
			ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job2),
			Error::<TestRuntime>::AtMaxCapacity
		);
	});
}

// ─── Result Submission Tests ──────────────────────────────

#[test]
fn submit_result_works() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));

		assert_ok!(ComputeMarketplace::submit_result(
			RuntimeOrigin::signed(WORKER_A),
			job_id,
			test_result_hash(),
			test_result_uri(),
		));

		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Submitted);
		assert_eq!(job.result_hash, Some(test_result_hash()));
		assert!(job.challenge_end.is_some());
	});
}

#[test]
fn submit_result_wrong_worker_rejected() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		register_worker(WORKER_B);
		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));

		assert_noop!(
			ComputeMarketplace::submit_result(
				RuntimeOrigin::signed(WORKER_B),
				job_id,
				test_result_hash(),
				test_result_uri(),
			),
			Error::<TestRuntime>::NotAssignedWorker
		);
	});
}

// ─── Happy Path: Full Lifecycle ───────────────────────────

#[test]
fn full_lifecycle_unchallenged() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		let worker_balance = Balances::free_balance(WORKER_A);
		let requester_balance = Balances::free_balance(REQUESTER);

		// 1. Submit job
		let job_id = submit_default_job();
		assert_eq!(Balances::free_balance(REQUESTER), requester_balance - 5000);

		// 2. Accept job
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));

		// 3. Submit result
		assert_ok!(ComputeMarketplace::submit_result(
			RuntimeOrigin::signed(WORKER_A),
			job_id,
			test_result_hash(),
			test_result_uri(),
		));

		// 4. Advance past challenge window (10 blocks)
		run_to_block(15);

		// 5. Job should be auto-finalized by on_initialize
		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Completed);

		// 6. Verify payment: 90% to worker (protocol fee = 10%)
		let expected_payout = 4500u128; // 5000 * 90%
		// worker_balance was captured after register (stake already reserved)
		// so worker gets: worker_balance + payout
		assert_eq!(
			Balances::free_balance(WORKER_A),
			worker_balance + expected_payout
		);

		// 7. Worker profile updated
		let profile = Workers::<TestRuntime>::get(WORKER_A).unwrap();
		assert_eq!(profile.active_jobs, 0);
		assert_eq!(profile.completed_jobs, 1);
	});
}

#[test]
fn full_lifecycle_manual_finalize() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));
		assert_ok!(ComputeMarketplace::submit_result(
			RuntimeOrigin::signed(WORKER_A),
			job_id,
			test_result_hash(),
			test_result_uri(),
		));

		// Can't finalize during challenge window
		assert_noop!(
			ComputeMarketplace::finalize_job(RuntimeOrigin::signed(REQUESTER), job_id),
			Error::<TestRuntime>::ChallengeWindowOpen
		);

		// Advance past window
		System::set_block_number(15);

		// Now can finalize
		assert_ok!(ComputeMarketplace::finalize_job(RuntimeOrigin::signed(REQUESTER), job_id));

		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Completed);
	});
}

// ─── Challenge Tests ──────────────────────────────────────

#[test]
fn challenge_works() {
	ExtBuilder::build().execute_with(|| {
		// Need enough workers for committee (3 required)
		register_worker(WORKER_A);
		register_worker(WORKER_B);
		register_worker(WORKER_C);
		register_worker(WORKER_D);

		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));
		assert_ok!(ComputeMarketplace::submit_result(
			RuntimeOrigin::signed(WORKER_A),
			job_id,
			test_result_hash(),
			test_result_uri(),
		));

		// Challenge
		let challenger_balance = Balances::free_balance(CHALLENGER);
		assert_ok!(ComputeMarketplace::challenge(
			RuntimeOrigin::signed(CHALLENGER),
			job_id,
			Some(H256::from_low_u64_be(999)), // different hash
		));

		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Challenged);

		let challenge = Challenges::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(challenge.challenger, CHALLENGER);
		assert_eq!(challenge.bond, 50);
		assert_eq!(challenge.committee.len(), 3);

		// Bond reserved
		assert_eq!(Balances::reserved_balance(CHALLENGER), 50);
	});
}

#[test]
fn challenge_self_rejected() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));
		assert_ok!(ComputeMarketplace::submit_result(
			RuntimeOrigin::signed(WORKER_A),
			job_id,
			test_result_hash(),
			test_result_uri(),
		));

		assert_noop!(
			ComputeMarketplace::challenge(RuntimeOrigin::signed(WORKER_A), job_id, None),
			Error::<TestRuntime>::CannotChallengeSelf
		);
	});
}

#[test]
fn challenge_upheld_worker_slashed() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		register_worker(WORKER_B);
		register_worker(WORKER_C);
		register_worker(WORKER_D);

		let requester_balance_before = Balances::free_balance(REQUESTER);
		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));
		assert_ok!(ComputeMarketplace::submit_result(
			RuntimeOrigin::signed(WORKER_A),
			job_id,
			test_result_hash(),
			test_result_uri(),
		));

		assert_ok!(ComputeMarketplace::challenge(
			RuntimeOrigin::signed(CHALLENGER),
			job_id,
			None,
		));

		let challenge = Challenges::<TestRuntime>::get(job_id).unwrap();
		let committee = challenge.committee.clone();

		// All committee members vote against worker
		for member in committee.iter() {
			assert_ok!(ComputeMarketplace::vote_challenge(
				RuntimeOrigin::signed(*member),
				job_id,
				ChallengeVote::WorkerIncorrect,
			));
		}

		// Job should be auto-finalized after all votes
		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Slashed);

		// Requester should be refunded
		assert_eq!(Balances::free_balance(REQUESTER), requester_balance_before);

		// Worker reputation damaged
		let profile = Workers::<TestRuntime>::get(WORKER_A).unwrap();
		assert_eq!(profile.failed_jobs, 1);
		assert_eq!(profile.active_jobs, 0);
	});
}

#[test]
fn challenge_failed_challenger_loses_bond() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		register_worker(WORKER_B);
		register_worker(WORKER_C);
		register_worker(WORKER_D);

		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));
		assert_ok!(ComputeMarketplace::submit_result(
			RuntimeOrigin::signed(WORKER_A),
			job_id,
			test_result_hash(),
			test_result_uri(),
		));

		let challenger_balance_before = Balances::free_balance(CHALLENGER);
		assert_ok!(ComputeMarketplace::challenge(
			RuntimeOrigin::signed(CHALLENGER),
			job_id,
			None,
		));

		let challenge = Challenges::<TestRuntime>::get(job_id).unwrap();
		let committee = challenge.committee.clone();

		// All committee members vote FOR worker
		for member in committee.iter() {
			assert_ok!(ComputeMarketplace::vote_challenge(
				RuntimeOrigin::signed(*member),
				job_id,
				ChallengeVote::WorkerCorrect,
			));
		}

		// Job completed despite challenge
		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Completed);

		// Challenger lost their bond (50)
		assert!(Balances::free_balance(CHALLENGER) < challenger_balance_before);
	});
}

// ─── Expiry Tests ─────────────────────────────────────────

#[test]
fn job_expires_when_unaccepted() {
	ExtBuilder::build().execute_with(|| {
		let requester_balance = Balances::free_balance(REQUESTER);
		let job_id = submit_default_job();

		// Advance past deadline (100 blocks)
		run_to_block(105);

		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Expired);

		// Requester refunded
		assert_eq!(Balances::free_balance(REQUESTER), requester_balance);
	});
}

#[test]
fn job_expires_when_worker_doesnt_deliver() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		let requester_balance = Balances::free_balance(REQUESTER);
		let job_id = submit_default_job();
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));

		// Advance past deadline without submitting result
		run_to_block(105);

		let job = Jobs::<TestRuntime>::get(job_id).unwrap();
		assert_eq!(job.status, JobStatus::Expired);

		// Requester refunded
		assert_eq!(Balances::free_balance(REQUESTER), requester_balance);

		// Worker reputation damaged
		let profile = Workers::<TestRuntime>::get(WORKER_A).unwrap();
		assert_eq!(profile.failed_jobs, 1);
		assert_eq!(profile.active_jobs, 0);
	});
}

// ─── Heartbeat Tests ──────────────────────────────────────

#[test]
fn heartbeat_works() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		heartbeat(WORKER_A);

		let uptime = Heartbeats::<TestRuntime>::get(WORKER_A);
		assert_eq!(uptime.heartbeat_count, 1);
		assert_eq!(uptime.last_heartbeat, 1);
	});
}

#[test]
fn heartbeat_unregistered_rejected() {
	ExtBuilder::build().execute_with(|| {
		assert_noop!(
			ComputeMarketplace::submit_heartbeat(RuntimeOrigin::signed(WORKER_A)),
			Error::<TestRuntime>::NotRegistered
		);
	});
}

#[test]
fn stale_heartbeat_blocks_job_acceptance() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		heartbeat(WORKER_A);

		// Advance well past heartbeat interval (1000 blocks)
		System::set_block_number(1500);

		let job_id = submit_default_job();
		assert_noop!(
			ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id),
			Error::<TestRuntime>::WorkerNotAvailable
		);

		// Fresh heartbeat fixes it
		heartbeat(WORKER_A);
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));
	});
}

// ─── Sudo Configuration Tests ─────────────────────────────

#[test]
fn sudo_set_challenge_period() {
	ExtBuilder::build().execute_with(|| {
		assert_ok!(ComputeMarketplace::set_challenge_period(RuntimeOrigin::root(), 500));
		assert_eq!(ChallengePeriodBlocks::<TestRuntime>::get(), 500);
	});
}

#[test]
fn sudo_set_protocol_fee() {
	ExtBuilder::build().execute_with(|| {
		assert_ok!(ComputeMarketplace::set_protocol_fee(
			RuntimeOrigin::root(),
			Perbill::from_percent(5),
		));
		assert_eq!(ProtocolFee::<TestRuntime>::get(), Perbill::from_percent(5));
	});
}

#[test]
fn sudo_requires_root() {
	ExtBuilder::build().execute_with(|| {
		assert_noop!(
			ComputeMarketplace::set_challenge_period(RuntimeOrigin::signed(WORKER_A), 500),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

// ─── Availability Pool Tests ──────────────────────────────

#[test]
fn fund_availability_pool_works() {
	ExtBuilder::build().execute_with(|| {
		assert_ok!(ComputeMarketplace::fund_availability_pool(
			RuntimeOrigin::signed(FUNDER),
			10_000,
		));
		assert_eq!(AvailabilityPool::<TestRuntime>::get(), 10_000);
	});
}

// ─── Capability Matching Tests ────────────────────────────

#[test]
fn requirements_satisfied_by_works() {
	let caps = Capabilities {
		cpu_cores: 8,
		memory_mb: 16384,
		gpu: GpuClass::Compute,
		storage_mb: 100_000,
	};

	// Satisfied
	let reqs = JobRequirements {
		min_cpu_cores: 4,
		min_memory_mb: 8192,
		gpu_required: GpuClass::None,
		min_storage_mb: 50_000,
	};
	assert!(reqs.satisfied_by(&caps));

	// GPU requirement met
	let gpu_reqs = JobRequirements {
		min_cpu_cores: 4,
		min_memory_mb: 8192,
		gpu_required: GpuClass::Compute,
		min_storage_mb: 50_000,
	};
	assert!(gpu_reqs.satisfied_by(&caps));

	// GPU requirement NOT met (needs HighEnd, has Compute)
	let high_gpu_reqs = JobRequirements {
		min_cpu_cores: 4,
		min_memory_mb: 8192,
		gpu_required: GpuClass::HighEnd,
		min_storage_mb: 50_000,
	};
	assert!(!high_gpu_reqs.satisfied_by(&caps));

	// CPU requirement NOT met
	let high_cpu_reqs = JobRequirements {
		min_cpu_cores: 16,
		min_memory_mb: 8192,
		gpu_required: GpuClass::None,
		min_storage_mb: 50_000,
	};
	assert!(!high_cpu_reqs.satisfied_by(&caps));
}

// ─── Protocol Fee Tests ───────────────────────────────────

#[test]
fn protocol_fee_applied_correctly() {
	ExtBuilder::build().execute_with(|| {
		// Set 5% protocol fee
		assert_ok!(ComputeMarketplace::set_protocol_fee(
			RuntimeOrigin::root(),
			Perbill::from_percent(5),
		));

		register_worker(WORKER_A);
		let worker_balance = Balances::free_balance(WORKER_A);
		let job_id = submit_default_job(); // budget = 5000

		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id));
		assert_ok!(ComputeMarketplace::submit_result(
			RuntimeOrigin::signed(WORKER_A),
			job_id,
			test_result_hash(),
			test_result_uri(),
		));

		// Auto-finalize
		run_to_block(15);

		// Worker gets 95% = 4750
		// worker_balance captured after register (stake already reserved)
		assert_eq!(
			Balances::free_balance(WORKER_A),
			worker_balance + 4750
		);
	});
}

// ─── Edge Cases ───────────────────────────────────────────

#[test]
fn multiple_jobs_track_correctly() {
	ExtBuilder::build().execute_with(|| {
		register_worker(WORKER_A);
		register_worker(WORKER_B);

		let job1 = submit_default_job();
		let job2 = submit_default_job();

		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job1));
		assert_ok!(ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_B), job2));

		// Both assigned
		assert_eq!(Jobs::<TestRuntime>::get(job1).unwrap().status, JobStatus::Assigned);
		assert_eq!(Jobs::<TestRuntime>::get(job2).unwrap().status, JobStatus::Assigned);
		assert_eq!(Jobs::<TestRuntime>::get(job1).unwrap().worker, Some(WORKER_A));
		assert_eq!(Jobs::<TestRuntime>::get(job2).unwrap().worker, Some(WORKER_B));
	});
}

#[test]
fn not_registered_cannot_accept() {
	ExtBuilder::build().execute_with(|| {
		let job_id = submit_default_job();
		assert_noop!(
			ComputeMarketplace::accept_job(RuntimeOrigin::signed(WORKER_A), job_id),
			Error::<TestRuntime>::NotRegistered
		);
	});
}
