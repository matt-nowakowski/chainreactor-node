use crate::mock::*;
use crate::*;
use frame_support::{assert_noop, assert_ok};
use sp_core::H256;
use sp_runtime::Perbill;

fn hash(n: u8) -> H256 {
	H256::from([n; 32])
}

fn create_default_group() -> SolutionGroupId {
	assert_ok!(Worker::create_solution_group(
		RuntimeOrigin::signed(GROUP_OWNER),
		b"Test Group".to_vec(),
		1000, // stake requirement
		Perbill::from_percent(50), // sla threshold
		Perbill::from_percent(66), // consensus threshold (2/3)
		10, // round length (10 blocks)
		100, // reward period length
		vec![], // metadata
	));
	0 // first group is always id 0
}

// ─── Solution Group Tests ──────────────────────────────────

#[test]
fn create_solution_group_works() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		let group = SolutionGroups::<TestRuntime>::get(id).unwrap();
		assert_eq!(group.owner, GROUP_OWNER);
		assert_eq!(group.stake_requirement, 1000);
		assert_eq!(group.round_length, 10);
		assert!(group.active);
		assert_eq!(NextSolutionGroupId::<TestRuntime>::get(), 1);

		// Reward period initialized
		let period = RewardPeriods::<TestRuntime>::get(id).unwrap();
		assert_eq!(period.current, 0);
		assert_eq!(period.length, 100);
	});
}

#[test]
fn create_group_with_empty_name_fails() {
	ExtBuilder::build().execute_with(|| {
		assert_noop!(
			Worker::create_solution_group(
				RuntimeOrigin::signed(GROUP_OWNER),
				vec![],
				1000,
				Perbill::from_percent(50),
				Perbill::from_percent(66),
				10,
				100,
				vec![],
			),
			Error::<TestRuntime>::InvalidName
		);
	});
}

#[test]
fn set_group_active_works() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		assert_ok!(Worker::set_group_active(
			RuntimeOrigin::signed(GROUP_OWNER),
			id,
			false,
		));

		let group = SolutionGroups::<TestRuntime>::get(id).unwrap();
		assert!(!group.active);
	});
}

#[test]
fn set_group_active_fails_for_non_owner() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		assert_noop!(
			Worker::set_group_active(RuntimeOrigin::signed(ALICE), id, false),
			Error::<TestRuntime>::NotGroupOwner
		);
	});
}

// ─── Subscription Tests ────────────────────────────────────

#[test]
fn subscribe_works() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));

		let sub = Subscriptions::<TestRuntime>::get(ALICE, id).unwrap();
		assert_eq!(sub.stake_locked, 1000);
		assert!(sub.active);

		// Stake should be reserved
		assert_eq!(Balances::reserved_balance(ALICE), 1000);
		assert_eq!(Balances::free_balance(ALICE), INITIAL_BALANCE - 1000);
	});
}

#[test]
fn subscribe_fails_with_insufficient_balance() {
	ExtBuilder::build().execute_with(|| {
		// Create group with very high stake
		assert_ok!(Worker::create_solution_group(
			RuntimeOrigin::signed(GROUP_OWNER),
			b"Expensive".to_vec(),
			INITIAL_BALANCE + 1, // more than anyone has
			Perbill::from_percent(50),
			Perbill::from_percent(66),
			10,
			100,
			vec![],
		));

		assert_noop!(
			Worker::subscribe(RuntimeOrigin::signed(ALICE), 0),
			Error::<TestRuntime>::InsufficientStake
		);
	});
}

#[test]
fn subscribe_twice_fails() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));

		assert_noop!(
			Worker::subscribe(RuntimeOrigin::signed(ALICE), id),
			Error::<TestRuntime>::AlreadySubscribed
		);
	});
}

#[test]
fn unsubscribe_returns_stake() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));
		assert_eq!(Balances::reserved_balance(ALICE), 1000);

		assert_ok!(Worker::unsubscribe(RuntimeOrigin::signed(ALICE), id));

		assert_eq!(Balances::reserved_balance(ALICE), 0);
		assert_eq!(Balances::free_balance(ALICE), INITIAL_BALANCE);
		assert!(Subscriptions::<TestRuntime>::get(ALICE, id).is_none());
	});
}

#[test]
fn subscribe_to_inactive_group_fails() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::set_group_active(
			RuntimeOrigin::signed(GROUP_OWNER), id, false,
		));

		assert_noop!(
			Worker::subscribe(RuntimeOrigin::signed(ALICE), id),
			Error::<TestRuntime>::SolutionGroupNotActive
		);
	});
}

// ─── Voting Round Tests ────────────────────────────────────

#[test]
fn voting_round_auto_starts_on_initialize() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		// First on_initialize should start a round
		Worker::on_initialize(System::block_number());

		let round_id = ActiveRound::<TestRuntime>::get(id).expect("round should exist");
		let round = VotingRounds::<TestRuntime>::get(round_id).unwrap();
		assert_eq!(round.solution_group_id, id);
		assert!(!round.finalized);
		assert_eq!(round.total_votes, 0);
	});
}

#[test]
fn submit_attestation_works() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));

		// Start a round
		Worker::on_initialize(System::block_number());

		let round_id = ActiveRound::<TestRuntime>::get(id).unwrap();

		assert_ok!(Worker::submit_attestation(
			RuntimeOrigin::signed(ALICE),
			id,
			hash(1),
		));

		let vote = Votes::<TestRuntime>::get(round_id, ALICE).unwrap();
		assert_eq!(vote, hash(1));

		let round = VotingRounds::<TestRuntime>::get(round_id).unwrap();
		assert_eq!(round.total_votes, 1);

		assert_eq!(VoteTallies::<TestRuntime>::get(round_id, hash(1)), 1);
	});
}

#[test]
fn submit_zero_hash_fails() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));
		Worker::on_initialize(System::block_number());

		assert_noop!(
			Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, H256::zero()),
			Error::<TestRuntime>::InvalidResultHash
		);
	});
}

#[test]
fn double_vote_fails() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));
		Worker::on_initialize(System::block_number());

		assert_ok!(Worker::submit_attestation(
			RuntimeOrigin::signed(ALICE), id, hash(1),
		));

		assert_noop!(
			Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(2)),
			Error::<TestRuntime>::AlreadyVoted
		);
	});
}

#[test]
fn non_subscriber_cannot_vote() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		Worker::on_initialize(System::block_number());

		assert_noop!(
			Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(1)),
			Error::<TestRuntime>::NotSubscribed
		);
	});
}

// ─── Consensus Tests ───────────────────────────────────────

#[test]
fn finalize_round_reaches_consensus() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		// Subscribe 3 workers
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(BOB), id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(CHARLIE), id));

		Worker::on_initialize(System::block_number());
		let round_id = ActiveRound::<TestRuntime>::get(id).unwrap();

		// All 3 agree on the same hash (100% > 66% threshold)
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(1)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), id, hash(1)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(CHARLIE), id, hash(1)));

		// Advance past round end
		run_to_block(12);

		assert_ok!(Worker::finalize_round(RuntimeOrigin::signed(ALICE), round_id));

		let round = VotingRounds::<TestRuntime>::get(round_id).unwrap();
		assert!(round.finalized);
		assert_eq!(round.consensus_result, Some(hash(1)));

		// Consensus result stored on the round
		assert_eq!(round.consensus_result, Some(hash(1)));
		assert_eq!(round.total_votes, 3);
	});
}

#[test]
fn finalize_round_no_consensus_when_split() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(BOB), id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(CHARLIE), id));

		Worker::on_initialize(System::block_number());
		let round_id = ActiveRound::<TestRuntime>::get(id).unwrap();

		// All vote differently — no hash reaches 66%
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(1)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), id, hash(2)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(CHARLIE), id, hash(3)));

		run_to_block(12);

		assert_ok!(Worker::finalize_round(RuntimeOrigin::signed(ALICE), round_id));

		let round = VotingRounds::<TestRuntime>::get(round_id).unwrap();
		assert!(round.finalized);
		assert_eq!(round.consensus_result, None);

		// No consensus result on the round
		assert_eq!(round.consensus_result, None);
	});
}

#[test]
fn finalize_before_round_ends_fails() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		Worker::on_initialize(System::block_number());
		let round_id = ActiveRound::<TestRuntime>::get(id).unwrap();

		assert_noop!(
			Worker::finalize_round(RuntimeOrigin::signed(ALICE), round_id),
			Error::<TestRuntime>::RoundNotEnded
		);
	});
}

// ─── Noor-Scanner Scenario Test ────────────────────────────

/// Simulates the noor-scanner use case:
/// Multiple scanner nodes monitor the same URL, produce VFP composite
/// hashes, and submit them. Consensus confirms page integrity.
#[test]
fn noor_scanner_full_flow() {
	ExtBuilder::build().execute_with(|| {
		// Chain operator creates a solution group for monitoring "https://example.com"
		// target_hash would be SHA256("https://example.com") in production
		assert_ok!(Worker::create_solution_group(
			RuntimeOrigin::signed(GROUP_OWNER),
			b"example.com monitor".to_vec(),
			500, // stake
			Perbill::from_percent(75), // 75% SLA
			Perbill::from_percent(66), // 2/3 consensus
			10, // 10 block rounds
			50, // 50 block reward periods
			b"https://example.com".to_vec(), // metadata: target URL
		));
		let group_id = 0;

		// Metadata (target URL) is stored and queryable
		let group = SolutionGroups::<TestRuntime>::get(group_id).unwrap();
		assert_eq!(group.metadata.to_vec(), b"https://example.com".to_vec());

		// 4 noor scanner nodes subscribe as workers
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), group_id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(BOB), group_id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(CHARLIE), group_id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(DAVE), group_id));

		// Round 1 starts
		Worker::on_initialize(System::block_number());
		let round_1 = ActiveRound::<TestRuntime>::get(group_id).unwrap();

		// All 4 scanners produce the same VFP composite hash (page is clean)
		// In production: hash = SHA256(visual_hash + dom_hash + network_hash + assets_hash)
		let clean_page_hash = hash(42);
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), group_id, clean_page_hash));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), group_id, clean_page_hash));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(CHARLIE), group_id, clean_page_hash));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(DAVE), group_id, clean_page_hash));

		// Advance past round end, finalize
		run_to_block(12);
		assert_ok!(Worker::finalize_round(RuntimeOrigin::signed(ALICE), round_1));

		// Consensus reached — all agreed on the same hash
		let round = VotingRounds::<TestRuntime>::get(round_1).unwrap();
		assert_eq!(round.consensus_result, Some(clean_page_hash));

		// Round consensus queryable — this is what a frontend would read
		assert_eq!(round.total_votes, 4);

		// All workers got correct votes recorded
		let period = RewardPeriods::<TestRuntime>::get(group_id).unwrap();
		let alice_perf = Performance::<TestRuntime>::get((group_id, period.current, ALICE));
		assert_eq!(alice_perf.correct_votes, 1);
		assert_eq!(alice_perf.total_votes, 1);
		assert_eq!(alice_perf.accuracy(), Perbill::from_percent(100));

		// Round 2 — page gets tampered, 3 scanners see it, 1 still has old cache
		// run_to_block triggers auto-finalize of round 1 and starts round 2
		run_to_block(13);
		let round_2 = ActiveRound::<TestRuntime>::get(group_id).unwrap();
		assert!(round_2 > round_1); // new round

		let tampered_hash = hash(99);
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), group_id, tampered_hash));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), group_id, tampered_hash));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(CHARLIE), group_id, tampered_hash));
		// Dave submits old hash (stale cache)
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(DAVE), group_id, clean_page_hash));

		// Advance past round end — auto-finalize via on_initialize
		run_to_block(25);

		// 3/4 = 75% > 66% threshold — consensus on tampered hash
		let round = VotingRounds::<TestRuntime>::get(round_2).unwrap();
		assert_eq!(round.consensus_result, Some(tampered_hash));

		// Dave's vote was wrong — recorded in performance
		let dave_perf = Performance::<TestRuntime>::get((group_id, period.current, DAVE));
		assert_eq!(dave_perf.correct_votes, 1); // only round 1 was correct
		assert_eq!(dave_perf.total_votes, 2);   // voted in both rounds
		assert_eq!(dave_perf.accuracy(), Perbill::from_percent(50));

		// Alice was correct both times
		let alice_perf = Performance::<TestRuntime>::get((group_id, period.current, ALICE));
		assert_eq!(alice_perf.correct_votes, 2);
		assert_eq!(alice_perf.total_votes, 2);
		assert_eq!(alice_perf.accuracy(), Perbill::from_percent(100));
	});
}

// ─── Reward Tests ──────────────────────────────────────────

#[test]
fn fund_reward_pool_works() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		assert_ok!(Worker::fund_reward_pool(
			RuntimeOrigin::signed(GROUP_OWNER),
			id,
			50_000,
		));

		let period = RewardPeriods::<TestRuntime>::get(id).unwrap();
		assert_eq!(period.reward_pool, 50_000);

		// Pallet account should hold the funds
		let pallet_account = Worker::pallet_account();
		assert_eq!(Balances::free_balance(pallet_account), 50_000);
	});
}

#[test]
fn claim_rewards_before_period_ends_fails() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));

		// Period 0 is current — can't claim it
		assert_noop!(
			Worker::claim_rewards(RuntimeOrigin::signed(ALICE), id, 0),
			Error::<TestRuntime>::PeriodNotComplete
		);
	});
}

#[test]
fn claim_rewards_below_sla_fails() {
	ExtBuilder::build().execute_with(|| {
		// Group with 75% SLA threshold, short reward period
		// 3 workers so consensus can be reached with 2/3 votes
		assert_ok!(Worker::create_solution_group(
			RuntimeOrigin::signed(GROUP_OWNER),
			b"Strict SLA".to_vec(),
			500,
			Perbill::from_percent(75),
			Perbill::from_percent(51),
			5, // 5 block rounds
			20, // 20 block reward period
			vec![],
		));
		let id = 0;

		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(BOB), id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(CHARLIE), id));

		// Fund the pool
		assert_ok!(Worker::fund_reward_pool(RuntimeOrigin::signed(GROUP_OWNER), id, 10_000));

		// Round 1 (blocks 1-6): all agree — Alice correct
		Worker::on_initialize(1);
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(1)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), id, hash(1)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(CHARLIE), id, hash(1)));

		// Round 2 (auto-starts ~block 7, ends ~12): Alice disagrees
		// run_to_block triggers auto-finalize of round 1 and starts round 2
		run_to_block(8);
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(99)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), id, hash(2)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(CHARLIE), id, hash(2)));

		// Round 3 (auto-starts ~block 13, ends ~18): Alice wrong again
		run_to_block(14);
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(98)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), id, hash(3)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(CHARLIE), id, hash(3)));

		// Advance past reward period end (period length=20, started at block 1)
		// Also auto-finalizes round 3
		run_to_block(25);

		let period = RewardPeriods::<TestRuntime>::get(id).unwrap();
		assert!(period.current > 0, "reward period should have advanced");

		// Alice accuracy: 1 correct / 3 total = 33% < 75% SLA
		let alice_perf = Performance::<TestRuntime>::get((id, 0u64, ALICE));
		assert_eq!(alice_perf.correct_votes, 1);
		assert_eq!(alice_perf.total_votes, 3);
		assert!(alice_perf.accuracy() < Perbill::from_percent(75));

		assert_noop!(
			Worker::claim_rewards(RuntimeOrigin::signed(ALICE), id, 0),
			Error::<TestRuntime>::BelowSLAThreshold
		);
	});
}

// ─── Auto-Rotation Tests ───────────────────────────────────

#[test]
fn round_auto_rotates_after_expiry() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();

		// Start round 0
		Worker::on_initialize(1);
		let round_0 = ActiveRound::<TestRuntime>::get(id).unwrap();

		// Advance past round end (10 blocks)
		run_to_block(12);
		// on_initialize should auto-rotate
		Worker::on_initialize(12);

		let round_1 = ActiveRound::<TestRuntime>::get(id).unwrap();
		assert!(round_1 > round_0);

		// Old round should be auto-finalized
		let old = VotingRounds::<TestRuntime>::get(round_0).unwrap();
		assert!(old.finalized);
	});
}

#[test]
fn auto_finalize_with_votes_stores_consensus() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(BOB), id));

		Worker::on_initialize(1);
		let round_0 = ActiveRound::<TestRuntime>::get(id).unwrap();

		// Both agree
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(5)));
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), id, hash(5)));

		// Auto-rotate triggers auto-finalize
		run_to_block(12);
		Worker::on_initialize(12);

		// Consensus should be stored even though we didn't call finalize_round
		let old_round = VotingRounds::<TestRuntime>::get(round_0).unwrap();
		assert!(old_round.finalized);
		assert_eq!(old_round.consensus_result, Some(hash(5)));
		assert_eq!(old_round.total_votes, 2);
	});
}

// ─── Edge Cases ────────────────────────────────────────────

#[test]
fn inactive_group_does_not_rotate_rounds() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::set_group_active(RuntimeOrigin::signed(GROUP_OWNER), id, false));

		Worker::on_initialize(1);

		// No round should have started
		assert!(ActiveRound::<TestRuntime>::get(id).is_none());
	});
}

#[test]
fn vote_after_round_ends_fails() {
	ExtBuilder::build().execute_with(|| {
		let id = create_default_group();
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), id));

		Worker::on_initialize(1);

		// Advance past round end
		run_to_block(12);

		assert_noop!(
			Worker::submit_attestation(RuntimeOrigin::signed(ALICE), id, hash(1)),
			Error::<TestRuntime>::RoundAlreadyFinalized
		);
	});
}

#[test]
fn multiple_solution_groups_independent() {
	ExtBuilder::build().execute_with(|| {
		// Group 0
		assert_ok!(Worker::create_solution_group(
			RuntimeOrigin::signed(GROUP_OWNER),
			b"Group A".to_vec(),
			100, Perbill::from_percent(50), Perbill::from_percent(51),
			10, 100, vec![],
		));
		// Group 1
		assert_ok!(Worker::create_solution_group(
			RuntimeOrigin::signed(GROUP_OWNER),
			b"Group B".to_vec(),
			200, Perbill::from_percent(50), Perbill::from_percent(51),
			20, 100, vec![],
		));

		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(ALICE), 0));
		assert_ok!(Worker::subscribe(RuntimeOrigin::signed(BOB), 1));

		Worker::on_initialize(1);

		// Alice votes in group 0
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(ALICE), 0, hash(1)));
		// Bob votes in group 1
		assert_ok!(Worker::submit_attestation(RuntimeOrigin::signed(BOB), 1, hash(2)));

		// Alice can't vote in group 1 (not subscribed)
		assert_noop!(
			Worker::submit_attestation(RuntimeOrigin::signed(ALICE), 1, hash(1)),
			Error::<TestRuntime>::NotSubscribed
		);

		// Different stake amounts reserved
		assert_eq!(Balances::reserved_balance(ALICE), 100);
		assert_eq!(Balances::reserved_balance(BOB), 200);
	});
}
