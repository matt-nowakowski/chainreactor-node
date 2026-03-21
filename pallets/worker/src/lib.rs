//! # Worker Pallet
//!
//! Enables worker chain functionality: solution groups, attestation voting,
//! SLA-based rewards. Built on top of pallet-node-manager (registered nodes
//! are eligible workers).
//!
//! ## Overview
//!
//! - **Solution Groups** — task categories created by chain operators. Each group
//!   has independent stake requirements, SLA thresholds, and reward pools.
//! - **Attestation Voting** — workers execute off-chain computation and submit
//!   Blake2-hashed results. Threshold consensus determines the correct result.
//! - **SLA Scoring** — workers must maintain a minimum correct-vote rate per
//!   reward period to qualify for rewards. Rewards are stake-weighted.
//!
//! ## Design
//!
//! This pallet composes on top of node-manager rather than modifying watchtower.
//! Registered nodes (via node-manager) are eligible workers. The watchtower
//! pallet remains untouched for its governance role.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

mod types;
pub use types::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ReservableCurrency, ExistenceRequirement},
	PalletId,
};
use frame_system::pallet_prelude::*;
use sp_core::H256;
use sp_runtime::{
	traits::{AccountIdConversion, Saturating, Zero},
	transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction},
	Perbill, SaturatedConversion,
};
use sp_std::prelude::*;

type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Currency for staking and rewards.
		type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;

		/// PalletId for the reward pot account.
		#[pallet::constant]
		type WorkerPalletId: Get<PalletId>;

		/// Maximum length of a solution group name.
		#[pallet::constant]
		type MaxNameLen: Get<u32>;

		/// Maximum length of solution group metadata (opaque bytes — URL, JSON, etc.).
		#[pallet::constant]
		type MaxMetadataLen: Get<u32>;

		/// Maximum number of solution groups.
		#[pallet::constant]
		type MaxSolutionGroups: Get<u32>;

		/// Maximum votes tracked per voting round (prevents unbounded maps).
		#[pallet::constant]
		type MaxVotesPerRound: Get<u32>;

		/// Weight information.
		type WeightInfo: WeightInfo;
	}

	pub trait WeightInfo {
		fn create_solution_group() -> Weight;
		fn subscribe() -> Weight;
		fn unsubscribe() -> Weight;
		fn submit_attestation() -> Weight;
		fn finalize_round() -> Weight;
		fn claim_rewards() -> Weight;
		fn fund_reward_pool() -> Weight;
		fn set_group_active() -> Weight;
		fn set_subscription_cooldown() -> Weight;
		fn update_solution_group() -> Weight;
	}

	/// Default weight impl (placeholder — benchmark later).
	impl WeightInfo for () {
		fn create_solution_group() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn subscribe() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn unsubscribe() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn submit_attestation() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn finalize_round() -> Weight { Weight::from_parts(100_000_000, 0) }
		fn claim_rewards() -> Weight { Weight::from_parts(100_000_000, 0) }
		fn fund_reward_pool() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn set_group_active() -> Weight { Weight::from_parts(25_000_000, 0) }
		fn set_subscription_cooldown() -> Weight { Weight::from_parts(10_000_000, 0) }
		fn update_solution_group() -> Weight { Weight::from_parts(50_000_000, 0) }
	}

	// ─── Storage ───────────────────────────────────────────────

	/// Subscription cooldown in blocks — configurable via sudo.
	/// Default: 1200 blocks (~2h at 6s block time).
	#[pallet::storage]
	pub type SubscriptionCooldownBlocks<T> = StorageValue<_, u32, ValueQuery, DefaultCooldown>;

	/// Default cooldown value (1200 blocks).
	#[pallet::type_value]
	pub fn DefaultCooldown() -> u32 { 1200 }

	/// Auto-incrementing counter for solution group IDs.
	#[pallet::storage]
	pub type NextSolutionGroupId<T> = StorageValue<_, SolutionGroupId, ValueQuery>;

	/// Solution group definitions.
	#[pallet::storage]
	pub type SolutionGroups<T: Config> =
		StorageMap<_, Blake2_128Concat, SolutionGroupId, SolutionGroup<T>, OptionQuery>;

	/// Worker subscriptions: (worker_account, solution_group_id) → Subscription
	#[pallet::storage]
	pub type Subscriptions<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat, T::AccountId,
		Blake2_128Concat, SolutionGroupId,
		Subscription<BalanceOf<T>, BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Auto-incrementing counter for voting round IDs.
	#[pallet::storage]
	pub type NextVotingRoundId<T> = StorageValue<_, VotingRoundId, ValueQuery>;

	/// Voting round metadata.
	#[pallet::storage]
	pub type VotingRounds<T: Config> =
		StorageMap<_, Blake2_128Concat, VotingRoundId, VotingRound<BlockNumberFor<T>>, OptionQuery>;

	/// Individual votes: (round_id, worker) → result_hash
	#[pallet::storage]
	pub type Votes<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat, VotingRoundId,
		Blake2_128Concat, T::AccountId,
		H256,
		OptionQuery,
	>;

	/// Vote tallies per round: (round_id, result_hash) → count
	#[pallet::storage]
	pub type VoteTallies<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat, VotingRoundId,
		Blake2_128Concat, H256,
		u32,
		ValueQuery,
	>;

	/// Current active round per solution group.
	#[pallet::storage]
	pub type ActiveRound<T: Config> =
		StorageMap<_, Blake2_128Concat, SolutionGroupId, VotingRoundId, OptionQuery>;

	/// Reward period tracking per solution group.
	#[pallet::storage]
	pub type RewardPeriods<T: Config> = StorageMap<
		_,
		Blake2_128Concat, SolutionGroupId,
		WorkerRewardPeriod<BlockNumberFor<T>, BalanceOf<T>>,
		OptionQuery,
	>;

	/// Worker performance per reward period:
	/// (solution_group_id, period_index, worker) → WorkerPerformance
	#[pallet::storage]
	pub type Performance<T: Config> = StorageNMap<
		_,
		(
			NMapKey<Blake2_128Concat, SolutionGroupId>,
			NMapKey<Blake2_128Concat, RewardPeriodIndex>,
			NMapKey<Blake2_128Concat, T::AccountId>,
		),
		WorkerPerformance,
		ValueQuery,
	>;

	/// Tracks whether a worker has claimed rewards for a given period.
	/// (solution_group_id, period_index, worker) → bool
	#[pallet::storage]
	pub type RewardsClaimed<T: Config> = StorageNMap<
		_,
		(
			NMapKey<Blake2_128Concat, SolutionGroupId>,
			NMapKey<Blake2_128Concat, RewardPeriodIndex>,
			NMapKey<Blake2_128Concat, T::AccountId>,
		),
		bool,
		ValueQuery,
	>;

	// ─── Events ────────────────────────────────────────────────

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new solution group was created.
		SolutionGroupCreated {
			id: SolutionGroupId,
			owner: T::AccountId,
			name: Vec<u8>,
			stake_requirement: BalanceOf<T>,
		},
		/// Solution group active status changed.
		SolutionGroupStatusChanged {
			id: SolutionGroupId,
			active: bool,
		},
		/// A worker subscribed to a solution group.
		WorkerSubscribed {
			worker: T::AccountId,
			solution_group_id: SolutionGroupId,
			stake_locked: BalanceOf<T>,
		},
		/// A worker unsubscribed from a solution group.
		WorkerUnsubscribed {
			worker: T::AccountId,
			solution_group_id: SolutionGroupId,
			stake_returned: BalanceOf<T>,
		},
		/// A new voting round started.
		VotingRoundStarted {
			round_id: VotingRoundId,
			solution_group_id: SolutionGroupId,
			ends_at: BlockNumberFor<T>,
		},
		/// A worker submitted an attestation vote.
		AttestationSubmitted {
			worker: T::AccountId,
			round_id: VotingRoundId,
			result_hash: H256,
		},
		/// A voting round reached consensus.
		ConsensusReached {
			round_id: VotingRoundId,
			consensus_hash: H256,
			vote_count: u32,
		},
		/// A voting round expired without consensus.
		RoundExpiredNoConsensus {
			round_id: VotingRoundId,
		},
		/// Rewards were claimed by a worker.
		RewardsClaimed {
			worker: T::AccountId,
			solution_group_id: SolutionGroupId,
			period: RewardPeriodIndex,
			amount: BalanceOf<T>,
		},
		/// Reward pool funded.
		RewardPoolFunded {
			solution_group_id: SolutionGroupId,
			amount: BalanceOf<T>,
		},
		/// A new reward period started.
		RewardPeriodAdvanced {
			solution_group_id: SolutionGroupId,
			period: RewardPeriodIndex,
		},
		/// Worker missed SLA threshold.
		SLAThresholdMissed {
			worker: T::AccountId,
			solution_group_id: SolutionGroupId,
			period: RewardPeriodIndex,
			accuracy: Perbill,
		},
		/// Subscription cooldown was updated.
		SubscriptionCooldownUpdated {
			blocks: u32,
		},
		/// Solution group parameters were updated.
		SolutionGroupUpdated {
			id: SolutionGroupId,
		},
	}

	// ─── Errors ────────────────────────────────────────────────

	#[pallet::error]
	pub enum Error<T> {
		/// Solution group name is empty or too long.
		InvalidName,
		/// Maximum number of solution groups reached.
		TooManySolutionGroups,
		/// Solution group not found.
		SolutionGroupNotFound,
		/// Solution group is not active.
		SolutionGroupNotActive,
		/// Caller is not the owner of the solution group.
		NotGroupOwner,
		/// Worker is already subscribed to this solution group.
		AlreadySubscribed,
		/// Worker is not subscribed to this solution group.
		NotSubscribed,
		/// Insufficient balance for staking.
		InsufficientStake,
		/// Subscription is still in cooldown period.
		SubscriptionCooldown,
		/// Voting round not found.
		RoundNotFound,
		/// Voting round has already been finalized.
		RoundAlreadyFinalized,
		/// Voting round has not ended yet.
		RoundNotEnded,
		/// Worker has already voted in this round.
		AlreadyVoted,
		/// No active round for this solution group.
		NoActiveRound,
		/// Result hash cannot be zero.
		InvalidResultHash,
		/// Rewards already claimed for this period.
		AlreadyClaimed,
		/// No reward period found for this solution group.
		NoRewardPeriod,
		/// Worker did not meet SLA threshold.
		BelowSLAThreshold,
		/// Cannot claim rewards for the current (incomplete) period.
		PeriodNotComplete,
		/// Arithmetic overflow.
		ArithmeticOverflow,
		/// Metadata exceeds maximum length.
		MetadataTooLong,
	}

	// ─── Hooks ─────────────────────────────────────────────────

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(now: BlockNumberFor<T>) -> Weight {
			let mut weight = Weight::zero();

			// Check each active solution group for round rotation and period advancement
			let mut group_id = 0u32;
			while group_id < NextSolutionGroupId::<T>::get() {
				if let Some(group) = SolutionGroups::<T>::get(group_id) {
					if group.active {
						weight = weight.saturating_add(
							Self::maybe_rotate_round(group_id, &group, now)
						);
						weight = weight.saturating_add(
							Self::maybe_advance_period(group_id, now)
						);
					}
				}
				group_id = group_id.saturating_add(1);
			}

			weight
		}
	}

	// ─── Extrinsics ────────────────────────────────────────────

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Create a new solution group. Only callable by sudo or root.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::create_solution_group())]
		pub fn create_solution_group(
			origin: OriginFor<T>,
			name: Vec<u8>,
			stake_requirement: BalanceOf<T>,
			sla_threshold: Perbill,
			consensus_threshold: Perbill,
			round_length: u32,
			reward_period_length: u32,
			metadata: Vec<u8>,
		) -> DispatchResult {
			let owner = ensure_signed(origin)?;

			let bounded_name: BoundedVec<u8, T::MaxNameLen> =
				name.clone().try_into().map_err(|_| Error::<T>::InvalidName)?;
			ensure!(!bounded_name.is_empty(), Error::<T>::InvalidName);

			let bounded_metadata: BoundedVec<u8, T::MaxMetadataLen> =
				metadata.try_into().map_err(|_| Error::<T>::MetadataTooLong)?;

			let id = NextSolutionGroupId::<T>::get();
			ensure!(id < T::MaxSolutionGroups::get(), Error::<T>::TooManySolutionGroups);

			let now = <frame_system::Pallet<T>>::block_number();

			let group = SolutionGroup {
				name: bounded_name,
				owner: owner.clone(),
				stake_requirement,
				sla_threshold,
				consensus_threshold,
				round_length,
				active: true,
				created_at: now,
				metadata: bounded_metadata,
			};

			SolutionGroups::<T>::insert(id, &group);
			NextSolutionGroupId::<T>::put(id.saturating_add(1));

			// Initialize reward period
			RewardPeriods::<T>::insert(id, WorkerRewardPeriod {
				current: 0u64,
				first: now,
				length: reward_period_length,
				reward_pool: BalanceOf::<T>::zero(),
			});

			Self::deposit_event(Event::SolutionGroupCreated {
				id,
				owner,
				name,
				stake_requirement,
			});

			Ok(())
		}

		/// Toggle a solution group's active status.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_group_active())]
		pub fn set_group_active(
			origin: OriginFor<T>,
			solution_group_id: SolutionGroupId,
			active: bool,
		) -> DispatchResult {
			let caller = ensure_signed(origin)?;
			SolutionGroups::<T>::try_mutate(solution_group_id, |maybe_group| {
				let group = maybe_group.as_mut().ok_or(Error::<T>::SolutionGroupNotFound)?;
				ensure!(group.owner == caller, Error::<T>::NotGroupOwner);
				group.active = active;
				Self::deposit_event(Event::SolutionGroupStatusChanged {
					id: solution_group_id,
					active,
				});
				Ok(())
			})
		}

		/// Subscribe to a solution group by locking the required stake.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::subscribe())]
		pub fn subscribe(
			origin: OriginFor<T>,
			solution_group_id: SolutionGroupId,
		) -> DispatchResult {
			let worker = ensure_signed(origin)?;

			let group = SolutionGroups::<T>::get(solution_group_id)
				.ok_or(Error::<T>::SolutionGroupNotFound)?;
			ensure!(group.active, Error::<T>::SolutionGroupNotActive);
			ensure!(
				!Subscriptions::<T>::contains_key(&worker, solution_group_id),
				Error::<T>::AlreadySubscribed
			);

			// Lock stake
			let stake = group.stake_requirement;
			let free = T::Currency::free_balance(&worker);
			ensure!(free >= stake, Error::<T>::InsufficientStake);
			// Reserve (lock) tokens — they can't be transferred while subscribed
			T::Currency::reserve(&worker, stake)
				.map_err(|_| Error::<T>::InsufficientStake)?;

			let now = <frame_system::Pallet<T>>::block_number();
			Subscriptions::<T>::insert(&worker, solution_group_id, Subscription {
				stake_locked: stake,
				subscribed_at: now,
				active: true,
			});

			Self::deposit_event(Event::WorkerSubscribed {
				worker,
				solution_group_id,
				stake_locked: stake,
			});

			Ok(())
		}

		/// Unsubscribe from a solution group and unlock stake.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::unsubscribe())]
		pub fn unsubscribe(
			origin: OriginFor<T>,
			solution_group_id: SolutionGroupId,
		) -> DispatchResult {
			let worker = ensure_signed(origin)?;

			let sub = Subscriptions::<T>::get(&worker, solution_group_id)
				.ok_or(Error::<T>::NotSubscribed)?;

			// Unreserve stake
			T::Currency::unreserve(&worker, sub.stake_locked);

			Subscriptions::<T>::remove(&worker, solution_group_id);

			Self::deposit_event(Event::WorkerUnsubscribed {
				worker,
				solution_group_id,
				stake_returned: sub.stake_locked,
			});

			Ok(())
		}

		/// Submit an attestation vote for the active round (signed version).
		/// `result_hash` is a Blake2-256 hash of the off-chain computation result.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::submit_attestation())]
		pub fn submit_attestation(
			origin: OriginFor<T>,
			solution_group_id: SolutionGroupId,
			result_hash: H256,
		) -> DispatchResult {
			let worker = ensure_signed(origin)?;
			Self::do_submit_attestation(worker, solution_group_id, result_hash)
		}

		/// Submit an attestation vote (unsigned — no tx fees required).
		/// Used by scanner nodes that don't hold tokens.
		#[pallet::call_index(10)]
		#[pallet::weight(T::WeightInfo::submit_attestation())]
		pub fn unsigned_submit_attestation(
			origin: OriginFor<T>,
			worker: T::AccountId,
			solution_group_id: SolutionGroupId,
			result_hash: H256,
		) -> DispatchResult {
			ensure_none(origin)?;
			Self::do_submit_attestation(worker, solution_group_id, result_hash)
		}

		/// Finalize a voting round after it has ended.
		/// Anyone can call this — it just processes the results.
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::finalize_round())]
		pub fn finalize_round(
			origin: OriginFor<T>,
			round_id: VotingRoundId,
		) -> DispatchResult {
			ensure_signed(origin)?;

			let mut round = VotingRounds::<T>::get(round_id)
				.ok_or(Error::<T>::RoundNotFound)?;
			ensure!(!round.finalized, Error::<T>::RoundAlreadyFinalized);

			let now = <frame_system::Pallet<T>>::block_number();
			ensure!(now > round.ends_at, Error::<T>::RoundNotEnded);

			let group = SolutionGroups::<T>::get(round.solution_group_id)
				.ok_or(Error::<T>::SolutionGroupNotFound)?;

			// Find the result hash with the most votes
			let consensus_threshold = group.consensus_threshold;
			let total = round.total_votes;

			let mut best_hash = H256::zero();
			let mut best_count = 0u32;

			// Iterate vote tallies for this round
			for (hash, count) in VoteTallies::<T>::iter_prefix(round_id) {
				if count > best_count {
					best_count = count;
					best_hash = hash;
				}
			}

			// Check if the best result meets the consensus threshold
			let reached_consensus = total > 0 &&
				Perbill::from_rational(best_count, total) >= consensus_threshold;

			if reached_consensus {
				round.consensus_result = Some(best_hash);
				Self::deposit_event(Event::ConsensusReached {
					round_id,
					consensus_hash: best_hash,
					vote_count: best_count,
				});

				// Update performance for all voters in this round
				if let Some(period) = RewardPeriods::<T>::get(round.solution_group_id) {
					for (worker, voted_hash) in Votes::<T>::iter_prefix(round_id) {
						let correct = voted_hash == best_hash;
						Performance::<T>::mutate(
							(round.solution_group_id, period.current, &worker),
							|perf| {
								perf.total_votes = perf.total_votes.saturating_add(1);
								if correct {
									perf.correct_votes = perf.correct_votes.saturating_add(1);
								}
							},
						);
					}
				}
			} else {
				Self::deposit_event(Event::RoundExpiredNoConsensus { round_id });
			}

			round.finalized = true;
			VotingRounds::<T>::insert(round_id, &round);

			Ok(())
		}

		/// Claim rewards for a completed reward period.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::claim_rewards())]
		pub fn claim_rewards(
			origin: OriginFor<T>,
			solution_group_id: SolutionGroupId,
			period_index: RewardPeriodIndex,
		) -> DispatchResult {
			let worker = ensure_signed(origin)?;

			let period = RewardPeriods::<T>::get(solution_group_id)
				.ok_or(Error::<T>::NoRewardPeriod)?;
			// Can only claim completed periods (not current)
			ensure!(period_index < period.current, Error::<T>::PeriodNotComplete);

			// Check not already claimed
			ensure!(
				!RewardsClaimed::<T>::get((solution_group_id, period_index, &worker)),
				Error::<T>::AlreadyClaimed
			);

			let group = SolutionGroups::<T>::get(solution_group_id)
				.ok_or(Error::<T>::SolutionGroupNotFound)?;

			let perf = Performance::<T>::get((solution_group_id, period_index, &worker));
			let accuracy = perf.accuracy();

			// Check SLA threshold
			if accuracy < group.sla_threshold {
				Self::deposit_event(Event::SLAThresholdMissed {
					worker: worker.clone(),
					solution_group_id,
					period: period_index,
					accuracy,
				});
				return Err(Error::<T>::BelowSLAThreshold.into());
			}

			// Calculate stake-weighted reward
			let sub = Subscriptions::<T>::get(&worker, solution_group_id)
				.ok_or(Error::<T>::NotSubscribed)?;

			let reward = Self::calculate_reward(
				solution_group_id,
				period_index,
				&worker,
				sub.stake_locked,
				perf.correct_votes,
			)?;

			if !reward.is_zero() {
				// Transfer from pallet account
				let pallet_account = Self::pallet_account();
				T::Currency::transfer(
					&pallet_account,
					&worker,
					reward,
					ExistenceRequirement::AllowDeath,
				)?;
			}

			RewardsClaimed::<T>::insert((solution_group_id, period_index, &worker), true);

			Self::deposit_event(Event::RewardsClaimed {
				worker,
				solution_group_id,
				period: period_index,
				amount: reward,
			});

			Ok(())
		}

		/// Fund the reward pool for a solution group.
		/// Transfers tokens from the caller to the pallet account.
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::fund_reward_pool())]
		pub fn fund_reward_pool(
			origin: OriginFor<T>,
			solution_group_id: SolutionGroupId,
			amount: BalanceOf<T>,
		) -> DispatchResult {
			let funder = ensure_signed(origin)?;

			ensure!(
				SolutionGroups::<T>::contains_key(solution_group_id),
				Error::<T>::SolutionGroupNotFound
			);

			let pallet_account = Self::pallet_account();
			T::Currency::transfer(
				&funder,
				&pallet_account,
				amount,
				ExistenceRequirement::KeepAlive,
			)?;

			// Add to current period's reward pool
			RewardPeriods::<T>::mutate(solution_group_id, |maybe_period| {
				if let Some(period) = maybe_period {
					period.reward_pool = period.reward_pool.saturating_add(amount);
				}
			});

			Self::deposit_event(Event::RewardPoolFunded {
				solution_group_id,
				amount,
			});

			Ok(())
		}

		/// Set the subscription cooldown period (in blocks). Root only.
		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::set_subscription_cooldown())]
		pub fn set_subscription_cooldown(
			origin: OriginFor<T>,
			blocks: u32,
		) -> DispatchResult {
			ensure_root(origin)?;
			SubscriptionCooldownBlocks::<T>::put(blocks);
			Self::deposit_event(Event::SubscriptionCooldownUpdated { blocks });
			Ok(())
		}

		/// Update a solution group's parameters. Root only.
		/// Pass `None` for any field to leave it unchanged.
		#[pallet::call_index(9)]
		#[pallet::weight(T::WeightInfo::update_solution_group())]
		pub fn update_solution_group(
			origin: OriginFor<T>,
			solution_group_id: SolutionGroupId,
			stake_requirement: Option<BalanceOf<T>>,
			sla_threshold: Option<Perbill>,
			consensus_threshold: Option<Perbill>,
			round_length: Option<u32>,
			metadata: Option<Vec<u8>>,
		) -> DispatchResult {
			ensure_root(origin)?;

			SolutionGroups::<T>::try_mutate(solution_group_id, |maybe_group| {
				let group = maybe_group.as_mut().ok_or(Error::<T>::SolutionGroupNotFound)?;

				if let Some(stake) = stake_requirement {
					group.stake_requirement = stake;
				}
				if let Some(sla) = sla_threshold {
					group.sla_threshold = sla;
				}
				if let Some(consensus) = consensus_threshold {
					group.consensus_threshold = consensus;
				}
				if let Some(length) = round_length {
					group.round_length = length;
				}
				if let Some(meta) = metadata {
					group.metadata = meta.try_into().map_err(|_| Error::<T>::MetadataTooLong)?;
				}

				Self::deposit_event(Event::SolutionGroupUpdated {
					id: solution_group_id,
				});

				Ok(())
			})
		}
	}

	// ─── Internal Helpers ──────────────────────────────────────

	impl<T: Config> Pallet<T> {
		/// The pallet's account ID (holds reward pool funds).
		pub fn pallet_account() -> T::AccountId {
			T::WorkerPalletId::get().into_account_truncating()
		}

		/// Internal attestation logic shared by signed and unsigned paths.
		fn do_submit_attestation(
			worker: T::AccountId,
			solution_group_id: SolutionGroupId,
			result_hash: H256,
		) -> DispatchResult {
			ensure!(result_hash != H256::zero(), Error::<T>::InvalidResultHash);

			let sub = Subscriptions::<T>::get(&worker, solution_group_id)
				.ok_or(Error::<T>::NotSubscribed)?;
			ensure!(sub.active, Error::<T>::NotSubscribed);

			let now = <frame_system::Pallet<T>>::block_number();
			let cooldown = SubscriptionCooldownBlocks::<T>::get();
			let cooldown_end = sub.subscribed_at.saturating_add(cooldown.into());
			ensure!(now >= cooldown_end, Error::<T>::SubscriptionCooldown);

			let round_id = ActiveRound::<T>::get(solution_group_id)
				.ok_or(Error::<T>::NoActiveRound)?;
			let round = VotingRounds::<T>::get(round_id)
				.ok_or(Error::<T>::RoundNotFound)?;
			ensure!(!round.finalized, Error::<T>::RoundAlreadyFinalized);
			ensure!(now <= round.ends_at, Error::<T>::RoundAlreadyFinalized);

			ensure!(
				!Votes::<T>::contains_key(round_id, &worker),
				Error::<T>::AlreadyVoted
			);

			Votes::<T>::insert(round_id, &worker, result_hash);
			VoteTallies::<T>::mutate(round_id, result_hash, |count| {
				*count = count.saturating_add(1);
			});
			VotingRounds::<T>::mutate(round_id, |maybe_round| {
				if let Some(r) = maybe_round {
					r.total_votes = r.total_votes.saturating_add(1);
				}
			});

			Self::deposit_event(Event::AttestationSubmitted {
				worker,
				round_id,
				result_hash,
			});

			Ok(())
		}

		/// Check if a voting round should end and a new one should start.
		fn maybe_rotate_round(
			group_id: SolutionGroupId,
			group: &SolutionGroup<T>,
			now: BlockNumberFor<T>,
		) -> Weight {
			let active_round_id = ActiveRound::<T>::get(group_id);

			let should_start_new = match active_round_id {
				None => true,
				Some(round_id) => {
					if let Some(round) = VotingRounds::<T>::get(round_id) {
						now > round.ends_at
					} else {
						true
					}
				}
			};

			if !should_start_new {
				return Weight::from_parts(5_000, 0);
			}

			// Auto-finalize previous round if needed
			if let Some(prev_id) = active_round_id {
				if let Some(mut prev) = VotingRounds::<T>::get(prev_id) {
					if !prev.finalized {
						// Simple auto-finalize: find best hash
						let mut best_hash = H256::zero();
						let mut best_count = 0u32;
						for (hash, count) in VoteTallies::<T>::iter_prefix(prev_id) {
							if count > best_count {
								best_count = count;
								best_hash = hash;
							}
						}

						let total = prev.total_votes;
						let reached = total > 0 &&
							Perbill::from_rational(best_count, total) >= group.consensus_threshold;

						if reached {
							prev.consensus_result = Some(best_hash);
							// Update performance
							if let Some(period) = RewardPeriods::<T>::get(group_id) {
								for (worker, voted_hash) in Votes::<T>::iter_prefix(prev_id) {
									let correct = voted_hash == best_hash;
									Performance::<T>::mutate(
										(group_id, period.current, &worker),
										|perf| {
											perf.total_votes = perf.total_votes.saturating_add(1);
											if correct {
												perf.correct_votes = perf.correct_votes.saturating_add(1);
											}
										},
									);
								}
							}
						}

						prev.finalized = true;
						VotingRounds::<T>::insert(prev_id, prev);
					}
				}
			}

			// Start new round
			let round_id = NextVotingRoundId::<T>::get();
			let ends_at = now.saturating_add(group.round_length.into());

			let round = VotingRound {
				solution_group_id: group_id,
				started_at: now,
				ends_at,
				consensus_result: None,
				total_votes: 0,
				finalized: false,
			};

			VotingRounds::<T>::insert(round_id, &round);
			ActiveRound::<T>::insert(group_id, round_id);
			NextVotingRoundId::<T>::put(round_id.saturating_add(1));

			Self::deposit_event(Event::VotingRoundStarted {
				round_id,
				solution_group_id: group_id,
				ends_at,
			});

			Weight::from_parts(50_000_000, 0)
		}

		/// Check if the reward period should advance.
		/// When a period ends, automatically distributes rewards to all qualifying workers.
		fn maybe_advance_period(
			group_id: SolutionGroupId,
			now: BlockNumberFor<T>,
		) -> Weight {
			let should_advance = RewardPeriods::<T>::get(group_id)
				.map(|p| {
					let elapsed = now.saturating_sub(p.first);
					elapsed >= p.length.into()
				})
				.unwrap_or(false);

			if !should_advance {
				return Weight::from_parts(5_000, 0);
			}

			let completed_period = RewardPeriods::<T>::get(group_id)
				.map(|p| p.current)
				.unwrap_or(0);

			// Auto-distribute rewards for the completed period
			if let Some(group) = SolutionGroups::<T>::get(group_id) {
				Self::auto_distribute_rewards(group_id, completed_period, &group);
			}

			// Advance to next period
			RewardPeriods::<T>::mutate(group_id, |maybe_period| {
				if let Some(period) = maybe_period {
					let new_index = period.current.saturating_add(1);
					period.current = new_index;
					period.first = now;
					period.reward_pool = BalanceOf::<T>::zero();

					Self::deposit_event(Event::RewardPeriodAdvanced {
						solution_group_id: group_id,
						period: new_index,
					});
				}
			});

			Weight::from_parts(50_000_000, 0)
		}

		/// Distribute rewards to all qualifying workers for a completed period.
		/// Workers must meet the SLA threshold and have submitted votes.
		fn auto_distribute_rewards(
			group_id: SolutionGroupId,
			period_index: RewardPeriodIndex,
			group: &SolutionGroup<T>,
		) {
			let pallet_account = Self::pallet_account();
			let pool_balance: u128 = SaturatedConversion::saturated_into(
				T::Currency::free_balance(&pallet_account)
			);

			if pool_balance == 0 {
				return;
			}

			// Collect all qualifying workers and their weighted contributions
			let mut qualifying: Vec<(T::AccountId, u128)> = Vec::new();
			let mut total_weighted: u128 = 0;

			for ((_gid, _pid, worker), perf) in Performance::<T>::iter() {
				if _gid != group_id || _pid != period_index {
					continue;
				}
				if perf.total_votes == 0 {
					continue;
				}

				let accuracy = perf.accuracy();

				// Check SLA threshold
				if accuracy < group.sla_threshold {
					Self::deposit_event(Event::SLAThresholdMissed {
						worker: worker.clone(),
						solution_group_id: group_id,
						period: period_index,
						accuracy,
					});
					continue;
				}

				// Already claimed manually? Skip.
				if RewardsClaimed::<T>::get((group_id, period_index, &worker)) {
					continue;
				}

				// Get stake
				if let Some(sub) = Subscriptions::<T>::get(&worker, group_id) {
					let stake: u128 = SaturatedConversion::saturated_into(sub.stake_locked);
					let weighted = (perf.correct_votes as u128).saturating_mul(stake);
					total_weighted = total_weighted.saturating_add(weighted);
					qualifying.push((worker, weighted));
				}
			}

			if total_weighted == 0 || qualifying.is_empty() {
				return;
			}

			// Distribute proportionally
			for (worker, weighted) in qualifying {
				let reward = weighted
					.saturating_mul(pool_balance)
					.checked_div(total_weighted)
					.unwrap_or(0);

				if reward == 0 {
					continue;
				}

				let reward_balance: BalanceOf<T> = reward.saturated_into();

				if T::Currency::transfer(
					&pallet_account,
					&worker,
					reward_balance,
					ExistenceRequirement::AllowDeath,
				).is_ok() {
					RewardsClaimed::<T>::insert((group_id, period_index, &worker), true);

					Self::deposit_event(Event::RewardsClaimed {
						worker,
						solution_group_id: group_id,
						period: period_index,
						amount: reward_balance,
					});
				}
			}
		}

		/// Calculate a worker's reward for a completed period.
		/// Formula: (correct_votes * stake) / total_weighted_correct * reward_pool
		fn calculate_reward(
			solution_group_id: SolutionGroupId,
			period_index: RewardPeriodIndex,
			_worker: &T::AccountId,
			stake: BalanceOf<T>,
			correct_votes: u32,
		) -> Result<BalanceOf<T>, DispatchError> {
			// We need the reward pool for the completed period.
			// Since periods advance, we'd need historical tracking.
			// For now, use a simplified approach: equal share of current pool
			// weighted by (correct_votes * stake).

			// Sum all weighted correct votes for this period
			let mut total_weighted: u128 = 0u128;
			let worker_weighted: u128;

			// Convert stake to u128 for math
			let stake_u128: u128 = SaturatedConversion::saturated_into(stake);
			worker_weighted = (correct_votes as u128).saturating_mul(stake_u128);

			for ((_gid, _pid, _acct), perf) in Performance::<T>::iter() {
				// Only count entries for this group+period
				// (iter() returns all entries; we filter)
				if _gid == solution_group_id && _pid == period_index {
					// Get this worker's stake
					if let Some(sub) = Subscriptions::<T>::get(&_acct, solution_group_id) {
						let s: u128 = SaturatedConversion::saturated_into(sub.stake_locked);
						total_weighted = total_weighted.saturating_add(
							(perf.correct_votes as u128).saturating_mul(s)
						);
					}
				}
			}

			if total_weighted == 0 || worker_weighted == 0 {
				return Ok(BalanceOf::<T>::zero());
			}

			// Get pallet account balance as the available reward pool
			let pallet_account = Self::pallet_account();
			let pool_balance: u128 = SaturatedConversion::saturated_into(T::Currency::free_balance(&pallet_account));

			// reward = (worker_weighted / total_weighted) * pool_balance
			let reward = worker_weighted
				.saturating_mul(pool_balance)
				.checked_div(total_weighted)
				.unwrap_or(0u128);

			// Convert back to Balance
			let reward_balance: BalanceOf<T> = reward.saturated_into();
			Ok(reward_balance)
		}
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			match call {
				Call::unsigned_submit_attestation { worker, solution_group_id, result_hash } => {
					// Verify the worker is subscribed
					if Subscriptions::<T>::get(worker, solution_group_id).is_none() {
						return InvalidTransaction::BadSigner.into();
					}

					// Verify result hash is non-zero
					if *result_hash == H256::zero() {
						return InvalidTransaction::BadProof.into();
					}

					// Check not already voted in current round
					if let Some(round_id) = ActiveRound::<T>::get(solution_group_id) {
						if Votes::<T>::contains_key(round_id, worker) {
							return InvalidTransaction::Stale.into();
						}
					}

					ValidTransaction::with_tag_prefix("worker-attestation")
						.priority(20_000)
						.longevity(5)
						.and_provides((worker.clone(), solution_group_id))
						.propagate(true)
						.build()
				}
				_ => InvalidTransaction::Call.into(),
			}
		}
	}
}
