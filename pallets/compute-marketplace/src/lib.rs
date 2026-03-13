//! # Compute Marketplace Pallet
//!
//! Standalone decentralized compute marketplace with optimistic execution.
//! Workers register with hardware capabilities, requesters submit jobs with
//! requirements, and the pallet matches them. Results are accepted optimistically
//! after a challenge window — no upfront re-execution required.
//!
//! ## Overview
//!
//! - **Worker Registration** — nodes register with stake + hardware capabilities
//!   (CPU, RAM, GPU class, storage). Capabilities are on-chain for job matching.
//! - **Job Lifecycle** — Open → Assigned → Submitted → Completed (happy path).
//!   Challenge window between Submitted and Completed allows fraud disputes.
//! - **Optimistic Execution** — results accepted if unchallenged. On challenge,
//!   a randomly selected committee votes. Slashing for dishonest workers.
//! - **Heartbeat & Availability** — workers submit periodic heartbeats to prove
//!   liveness. Offline workers can't accept jobs.
//! - **Built-in Execution** — the node's off-chain worker detects assigned jobs
//!   and executes them natively on the host machine (command, Docker, WASM).
//!
//! ## Standalone Design
//!
//! This pallet is fully self-contained. It does NOT depend on pallet-node-manager
//! or any other Chainreactor pallet. It handles its own worker registration,
//! heartbeats, staking, reputation, and rewards. Include it in any Substrate
//! runtime as a standalone module.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

mod types;
pub use types::*;

#[cfg(feature = "std")]
pub mod engine;

#[cfg(feature = "std")]
pub mod offchain;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use parity_scale_codec::{Decode, Encode};
use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ReservableCurrency, ExistenceRequirement},
	PalletId,
};
use frame_system::pallet_prelude::*;
use sp_core::H256;
use sp_runtime::{
	traits::{AccountIdConversion, Saturating, Zero, Hash},
	transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction},
	Perbill, SaturatedConversion,
};
use sp_std::prelude::*;

/// Key type for the compute marketplace OCW.
/// Workers inject this key via `author_insertKey("cmkt", mnemonic, pubkey)`.
pub const KEY_TYPE: sp_core::crypto::KeyTypeId = sp_core::crypto::KeyTypeId(*b"cmkt");

type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config
		+ frame_system::offchain::SendTransactionTypes<Call<Self>>
	{
		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Currency for staking, escrow, and rewards.
		type Currency: Currency<Self::AccountId> + ReservableCurrency<Self::AccountId>;

		/// PalletId — used to derive the escrow account that holds job payments.
		#[pallet::constant]
		type ComputePalletId: Get<PalletId>;

		/// Maximum length of a URI (spec_uri, result_uri).
		#[pallet::constant]
		type MaxUriLen: Get<u32>;

		/// Maximum number of workers that can register.
		#[pallet::constant]
		type MaxWorkers: Get<u32>;

		/// Maximum number of open jobs at any time.
		#[pallet::constant]
		type MaxJobs: Get<u32>;

		/// Maximum committee size for dispute resolution.
		#[pallet::constant]
		type MaxCommitteeSize: Get<u32>;

		/// Weight information.
		type WeightInfo: WeightInfo;
	}

	pub trait WeightInfo {
		fn register_worker() -> Weight;
		fn deregister_worker() -> Weight;
		fn update_capabilities() -> Weight;
		fn submit_job() -> Weight;
		fn cancel_job() -> Weight;
		fn accept_job() -> Weight;
		fn submit_result() -> Weight;
		fn challenge() -> Weight;
		fn vote_challenge() -> Weight;
		fn finalize_job() -> Weight;
		fn submit_heartbeat() -> Weight;
		fn set_challenge_period() -> Weight;
		fn set_challenge_bond() -> Weight;
		fn set_min_worker_stake() -> Weight;
		fn set_committee_size() -> Weight;
		fn set_protocol_fee() -> Weight;
		fn set_heartbeat_interval() -> Weight;
		fn fund_availability_pool() -> Weight;
	}

	/// Default weight impl (placeholder — benchmark later).
	impl WeightInfo for () {
		fn register_worker() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn deregister_worker() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn update_capabilities() -> Weight { Weight::from_parts(25_000_000, 0) }
		fn submit_job() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn cancel_job() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn accept_job() -> Weight { Weight::from_parts(75_000_000, 0) }
		fn submit_result() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn challenge() -> Weight { Weight::from_parts(100_000_000, 0) }
		fn vote_challenge() -> Weight { Weight::from_parts(50_000_000, 0) }
		fn finalize_job() -> Weight { Weight::from_parts(100_000_000, 0) }
		fn submit_heartbeat() -> Weight { Weight::from_parts(25_000_000, 0) }
		fn set_challenge_period() -> Weight { Weight::from_parts(10_000_000, 0) }
		fn set_challenge_bond() -> Weight { Weight::from_parts(10_000_000, 0) }
		fn set_min_worker_stake() -> Weight { Weight::from_parts(10_000_000, 0) }
		fn set_committee_size() -> Weight { Weight::from_parts(10_000_000, 0) }
		fn set_protocol_fee() -> Weight { Weight::from_parts(10_000_000, 0) }
		fn set_heartbeat_interval() -> Weight { Weight::from_parts(10_000_000, 0) }
		fn fund_availability_pool() -> Weight { Weight::from_parts(50_000_000, 0) }
	}

	// ─── Storage ───────────────────────────────────────────────

	/// Auto-incrementing job ID counter.
	#[pallet::storage]
	pub type NextJobId<T> = StorageValue<_, JobId, ValueQuery>;

	/// Worker profiles: account → WorkerProfile
	#[pallet::storage]
	pub type Workers<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, WorkerProfile<T>, OptionQuery>;

	/// Total number of registered workers (for bounds checking).
	#[pallet::storage]
	pub type WorkerCount<T> = StorageValue<_, u32, ValueQuery>;

	/// Job definitions: job_id → Job
	#[pallet::storage]
	pub type Jobs<T: Config> =
		StorageMap<_, Blake2_128Concat, JobId, Job<T>, OptionQuery>;

	/// Escrow balances: job_id → escrowed amount
	#[pallet::storage]
	pub type Escrows<T: Config> =
		StorageMap<_, Blake2_128Concat, JobId, BalanceOf<T>, ValueQuery>;

	/// Active challenges: job_id → Challenge
	#[pallet::storage]
	pub type Challenges<T: Config> =
		StorageMap<_, Blake2_128Concat, JobId, Challenge<T>, OptionQuery>;

	/// Committee votes: (job_id, voter) → ChallengeVote
	#[pallet::storage]
	pub type CommitteeVotes<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat, JobId,
		Blake2_128Concat, T::AccountId,
		ChallengeVote,
		OptionQuery,
	>;

	/// Worker heartbeat tracking: account → WorkerUptime
	#[pallet::storage]
	pub type Heartbeats<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, WorkerUptime, ValueQuery>;

	// ─── Configuration (sudo-configurable) ─────────────────────

	/// Challenge window in blocks (default: 100 blocks ~10min at 6s).
	#[pallet::storage]
	pub type ChallengePeriodBlocks<T> = StorageValue<_, u32, ValueQuery, DefaultChallengePeriod>;
	#[pallet::type_value]
	pub fn DefaultChallengePeriod() -> u32 { 100 }

	/// Bond required to submit a challenge (default: 100 units).
	#[pallet::storage]
	pub type ChallengeBondAmount<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

	/// Minimum stake to register as a worker (default: 1000 units).
	#[pallet::storage]
	pub type MinWorkerStake<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

	/// Number of committee members for dispute resolution (default: 3).
	#[pallet::storage]
	pub type CommitteeSizeConfig<T> = StorageValue<_, u8, ValueQuery, DefaultCommitteeSize>;
	#[pallet::type_value]
	pub fn DefaultCommitteeSize() -> u8 { 3 }

	/// Protocol fee as Perbill (default: 10%).
	#[pallet::storage]
	pub type ProtocolFee<T> = StorageValue<_, Perbill, ValueQuery, DefaultProtocolFee>;
	#[pallet::type_value]
	pub fn DefaultProtocolFee() -> Perbill { Perbill::from_percent(10) }

	/// Heartbeat interval in blocks — workers must heartbeat within this window (default: 300 ~30min).
	#[pallet::storage]
	pub type HeartbeatInterval<T> = StorageValue<_, u32, ValueQuery, DefaultHeartbeatInterval>;
	#[pallet::type_value]
	pub fn DefaultHeartbeatInterval() -> u32 { 300 }

	/// Availability reward pool balance (funded by chain operator).
	#[pallet::storage]
	pub type AvailabilityPool<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

	/// Slash percentage applied to worker stake on successful challenge (default: 10%).
	#[pallet::storage]
	pub type SlashPercent<T> = StorageValue<_, Perbill, ValueQuery, DefaultSlashPercent>;
	#[pallet::type_value]
	pub fn DefaultSlashPercent() -> Perbill { Perbill::from_percent(10) }

	// ─── Events ────────────────────────────────────────────────

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new worker registered with capabilities.
		WorkerRegistered {
			worker: T::AccountId,
			stake: BalanceOf<T>,
			capabilities: Capabilities,
		},
		/// A worker deregistered and unlocked stake.
		WorkerDeregistered {
			worker: T::AccountId,
			stake_returned: BalanceOf<T>,
		},
		/// A worker updated their capabilities.
		WorkerCapabilitiesUpdated {
			worker: T::AccountId,
			capabilities: Capabilities,
		},
		/// A new job was submitted.
		JobSubmitted {
			job_id: JobId,
			requester: T::AccountId,
			budget: BalanceOf<T>,
			spec_hash: H256,
			requirements: JobRequirements,
		},
		/// A job was cancelled by the requester.
		JobCancelled {
			job_id: JobId,
			requester: T::AccountId,
			refund: BalanceOf<T>,
		},
		/// A worker accepted a job.
		JobAccepted {
			job_id: JobId,
			worker: T::AccountId,
		},
		/// A worker submitted a result (challenge window opens).
		ResultSubmitted {
			job_id: JobId,
			worker: T::AccountId,
			result_hash: H256,
			challenge_end: BlockNumberFor<T>,
		},
		/// A job result was challenged.
		JobChallenged {
			job_id: JobId,
			challenger: T::AccountId,
			bond: BalanceOf<T>,
		},
		/// A committee member voted on a challenge.
		ChallengeVoteSubmitted {
			job_id: JobId,
			voter: T::AccountId,
			vote: ChallengeVote,
		},
		/// A job was finalized (completed successfully).
		JobCompleted {
			job_id: JobId,
			worker: T::AccountId,
			payout: BalanceOf<T>,
			protocol_fee: BalanceOf<T>,
		},
		/// A worker was slashed (challenge upheld).
		WorkerSlashed {
			job_id: JobId,
			worker: T::AccountId,
			slash_amount: BalanceOf<T>,
			challenger_reward: BalanceOf<T>,
		},
		/// A job expired (worker failed to deliver).
		JobExpired {
			job_id: JobId,
			worker: Option<T::AccountId>,
		},
		/// Challenge failed — worker result upheld, challenger loses bond.
		ChallengeFailed {
			job_id: JobId,
			challenger: T::AccountId,
			bond_lost: BalanceOf<T>,
		},
		/// Worker submitted a heartbeat.
		HeartbeatReceived {
			worker: T::AccountId,
			block: BlockNumberFor<T>,
		},
		/// Availability rewards distributed.
		AvailabilityRewardPaid {
			worker: T::AccountId,
			amount: BalanceOf<T>,
		},
		/// Availability pool funded.
		AvailabilityPoolFunded {
			amount: BalanceOf<T>,
		},
		/// Configuration updated.
		ConfigUpdated {
			parameter: Vec<u8>,
		},
	}

	// ─── Errors ────────────────────────────────────────────────

	#[pallet::error]
	pub enum Error<T> {
		/// Worker is already registered.
		AlreadyRegistered,
		/// Worker is not registered.
		NotRegistered,
		/// Insufficient balance for staking.
		InsufficientStake,
		/// Worker has active jobs — cannot deregister.
		HasActiveJobs,
		/// Maximum number of workers reached.
		TooManyWorkers,
		/// Job not found.
		JobNotFound,
		/// Job is not in the expected status.
		InvalidJobStatus,
		/// Caller is not the job requester.
		NotRequester,
		/// Caller is not the assigned worker.
		NotAssignedWorker,
		/// Worker does not meet job requirements.
		InsufficientCapabilities,
		/// Worker is at maximum concurrent job capacity.
		AtMaxCapacity,
		/// Worker is not available (offline / missed heartbeats).
		WorkerNotAvailable,
		/// Result hash cannot be zero.
		InvalidResultHash,
		/// URI is empty or too long.
		InvalidUri,
		/// Spec hash cannot be zero.
		InvalidSpecHash,
		/// Budget must be greater than zero.
		InvalidBudget,
		/// Deadline must be in the future.
		InvalidDeadline,
		/// Cannot challenge own job result.
		CannotChallengeSelf,
		/// Challenge already exists for this job.
		AlreadyChallenged,
		/// Insufficient balance for challenge bond.
		InsufficientBond,
		/// Caller is not a committee member.
		NotCommitteeMember,
		/// Already voted on this challenge.
		AlreadyVoted,
		/// Challenge window has not expired yet.
		ChallengeWindowOpen,
		/// Challenge voting not complete.
		VotingIncomplete,
		/// Maximum number of jobs reached.
		TooManyJobs,
		/// Arithmetic overflow.
		ArithmeticOverflow,
		/// Not enough workers available for committee selection.
		InsufficientCommitteePool,
		/// Worker cannot accept their own job.
		CannotAcceptOwnJob,
	}

	// ─── Hooks ─────────────────────────────────────────────────

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		#[cfg(feature = "std")]
		fn offchain_worker(now: BlockNumberFor<T>) {
			Self::run_offchain_worker(now);
		}

		fn on_initialize(now: BlockNumberFor<T>) -> Weight {
			let mut weight = Weight::zero();

			// Check for expired deadlines and challenge windows
			let next_id = NextJobId::<T>::get();
			let mut job_id: JobId = 0;
			while job_id < next_id {
				if let Some(job) = Jobs::<T>::get(job_id) {
					weight = weight.saturating_add(Weight::from_parts(10_000, 0));
					match job.status {
						// Assigned but deadline passed — expire
						JobStatus::Assigned if now > job.deadline => {
							Self::expire_job(job_id, &job);
							weight = weight.saturating_add(Weight::from_parts(50_000_000, 0));
						},
						// Open but deadline passed — expire
						JobStatus::Open if now > job.deadline => {
							Self::expire_job(job_id, &job);
							weight = weight.saturating_add(Weight::from_parts(50_000_000, 0));
						},
						// Submitted and challenge window closed — auto-complete
						JobStatus::Submitted => {
							if let Some(challenge_end) = job.challenge_end {
								if now > challenge_end {
									let _ = Self::do_finalize_unchallenged(job_id, job);
									weight = weight.saturating_add(Weight::from_parts(75_000_000, 0));
								}
							}
						},
						_ => {},
					}
				}
				job_id = job_id.saturating_add(1);
			}

			weight
		}
	}

	// ─── Extrinsics ────────────────────────────────────────────

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		// ── Worker Management ─────────────────────────────────

		/// Register as a compute worker. Locks `stake` and advertises `capabilities`.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::register_worker())]
		pub fn register_worker(
			origin: OriginFor<T>,
			stake: BalanceOf<T>,
			capabilities: Capabilities,
		) -> DispatchResult {
			let worker = ensure_signed(origin)?;
			ensure!(!Workers::<T>::contains_key(&worker), Error::<T>::AlreadyRegistered);

			let min_stake = MinWorkerStake::<T>::get();
			ensure!(stake >= min_stake, Error::<T>::InsufficientStake);

			let count = WorkerCount::<T>::get();
			ensure!(count < T::MaxWorkers::get(), Error::<T>::TooManyWorkers);

			// Reserve stake
			T::Currency::reserve(&worker, stake)
				.map_err(|_| Error::<T>::InsufficientStake)?;

			let now = <frame_system::Pallet<T>>::block_number();

			Workers::<T>::insert(&worker, WorkerProfile {
				stake_locked: stake,
				capabilities,
				max_concurrent_jobs: 1,
				active_jobs: 0,
				completed_jobs: 0,
				failed_jobs: 0,
				reputation: Perbill::from_percent(100),
				registered_at: now,
			});
			WorkerCount::<T>::put(count.saturating_add(1));

			Self::deposit_event(Event::WorkerRegistered {
				worker,
				stake,
				capabilities,
			});

			Ok(())
		}

		/// Deregister as a worker. Unlocks stake. Must have no active jobs.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::deregister_worker())]
		pub fn deregister_worker(origin: OriginFor<T>) -> DispatchResult {
			let worker = ensure_signed(origin)?;
			let profile = Workers::<T>::get(&worker).ok_or(Error::<T>::NotRegistered)?;
			ensure!(profile.active_jobs == 0, Error::<T>::HasActiveJobs);

			T::Currency::unreserve(&worker, profile.stake_locked);
			Workers::<T>::remove(&worker);
			WorkerCount::<T>::mutate(|c| *c = c.saturating_sub(1));
			Heartbeats::<T>::remove(&worker);

			Self::deposit_event(Event::WorkerDeregistered {
				worker,
				stake_returned: profile.stake_locked,
			});

			Ok(())
		}

		/// Update advertised capabilities (e.g. after hardware upgrade).
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::update_capabilities())]
		pub fn update_capabilities(
			origin: OriginFor<T>,
			capabilities: Capabilities,
		) -> DispatchResult {
			let worker = ensure_signed(origin)?;
			Workers::<T>::try_mutate(&worker, |maybe| {
				let profile = maybe.as_mut().ok_or(Error::<T>::NotRegistered)?;
				profile.capabilities = capabilities;
				Self::deposit_event(Event::WorkerCapabilitiesUpdated {
					worker: worker.clone(),
					capabilities,
				});
				Ok(())
			})
		}

		// ── Job Lifecycle ─────────────────────────────────────

		/// Submit a compute job. Locks `budget` in escrow.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::submit_job())]
		pub fn submit_job(
			origin: OriginFor<T>,
			spec_hash: H256,
			spec_uri: Vec<u8>,
			budget: BalanceOf<T>,
			deadline_blocks: u32,
			requirements: JobRequirements,
		) -> DispatchResult {
			let requester = ensure_signed(origin)?;

			ensure!(spec_hash != H256::zero(), Error::<T>::InvalidSpecHash);
			ensure!(!budget.is_zero(), Error::<T>::InvalidBudget);

			let bounded_uri: BoundedVec<u8, T::MaxUriLen> =
				spec_uri.try_into().map_err(|_| Error::<T>::InvalidUri)?;
			ensure!(!bounded_uri.is_empty(), Error::<T>::InvalidUri);

			let job_id = NextJobId::<T>::get();
			ensure!(job_id < T::MaxJobs::get() as u64, Error::<T>::TooManyJobs);

			let now = <frame_system::Pallet<T>>::block_number();
			let deadline = now.saturating_add(deadline_blocks.into());

			// Transfer budget to pallet escrow account
			let pallet_account = Self::pallet_account();
			T::Currency::transfer(
				&requester,
				&pallet_account,
				budget,
				ExistenceRequirement::KeepAlive,
			)?;

			Escrows::<T>::insert(job_id, budget);

			Jobs::<T>::insert(job_id, Job {
				requester: requester.clone(),
				spec_hash,
				spec_uri: bounded_uri,
				budget,
				status: JobStatus::Open,
				worker: None,
				result_hash: None,
				result_uri: None,
				requirements,
				created_at: now,
				deadline,
				challenge_end: None,
			});
			NextJobId::<T>::put(job_id.saturating_add(1));

			Self::deposit_event(Event::JobSubmitted {
				job_id,
				requester,
				budget,
				spec_hash,
				requirements,
			});

			Ok(())
		}

		/// Cancel an open job before a worker accepts it. Refunds escrow.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::cancel_job())]
		pub fn cancel_job(
			origin: OriginFor<T>,
			job_id: JobId,
		) -> DispatchResult {
			let caller = ensure_signed(origin)?;

			Jobs::<T>::try_mutate(job_id, |maybe_job| {
				let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
				ensure!(job.requester == caller, Error::<T>::NotRequester);
				ensure!(job.status == JobStatus::Open, Error::<T>::InvalidJobStatus);

				// Refund escrow
				let escrowed = Escrows::<T>::take(job_id);
				if !escrowed.is_zero() {
					let pallet_account = Self::pallet_account();
					T::Currency::transfer(
						&pallet_account,
						&caller,
						escrowed,
						ExistenceRequirement::AllowDeath,
					)?;
				}

				job.status = JobStatus::Cancelled;

				Self::deposit_event(Event::JobCancelled {
					job_id,
					requester: caller.clone(),
					refund: escrowed,
				});

				Ok(())
			})
		}

		/// Accept an open job. Pallet verifies worker meets requirements.
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::accept_job())]
		pub fn accept_job(
			origin: OriginFor<T>,
			job_id: JobId,
		) -> DispatchResult {
			let worker = ensure_signed(origin)?;

			let profile = Workers::<T>::get(&worker).ok_or(Error::<T>::NotRegistered)?;
			ensure!(
				profile.active_jobs < profile.max_concurrent_jobs,
				Error::<T>::AtMaxCapacity
			);

			// Check heartbeat freshness
			Self::ensure_worker_available(&worker)?;

			Jobs::<T>::try_mutate(job_id, |maybe_job| {
				let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
				ensure!(job.status == JobStatus::Open, Error::<T>::InvalidJobStatus);
				ensure!(job.requester != worker, Error::<T>::CannotAcceptOwnJob);

				// Check capabilities
				ensure!(
					job.requirements.satisfied_by(&profile.capabilities),
					Error::<T>::InsufficientCapabilities
				);

				job.status = JobStatus::Assigned;
				job.worker = Some(worker.clone());

				// Increment active jobs
				Workers::<T>::mutate(&worker, |maybe| {
					if let Some(p) = maybe {
						p.active_jobs = p.active_jobs.saturating_add(1);
					}
				});

				Self::deposit_event(Event::JobAccepted {
					job_id,
					worker: worker.clone(),
				});

				Ok(())
			})
		}

		/// Submit a computation result. Opens the challenge window.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::submit_result())]
		pub fn submit_result(
			origin: OriginFor<T>,
			job_id: JobId,
			result_hash: H256,
			result_uri: Vec<u8>,
		) -> DispatchResult {
			let worker = ensure_signed(origin)?;
			ensure!(result_hash != H256::zero(), Error::<T>::InvalidResultHash);

			let bounded_uri: BoundedVec<u8, T::MaxUriLen> =
				result_uri.try_into().map_err(|_| Error::<T>::InvalidUri)?;
			ensure!(!bounded_uri.is_empty(), Error::<T>::InvalidUri);

			Jobs::<T>::try_mutate(job_id, |maybe_job| {
				let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
				ensure!(job.status == JobStatus::Assigned, Error::<T>::InvalidJobStatus);
				ensure!(
					job.worker.as_ref() == Some(&worker),
					Error::<T>::NotAssignedWorker
				);

				let now = <frame_system::Pallet<T>>::block_number();
				ensure!(now <= job.deadline, Error::<T>::InvalidJobStatus);

				let challenge_period = ChallengePeriodBlocks::<T>::get();
				let challenge_end = now.saturating_add(challenge_period.into());

				job.status = JobStatus::Submitted;
				job.result_hash = Some(result_hash);
				job.result_uri = Some(bounded_uri);
				job.challenge_end = Some(challenge_end);

				Self::deposit_event(Event::ResultSubmitted {
					job_id,
					worker: worker.clone(),
					result_hash,
					challenge_end,
				});

				Ok(())
			})
		}

		/// Challenge a submitted job result. Locks a bond.
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::challenge())]
		pub fn challenge(
			origin: OriginFor<T>,
			job_id: JobId,
			challenger_hash: Option<H256>,
		) -> DispatchResult {
			let challenger = ensure_signed(origin)?;

			let job = Jobs::<T>::get(job_id).ok_or(Error::<T>::JobNotFound)?;
			ensure!(job.status == JobStatus::Submitted, Error::<T>::InvalidJobStatus);
			ensure!(
				job.worker.as_ref() != Some(&challenger),
				Error::<T>::CannotChallengeSelf
			);
			ensure!(
				!Challenges::<T>::contains_key(job_id),
				Error::<T>::AlreadyChallenged
			);

			// Lock challenge bond
			let bond = ChallengeBondAmount::<T>::get();
			T::Currency::reserve(&challenger, bond)
				.map_err(|_| Error::<T>::InsufficientBond)?;

			// Select committee
			let committee = Self::select_committee(job_id, &job)?;

			let now = <frame_system::Pallet<T>>::block_number();

			Challenges::<T>::insert(job_id, Challenge {
				challenger: challenger.clone(),
				bond,
				challenger_hash,
				votes_for_worker: 0,
				votes_against_worker: 0,
				committee,
				created_at: now,
			});

			// Update job status
			Jobs::<T>::mutate(job_id, |maybe_job| {
				if let Some(j) = maybe_job {
					j.status = JobStatus::Challenged;
				}
			});

			Self::deposit_event(Event::JobChallenged {
				job_id,
				challenger,
				bond,
			});

			Ok(())
		}

		/// Vote on a challenge (committee members only).
		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::vote_challenge())]
		pub fn vote_challenge(
			origin: OriginFor<T>,
			job_id: JobId,
			vote: ChallengeVote,
		) -> DispatchResult {
			let voter = ensure_signed(origin)?;

			let job = Jobs::<T>::get(job_id).ok_or(Error::<T>::JobNotFound)?;
			ensure!(job.status == JobStatus::Challenged, Error::<T>::InvalidJobStatus);

			// Verify voter is on the committee
			let challenge = Challenges::<T>::get(job_id)
				.ok_or(Error::<T>::JobNotFound)?;
			ensure!(
				challenge.committee.contains(&voter),
				Error::<T>::NotCommitteeMember
			);
			ensure!(
				!CommitteeVotes::<T>::contains_key(job_id, &voter),
				Error::<T>::AlreadyVoted
			);

			CommitteeVotes::<T>::insert(job_id, &voter, vote);

			// Update tally
			Challenges::<T>::mutate(job_id, |maybe| {
				if let Some(c) = maybe {
					match vote {
						ChallengeVote::WorkerCorrect => {
							c.votes_for_worker = c.votes_for_worker.saturating_add(1);
						},
						ChallengeVote::WorkerIncorrect => {
							c.votes_against_worker = c.votes_against_worker.saturating_add(1);
						},
					}
				}
			});

			Self::deposit_event(Event::ChallengeVoteSubmitted {
				job_id,
				voter,
				vote,
			});

			// Auto-finalize if all committee members have voted
			let updated = Challenges::<T>::get(job_id).unwrap();
			let total_votes = updated.votes_for_worker
				.saturating_add(updated.votes_against_worker);
			if total_votes as u32 >= updated.committee.len() as u32 {
				let _ = Self::do_finalize_challenged(job_id);
			}

			Ok(())
		}

		/// Manually finalize a job. For unchallenged jobs after window expires,
		/// or challenged jobs after all votes are in.
		#[pallet::call_index(9)]
		#[pallet::weight(T::WeightInfo::finalize_job())]
		pub fn finalize_job(
			origin: OriginFor<T>,
			job_id: JobId,
		) -> DispatchResult {
			ensure_signed(origin)?;

			let job = Jobs::<T>::get(job_id).ok_or(Error::<T>::JobNotFound)?;
			let now = <frame_system::Pallet<T>>::block_number();

			match job.status {
				JobStatus::Submitted => {
					let challenge_end = job.challenge_end
						.ok_or(Error::<T>::ChallengeWindowOpen)?;
					ensure!(now > challenge_end, Error::<T>::ChallengeWindowOpen);
					Self::do_finalize_unchallenged(job_id, job)
				},
				JobStatus::Challenged => {
					Self::do_finalize_challenged(job_id)
				},
				_ => Err(Error::<T>::InvalidJobStatus.into()),
			}
		}

		// ── Heartbeat ─────────────────────────────────────────

		/// Submit a heartbeat proving worker availability.
		#[pallet::call_index(10)]
		#[pallet::weight(T::WeightInfo::submit_heartbeat())]
		pub fn submit_heartbeat(origin: OriginFor<T>) -> DispatchResult {
			let worker = ensure_signed(origin)?;
			ensure!(Workers::<T>::contains_key(&worker), Error::<T>::NotRegistered);

			let now = <frame_system::Pallet<T>>::block_number();
			let now_u64: u64 = now.saturated_into();

			Heartbeats::<T>::mutate(&worker, |uptime| {
				uptime.heartbeat_count = uptime.heartbeat_count.saturating_add(1);
				uptime.last_heartbeat = now_u64;
			});

			Self::deposit_event(Event::HeartbeatReceived {
				worker,
				block: now,
			});

			Ok(())
		}

		// ── Sudo Configuration ────────────────────────────────

		/// Set the challenge window duration in blocks. Root only.
		#[pallet::call_index(11)]
		#[pallet::weight(T::WeightInfo::set_challenge_period())]
		pub fn set_challenge_period(origin: OriginFor<T>, blocks: u32) -> DispatchResult {
			ensure_root(origin)?;
			ChallengePeriodBlocks::<T>::put(blocks);
			Self::deposit_event(Event::ConfigUpdated { parameter: b"challenge_period".to_vec() });
			Ok(())
		}

		/// Set the challenge bond amount. Root only.
		#[pallet::call_index(12)]
		#[pallet::weight(T::WeightInfo::set_challenge_bond())]
		pub fn set_challenge_bond(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
			ensure_root(origin)?;
			ChallengeBondAmount::<T>::put(amount);
			Self::deposit_event(Event::ConfigUpdated { parameter: b"challenge_bond".to_vec() });
			Ok(())
		}

		/// Set the minimum worker stake. Root only.
		#[pallet::call_index(13)]
		#[pallet::weight(T::WeightInfo::set_min_worker_stake())]
		pub fn set_min_worker_stake(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
			ensure_root(origin)?;
			MinWorkerStake::<T>::put(amount);
			Self::deposit_event(Event::ConfigUpdated { parameter: b"min_worker_stake".to_vec() });
			Ok(())
		}

		/// Set the dispute committee size. Root only.
		#[pallet::call_index(14)]
		#[pallet::weight(T::WeightInfo::set_committee_size())]
		pub fn set_committee_size(origin: OriginFor<T>, size: u8) -> DispatchResult {
			ensure_root(origin)?;
			CommitteeSizeConfig::<T>::put(size);
			Self::deposit_event(Event::ConfigUpdated { parameter: b"committee_size".to_vec() });
			Ok(())
		}

		/// Set the protocol fee percentage. Root only.
		#[pallet::call_index(15)]
		#[pallet::weight(T::WeightInfo::set_protocol_fee())]
		pub fn set_protocol_fee(origin: OriginFor<T>, fee: Perbill) -> DispatchResult {
			ensure_root(origin)?;
			ProtocolFee::<T>::put(fee);
			Self::deposit_event(Event::ConfigUpdated { parameter: b"protocol_fee".to_vec() });
			Ok(())
		}

		/// Set the heartbeat interval (blocks between required heartbeats). Root only.
		#[pallet::call_index(16)]
		#[pallet::weight(T::WeightInfo::set_heartbeat_interval())]
		pub fn set_heartbeat_interval(origin: OriginFor<T>, blocks: u32) -> DispatchResult {
			ensure_root(origin)?;
			HeartbeatInterval::<T>::put(blocks);
			Self::deposit_event(Event::ConfigUpdated { parameter: b"heartbeat_interval".to_vec() });
			Ok(())
		}

		/// Fund the availability reward pool. Anyone can call.
		#[pallet::call_index(17)]
		#[pallet::weight(T::WeightInfo::fund_availability_pool())]
		pub fn fund_availability_pool(
			origin: OriginFor<T>,
			amount: BalanceOf<T>,
		) -> DispatchResult {
			let funder = ensure_signed(origin)?;
			let pallet_account = Self::pallet_account();
			T::Currency::transfer(
				&funder,
				&pallet_account,
				amount,
				ExistenceRequirement::KeepAlive,
			)?;
			AvailabilityPool::<T>::mutate(|pool| *pool = pool.saturating_add(amount));
			Self::deposit_event(Event::AvailabilityPoolFunded { amount });
			Ok(())
		}

		// ── Unsigned extrinsics (submitted by OCW) ───────────

		/// Heartbeat submitted by the off-chain worker (unsigned).
		#[pallet::call_index(18)]
		#[pallet::weight(T::WeightInfo::submit_heartbeat())]
		pub fn unsigned_heartbeat(
			origin: OriginFor<T>,
			worker: T::AccountId,
		) -> DispatchResult {
			ensure_none(origin)?;
			ensure!(Workers::<T>::contains_key(&worker), Error::<T>::NotRegistered);

			let now = <frame_system::Pallet<T>>::block_number();
			let now_u64: u64 = now.saturated_into();

			Heartbeats::<T>::mutate(&worker, |uptime| {
				uptime.heartbeat_count = uptime.heartbeat_count.saturating_add(1);
				uptime.last_heartbeat = now_u64;
			});

			Self::deposit_event(Event::HeartbeatReceived {
				worker,
				block: now,
			});

			Ok(())
		}

		/// Result submission from the off-chain worker (unsigned).
		#[pallet::call_index(19)]
		#[pallet::weight(T::WeightInfo::submit_result())]
		pub fn unsigned_submit_result(
			origin: OriginFor<T>,
			job_id: JobId,
			worker: T::AccountId,
			result_hash: H256,
			result_uri: Vec<u8>,
		) -> DispatchResult {
			ensure_none(origin)?;
			ensure!(result_hash != H256::zero(), Error::<T>::InvalidResultHash);

			let bounded_uri: BoundedVec<u8, T::MaxUriLen> =
				result_uri.try_into().map_err(|_| Error::<T>::InvalidUri)?;
			ensure!(!bounded_uri.is_empty(), Error::<T>::InvalidUri);

			Jobs::<T>::try_mutate(job_id, |maybe_job| {
				let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
				ensure!(job.status == JobStatus::Assigned, Error::<T>::InvalidJobStatus);
				ensure!(
					job.worker.as_ref() == Some(&worker),
					Error::<T>::NotAssignedWorker
				);

				let now = <frame_system::Pallet<T>>::block_number();
				ensure!(now <= job.deadline, Error::<T>::InvalidJobStatus);

				let challenge_period = ChallengePeriodBlocks::<T>::get();
				let challenge_end = now.saturating_add(challenge_period.into());

				job.status = JobStatus::Submitted;
				job.result_hash = Some(result_hash);
				job.result_uri = Some(bounded_uri);
				job.challenge_end = Some(challenge_end);

				Self::deposit_event(Event::ResultSubmitted {
					job_id,
					worker: worker.clone(),
					result_hash,
					challenge_end,
				});

				Ok(())
			})
		}
	}

	// ─── Validate Unsigned ───────────────────────────────────────

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			match call {
				Call::unsigned_heartbeat { worker } => {
					// Worker must be registered
					if !Workers::<T>::contains_key(worker) {
						return InvalidTransaction::Custom(1).into();
					}
					ValidTransaction::with_tag_prefix("compute-marketplace-heartbeat")
						.priority(1)
						.longevity(5)
						.and_provides(("heartbeat", worker.encode()))
						.propagate(true)
						.build()
				},
				Call::unsigned_submit_result { job_id, worker, .. } => {
					// Job must exist and be assigned to this worker
					if let Some(job) = Jobs::<T>::get(job_id) {
						if job.status != JobStatus::Assigned || job.worker.as_ref() != Some(worker) {
							return InvalidTransaction::Custom(2).into();
						}
					} else {
						return InvalidTransaction::Custom(3).into();
					}
					ValidTransaction::with_tag_prefix("compute-marketplace-result")
						.priority(10)
						.longevity(10)
						.and_provides(("result", job_id))
						.propagate(true)
						.build()
				},
				_ => InvalidTransaction::Call.into(),
			}
		}
	}

	// ─── Internal Helpers ──────────────────────────────────────

	impl<T: Config> Pallet<T> {
		/// The pallet's escrow account (holds job payments + availability pool).
		pub fn pallet_account() -> T::AccountId {
			T::ComputePalletId::get().into_account_truncating()
		}

		/// Check that a worker has a recent heartbeat.
		fn ensure_worker_available(worker: &T::AccountId) -> DispatchResult {
			let uptime = Heartbeats::<T>::get(worker);
			// Allow first-time acceptance (no heartbeat yet required for fresh workers)
			if uptime.heartbeat_count == 0 {
				return Ok(());
			}

			let now: u64 = <frame_system::Pallet<T>>::block_number().saturated_into();
			let interval: u64 = HeartbeatInterval::<T>::get() as u64;
			let deadline = uptime.last_heartbeat.saturating_add(interval);

			ensure!(now <= deadline, Error::<T>::WorkerNotAvailable);
			Ok(())
		}

		/// Select a random committee from registered workers for dispute resolution.
		/// Excludes the assigned worker and the challenger.
		fn select_committee(
			job_id: JobId,
			job: &Job<T>,
		) -> Result<BoundedVec<T::AccountId, T::MaxCommitteeSize>, DispatchError> {
			let desired_size = CommitteeSizeConfig::<T>::get() as usize;
			let worker = job.worker.as_ref();
			let challenge = Challenges::<T>::get(job_id);
			let challenger = challenge.as_ref().map(|c| &c.challenger);

			// Collect eligible workers
			let mut candidates: Vec<T::AccountId> = Vec::new();
			for (account, _profile) in Workers::<T>::iter() {
				// Exclude the assigned worker and challenger
				if worker == Some(&account) {
					continue;
				}
				if challenger == Some(&account) {
					continue;
				}
				candidates.push(account);
			}

			ensure!(
				candidates.len() >= desired_size,
				Error::<T>::InsufficientCommitteePool
			);

			// Deterministic random selection using block hash + job_id
			let now = <frame_system::Pallet<T>>::block_number();
			let parent = now.saturating_sub(1u32.into());
			let seed = (
				<frame_system::Pallet<T>>::block_hash(parent),
				job_id,
			);
			let seed_hash = T::Hashing::hash_of(&seed);
			let seed_bytes: &[u8] = seed_hash.as_ref();

			// Fisher-Yates partial shuffle using seed bytes
			let mut selected: Vec<T::AccountId> = Vec::new();
			let n = candidates.len();
			for i in 0..desired_size {
				let byte_idx = i % seed_bytes.len();
				let swap_idx = i + (seed_bytes[byte_idx] as usize % (n - i));
				candidates.swap(i, swap_idx);
				selected.push(candidates[i].clone());
			}

			let bounded: BoundedVec<T::AccountId, T::MaxCommitteeSize> =
				selected.try_into().map_err(|_| Error::<T>::ArithmeticOverflow)?;

			Ok(bounded)
		}

		/// Expire a job — refund requester, penalize worker reputation if assigned.
		fn expire_job(job_id: JobId, job: &Job<T>) {
			// Refund escrow to requester
			let escrowed = Escrows::<T>::take(job_id);
			if !escrowed.is_zero() {
				let pallet_account = Self::pallet_account();
				let _ = T::Currency::transfer(
					&pallet_account,
					&job.requester,
					escrowed,
					ExistenceRequirement::AllowDeath,
				);
			}

			// Penalize worker reputation if was assigned
			if let Some(ref worker) = job.worker {
				Workers::<T>::mutate(worker, |maybe| {
					if let Some(p) = maybe {
						p.active_jobs = p.active_jobs.saturating_sub(1);
						p.failed_jobs = p.failed_jobs.saturating_add(1);
						p.reputation = Self::updated_reputation(
							p.completed_jobs,
							p.failed_jobs,
						);
					}
				});
			}

			// Update job status
			Jobs::<T>::mutate(job_id, |maybe_job| {
				if let Some(j) = maybe_job {
					j.status = JobStatus::Expired;
				}
			});

			Self::deposit_event(Event::JobExpired {
				job_id,
				worker: job.worker.clone(),
			});
		}

		/// Finalize an unchallenged job — release payment to worker.
		fn do_finalize_unchallenged(job_id: JobId, job: Job<T>) -> DispatchResult {
			let worker = job.worker.as_ref()
				.ok_or(Error::<T>::InvalidJobStatus)?;

			let escrowed = Escrows::<T>::take(job_id);
			let pallet_account = Self::pallet_account();

			// Calculate protocol fee
			let fee_rate = ProtocolFee::<T>::get();
			let protocol_fee = fee_rate * escrowed;
			let worker_payout = escrowed.saturating_sub(protocol_fee);

			// Pay worker
			if !worker_payout.is_zero() {
				T::Currency::transfer(
					&pallet_account,
					worker,
					worker_payout,
					ExistenceRequirement::AllowDeath,
				)?;
			}
			// Protocol fee stays in pallet account (chain operator can withdraw)

			// Update worker profile
			Workers::<T>::mutate(worker, |maybe| {
				if let Some(p) = maybe {
					p.active_jobs = p.active_jobs.saturating_sub(1);
					p.completed_jobs = p.completed_jobs.saturating_add(1);
					p.reputation = Self::updated_reputation(
						p.completed_jobs,
						p.failed_jobs,
					);
				}
			});

			// Update job status
			Jobs::<T>::mutate(job_id, |maybe_job| {
				if let Some(j) = maybe_job {
					j.status = JobStatus::Completed;
				}
			});

			Self::deposit_event(Event::JobCompleted {
				job_id,
				worker: worker.clone(),
				payout: worker_payout,
				protocol_fee,
			});

			Ok(())
		}

		/// Finalize a challenged job — determine outcome based on committee votes.
		fn do_finalize_challenged(job_id: JobId) -> DispatchResult {
			let challenge = Challenges::<T>::get(job_id)
				.ok_or(Error::<T>::JobNotFound)?;
			let job = Jobs::<T>::get(job_id)
				.ok_or(Error::<T>::JobNotFound)?;

			let total_votes = challenge.votes_for_worker
				.saturating_add(challenge.votes_against_worker);

			// Need majority of committee to have voted
			let committee_size = challenge.committee.len() as u8;
			let majority = committee_size / 2 + 1;
			ensure!(total_votes >= majority, Error::<T>::VotingIncomplete);

			let worker = job.worker.as_ref()
				.ok_or(Error::<T>::InvalidJobStatus)?;
			let pallet_account = Self::pallet_account();

			if challenge.votes_for_worker >= challenge.votes_against_worker {
				// Worker upheld — challenger loses bond, job completes normally
				// Unreserve and slash challenger bond (goes to pallet account)
				let bond = challenge.bond;
				T::Currency::unreserve(&challenge.challenger, bond);
				T::Currency::transfer(
					&challenge.challenger,
					&pallet_account,
					bond,
					ExistenceRequirement::AllowDeath,
				)?;

				// Complete the job normally
				let escrowed = Escrows::<T>::take(job_id);
				let fee_rate = ProtocolFee::<T>::get();
				let protocol_fee = fee_rate * escrowed;
				let worker_payout = escrowed.saturating_sub(protocol_fee);

				if !worker_payout.is_zero() {
					T::Currency::transfer(
						&pallet_account,
						worker,
						worker_payout,
						ExistenceRequirement::AllowDeath,
					)?;
				}

				Workers::<T>::mutate(worker, |maybe| {
					if let Some(p) = maybe {
						p.active_jobs = p.active_jobs.saturating_sub(1);
						p.completed_jobs = p.completed_jobs.saturating_add(1);
						p.reputation = Self::updated_reputation(
							p.completed_jobs,
							p.failed_jobs,
						);
					}
				});

				Jobs::<T>::mutate(job_id, |maybe_job| {
					if let Some(j) = maybe_job {
						j.status = JobStatus::Completed;
					}
				});

				Self::deposit_event(Event::ChallengeFailed {
					job_id,
					challenger: challenge.challenger,
					bond_lost: bond,
				});

				Self::deposit_event(Event::JobCompleted {
					job_id,
					worker: worker.clone(),
					payout: worker_payout,
					protocol_fee,
				});
			} else {
				// Worker found fraudulent — slash worker, refund requester, reward challenger
				let slash_rate = SlashPercent::<T>::get();
				let worker_stake = Workers::<T>::get(worker)
					.map(|p| p.stake_locked)
					.unwrap_or_else(BalanceOf::<T>::zero);
				let slash_amount = slash_rate * worker_stake;

				// Unreserve the slashed portion from worker
				if !slash_amount.is_zero() {
					T::Currency::unreserve(worker, slash_amount);
					// Half to challenger, half to protocol
					let challenger_reward = slash_amount / 2u32.into();
					let _ = T::Currency::transfer(
						worker,
						&challenge.challenger,
						challenger_reward,
						ExistenceRequirement::AllowDeath,
					);
					let protocol_portion = slash_amount.saturating_sub(challenger_reward);
					let _ = T::Currency::transfer(
						worker,
						&pallet_account,
						protocol_portion,
						ExistenceRequirement::AllowDeath,
					);
				}

				// Refund escrow to requester
				let escrowed = Escrows::<T>::take(job_id);
				if !escrowed.is_zero() {
					let _ = T::Currency::transfer(
						&pallet_account,
						&job.requester,
						escrowed,
						ExistenceRequirement::AllowDeath,
					);
				}

				// Return challenger's bond
				T::Currency::unreserve(&challenge.challenger, challenge.bond);

				// Update worker profile
				Workers::<T>::mutate(worker, |maybe| {
					if let Some(p) = maybe {
						p.active_jobs = p.active_jobs.saturating_sub(1);
						p.failed_jobs = p.failed_jobs.saturating_add(1);
						p.stake_locked = p.stake_locked.saturating_sub(slash_amount);
						p.reputation = Self::updated_reputation(
							p.completed_jobs,
							p.failed_jobs,
						);
					}
				});

				Jobs::<T>::mutate(job_id, |maybe_job| {
					if let Some(j) = maybe_job {
						j.status = JobStatus::Slashed;
					}
				});

				Self::deposit_event(Event::WorkerSlashed {
					job_id,
					worker: worker.clone(),
					slash_amount,
					challenger_reward: slash_amount / 2u32.into(),
				});
			}

			// Clean up challenge storage
			Challenges::<T>::remove(job_id);
			for member in challenge.committee.iter() {
				CommitteeVotes::<T>::remove(job_id, member);
			}

			Ok(())
		}

		/// Calculate reputation as completed / (completed + failed).
		fn updated_reputation(completed: u32, failed: u32) -> Perbill {
			let total = completed.saturating_add(failed);
			if total == 0 {
				return Perbill::from_percent(100);
			}
			Perbill::from_rational(completed, total)
		}
	}
}
