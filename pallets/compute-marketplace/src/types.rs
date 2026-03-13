use crate::*;
use sp_core::H256;

pub type JobId = u64;

// ─── Capabilities & Requirements ──────────────────────────

/// Hardware capabilities advertised by a worker node.
#[derive(
	Encode, Decode, Copy, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default,
)]
pub struct Capabilities {
	/// Number of CPU cores available
	pub cpu_cores: u16,
	/// Available memory in MB
	pub memory_mb: u32,
	/// GPU class
	pub gpu: GpuClass,
	/// Available disk storage in MB
	pub storage_mb: u32,
}

/// GPU capability tiers — ordered so that higher tiers satisfy lower requirements.
#[derive(
	Encode, Decode, Copy, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
	PartialOrd, Ord, Default,
)]
pub enum GpuClass {
	/// No GPU
	#[default]
	None,
	/// Integrated or low-end discrete GPU
	Basic,
	/// CUDA-capable discrete GPU (RTX/Quadro class)
	Compute,
	/// Data-center GPU (A100/H100 class)
	HighEnd,
}

/// Minimum hardware requirements declared by a job.
#[derive(
	Encode, Decode, Copy, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default,
)]
pub struct JobRequirements {
	pub min_cpu_cores: u16,
	pub min_memory_mb: u32,
	pub gpu_required: GpuClass,
	pub min_storage_mb: u32,
}

impl JobRequirements {
	/// Check whether the given capabilities satisfy these requirements.
	pub fn satisfied_by(&self, caps: &Capabilities) -> bool {
		caps.cpu_cores >= self.min_cpu_cores
			&& caps.memory_mb >= self.min_memory_mb
			&& caps.gpu >= self.gpu_required
			&& caps.storage_mb >= self.min_storage_mb
	}
}

// ─── Worker Profile ───────────────────────────────────────

/// A registered compute worker.
#[derive(
	Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
pub struct WorkerProfile<T: Config> {
	/// Tokens locked as collateral
	pub stake_locked: BalanceOf<T>,
	/// Machine capabilities
	pub capabilities: Capabilities,
	/// Maximum concurrent jobs this worker will accept
	pub max_concurrent_jobs: u8,
	/// Currently active jobs
	pub active_jobs: u8,
	/// Lifetime completed jobs
	pub completed_jobs: u32,
	/// Lifetime failed/slashed jobs
	pub failed_jobs: u32,
	/// Rolling reputation score (correct / total)
	pub reputation: Perbill,
	/// Block when this worker registered
	pub registered_at: BlockNumberFor<T>,
}

// ─── Job ──────────────────────────────────────────────────

/// Lifecycle status of a compute job.
#[derive(
	Encode, Decode, Copy, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
pub enum JobStatus {
	/// Posted, waiting for a worker to accept
	Open,
	/// Worker has accepted, computation in progress
	Assigned,
	/// Worker submitted result, challenge window open
	Submitted,
	/// Result challenged, committee voting in progress
	Challenged,
	/// Accepted — unchallenged or challenge failed
	Completed,
	/// Challenge upheld — worker penalized
	Slashed,
	/// Deadline passed with no result submitted
	Expired,
	/// Requester cancelled before assignment
	Cancelled,
}

/// A compute job.
#[derive(
	Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
pub struct Job<T: Config> {
	/// Who submitted this job
	pub requester: T::AccountId,
	/// Hash of the job specification (for integrity verification)
	pub spec_hash: H256,
	/// URI pointing to the full job specification (IPFS CID, HTTP URL, etc.)
	pub spec_uri: BoundedVec<u8, T::MaxUriLen>,
	/// Payment offered for this job (in native tokens)
	pub budget: BalanceOf<T>,
	/// Current lifecycle status
	pub status: JobStatus,
	/// Assigned worker (set on accept)
	pub worker: Option<T::AccountId>,
	/// Hash of the computation result
	pub result_hash: Option<H256>,
	/// URI pointing to the result data
	pub result_uri: Option<BoundedVec<u8, T::MaxUriLen>>,
	/// Minimum hardware requirements
	pub requirements: JobRequirements,
	/// Block when the job was created
	pub created_at: BlockNumberFor<T>,
	/// Worker must submit result before this block
	pub deadline: BlockNumberFor<T>,
	/// Block when the challenge window closes (set on result submission)
	pub challenge_end: Option<BlockNumberFor<T>>,
}

// ─── Challenge ────────────────────────────────────────────

/// A challenge against a submitted job result.
#[derive(
	Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
pub struct Challenge<T: Config> {
	/// Who raised the challenge
	pub challenger: T::AccountId,
	/// Bond locked by the challenger (anti-spam)
	pub bond: BalanceOf<T>,
	/// Challenger's own result hash (if they re-executed)
	pub challenger_hash: Option<H256>,
	/// Votes in favor of the worker's result
	pub votes_for_worker: u8,
	/// Votes against the worker's result
	pub votes_against_worker: u8,
	/// Committee members selected to adjudicate
	pub committee: BoundedVec<T::AccountId, T::MaxCommitteeSize>,
	/// Block when the challenge was raised
	pub created_at: BlockNumberFor<T>,
}

/// A committee member's vote on a challenge.
#[derive(
	Encode, Decode, Copy, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
pub enum ChallengeVote {
	/// Worker's result is correct
	WorkerCorrect,
	/// Worker's result is incorrect
	WorkerIncorrect,
}

// ─── Heartbeat (availability tracking) ────────────────────

/// Tracks worker uptime within a reward period.
#[derive(
	Encode, Decode, Copy, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default,
)]
pub struct WorkerUptime {
	/// Number of heartbeats submitted in this period
	pub heartbeat_count: u32,
	/// Block of last heartbeat
	pub last_heartbeat: u64,
}
