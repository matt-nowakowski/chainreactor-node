use crate::*;
use sp_core::H256;

pub type SolutionGroupId = u32;
pub type VotingRoundId = u64;
pub type RewardPeriodIndex = u64;

/// A solution group defines a category of off-chain compute tasks.
/// Workers subscribe to solution groups and earn rewards for correct attestations.
#[derive(
	Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
#[scale_info(skip_type_params(T))]
pub struct SolutionGroup<T: Config> {
	/// Human-readable name
	pub name: BoundedVec<u8, T::MaxNameLen>,
	/// Creator/owner of this solution group
	pub owner: T::AccountId,
	/// Minimum stake required to participate (in native currency)
	pub stake_requirement: BalanceOf<T>,
	/// Percentage of correct votes needed to qualify for rewards (e.g. 75%)
	pub sla_threshold: Perbill,
	/// Voting threshold — what fraction of votes must agree for consensus
	pub consensus_threshold: Perbill,
	/// Blocks per voting round
	pub round_length: u32,
	/// Whether this group is currently accepting work
	pub active: bool,
	/// Block when this group was created
	pub created_at: BlockNumberFor<T>,
	/// Opaque metadata — use case specific (e.g. target URL, task config, JSON blob).
	/// The pallet does not interpret this field; it is stored and queryable by clients.
	pub metadata: BoundedVec<u8, T::MaxMetadataLen>,
}

/// Tracks a worker's subscription to a solution group
#[derive(
	Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default,
)]
pub struct Subscription<Balance, BlockNumber> {
	/// Amount of stake locked for this subscription
	pub stake_locked: Balance,
	/// Block when the subscription started
	pub subscribed_at: BlockNumber,
	/// Whether this subscription is active
	pub active: bool,
}

/// A single voting round within a solution group
#[derive(
	Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
pub struct VotingRound<BlockNumber> {
	/// Which solution group this round belongs to
	pub solution_group_id: SolutionGroupId,
	/// Block when this round started
	pub started_at: BlockNumber,
	/// Block when this round ends
	pub ends_at: BlockNumber,
	/// The winning result hash (set after consensus)
	pub consensus_result: Option<H256>,
	/// Total votes submitted
	pub total_votes: u32,
	/// Whether this round has been finalized
	pub finalized: bool,
}

/// Tracks per-worker performance within a reward period
#[derive(
	Encode, Decode, Copy, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen, Default,
)]
pub struct WorkerPerformance {
	/// Number of votes that matched consensus
	pub correct_votes: u32,
	/// Total votes submitted
	pub total_votes: u32,
}

impl WorkerPerformance {
	pub fn accuracy(&self) -> Perbill {
		if self.total_votes == 0 {
			return Perbill::zero();
		}
		Perbill::from_rational(self.correct_votes, self.total_votes)
	}
}

/// Reward period tracking for a solution group
#[derive(
	Encode, Decode, Copy, Clone, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen,
)]
pub struct WorkerRewardPeriod<BlockNumber, Balance> {
	/// Current period index
	pub current: RewardPeriodIndex,
	/// Block when this period started
	pub first: BlockNumber,
	/// Length in blocks
	pub length: u32,
	/// Total reward pool for this period
	pub reward_pool: Balance,
}

impl<
		B: Copy + sp_std::ops::Add<Output = B> + sp_std::ops::Sub<Output = B> + From<u32> + PartialOrd,
		Balance: Default + Copy,
	> Default for WorkerRewardPeriod<B, Balance>
{
	fn default() -> Self {
		Self {
			current: 0u64,
			first: 0u32.into(),
			length: 7200u32, // ~12h at 6s block time
			reward_pool: Balance::default(),
		}
	}
}
