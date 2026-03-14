//! Off-chain worker — DISABLED.
//!
//! The compute marketplace uses the standalone `cr-compute` daemon for job
//! execution instead of the OCW+sidecar pattern. The daemon polls the chain,
//! downloads specs, executes jobs natively, and submits results via unsigned
//! extrinsics — all in a single binary with zero Substrate dependencies.
//!
//! The OCW was removed because:
//! 1. It raced with the daemon for job execution
//! 2. On execution failure (no localhost:9955 executor), it submitted bogus
//!    result hashes (hash of spec instead of output), corrupting job state
//! 3. The daemon replaces this pattern entirely
//!
//! See `compute-daemon/` for the replacement implementation.
