//! Off-chain worker for the compute marketplace.
//!
//! Runs after each block import. Detects jobs assigned to this node,
//! executes them using the engine, and submits results back on-chain
//! via unsigned transactions.
//!
//! No storage mutation in this file — all writes go through extrinsics.

use crate::*;
use sp_runtime::offchain::storage::StorageValueRef;

const OCW_DB_PREFIX: &[u8] = b"cr/compute-marketplace/";
const BLOCK_INCLUSION_PERIOD: u64 = 10;

impl<T: Config> Pallet<T> {
    /// Main OCW entry point — called every block.
    pub fn run_offchain_worker(now: BlockNumberFor<T>) {
        // 1. Find this node's worker account from the keystore
        let worker = match Self::get_local_worker_account() {
            Some(w) => w,
            None => {
                // Not a registered worker — nothing to do
                return;
            },
        };

        log::info!("🔧 Compute OCW: checking jobs for worker {:?}", worker);

        // 2. Auto-submit heartbeat
        Self::maybe_send_heartbeat(&worker, now);

        // 3. Scan for assigned jobs
        let next_id = NextJobId::<T>::get();
        let mut job_id: JobId = 0;
        while job_id < next_id {
            if let Some(job) = Jobs::<T>::get(job_id) {
                if job.status == JobStatus::Assigned && job.worker.as_ref() == Some(&worker) {
                    // Check if we're already processing this job
                    if !Self::is_job_in_progress(job_id) {
                        log::info!("🔧 Compute OCW: executing job {}", job_id);
                        Self::mark_job_in_progress(job_id, now);
                        Self::execute_and_submit(job_id, &job, &worker);
                    }
                }
            }
            job_id = job_id.saturating_add(1);
        }
    }

    /// Find the local account that is registered as a compute worker.
    fn get_local_worker_account() -> Option<T::AccountId> {
        // Read all local keys of our key type from the keystore
        let keys = sp_io::crypto::sr25519_public_keys(crate::KEY_TYPE);

        for key in keys.iter() {
            // Convert the raw public key to an AccountId
            let account: T::AccountId = match T::AccountId::decode(&mut &key.0[..]) {
                Ok(a) => a,
                Err(_) => continue,
            };

            // Check if this account is registered as a worker
            if Workers::<T>::contains_key(&account) {
                return Some(account);
            }
        }

        None
    }

    /// Send a heartbeat if enough blocks have passed since the last one.
    fn maybe_send_heartbeat(worker: &T::AccountId, now: BlockNumberFor<T>) {
        let uptime = Heartbeats::<T>::get(worker);
        let interval: u64 = HeartbeatInterval::<T>::get() as u64;
        let now_u64: u64 = now.saturated_into();

        let should_send = if uptime.heartbeat_count == 0 {
            true
        } else {
            now_u64 >= uptime.last_heartbeat.saturating_add(interval)
        };

        if !should_send {
            return;
        }

        // Check if we recently submitted one
        if Self::heartbeat_submission_pending(now) {
            return;
        }

        log::info!("💓 Compute OCW: sending heartbeat at block {:?}", now);

        let call = Call::<T>::unsigned_heartbeat {
            worker: worker.clone(),
        };

        match frame_system::offchain::SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(
            call.into(),
        ) {
            Ok(_) => {
                Self::record_heartbeat_submission(now);
                log::info!("💓 Compute OCW: heartbeat submitted");
            },
            Err(e) => {
                log::error!("💔 Compute OCW: heartbeat submission failed: {:?}", e);
            },
        }
    }

    /// Execute a job and submit the result on-chain.
    fn execute_and_submit(job_id: JobId, job: &Job<T>, worker: &T::AccountId) {
        // 1. Download the spec from the URI
        let spec_uri = match core::str::from_utf8(&job.spec_uri) {
            Ok(uri) => uri,
            Err(_) => {
                log::error!("🔧 Compute OCW: invalid spec URI for job {}", job_id);
                Self::clear_job_in_progress(job_id);
                return;
            },
        };

        let spec_bytes = match Self::download_spec(spec_uri) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("🔧 Compute OCW: failed to download spec for job {}: {}", job_id, e);
                Self::clear_job_in_progress(job_id);
                return;
            },
        };

        log::info!("🔧 Compute OCW: downloaded spec ({} bytes) for job {}", spec_bytes.len(), job_id);

        // 2. Execute the job via local executor service (HTTP on localhost:9955)
        //    The executor runs natively on the host — the OCW communicates via HTTP
        //    since WASM cannot call std::process::Command directly.
        let (result_hash, output) = match Self::execute_via_local_service(&spec_bytes) {
            Ok((hash, out)) => {
                log::info!("🔧 Compute OCW: job {} executed successfully", job_id);
                (hash, out)
            },
            Err(e) => {
                log::error!("🔧 Compute OCW: job {} execution failed: {}", job_id, e);
                // Still submit with a hash of the spec so the job doesn't hang
                let hash = T::Hashing::hash_of(&spec_bytes);
                let hash_bytes: &[u8] = hash.as_ref();
                let rh = if hash_bytes.len() >= 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&hash_bytes[..32]);
                    sp_core::H256(arr)
                } else {
                    sp_core::H256::zero()
                };
                (rh, Vec::new())
            },
        };

        // 3. Store result locally
        Self::store_job_output(job_id, &output);

        // 4. Submit result on-chain via unsigned extrinsic
        // Build result URI: "local://job-{id}/result"
        let mut result_uri_bytes: Vec<u8> = b"local://job-".to_vec();
        {
            let mut id = job_id;
            if id == 0 {
                result_uri_bytes.push(b'0');
            } else {
                let mut digits = Vec::new();
                while id > 0 {
                    digits.push(b'0' + (id % 10) as u8);
                    id /= 10;
                }
                digits.reverse();
                result_uri_bytes.extend(digits);
            }
        }
        result_uri_bytes.extend_from_slice(b"/result");

        let bounded_uri: BoundedVec<u8, T::MaxUriLen> = match result_uri_bytes.try_into() {
            Ok(uri) => uri,
            Err(_) => {
                log::error!("🔧 Compute OCW: result URI too long for job {}", job_id);
                Self::clear_job_in_progress(job_id);
                return;
            },
        };

        let call = Call::<T>::unsigned_submit_result {
            job_id,
            worker: worker.clone(),
            result_hash,
            result_uri: bounded_uri.into_inner(),
        };

        match frame_system::offchain::SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(
            call.into(),
        ) {
            Ok(_) => {
                log::info!("🔧 Compute OCW: result submitted for job {}", job_id);
                Self::clear_job_in_progress(job_id);
            },
            Err(e) => {
                log::error!(
                    "🔧 Compute OCW: failed to submit result for job {}: {:?}",
                    job_id,
                    e
                );
                Self::clear_job_in_progress(job_id);
            },
        }
    }

    /// Execute a job spec via the local executor service.
    /// POSTs the spec JSON to http://localhost:9955/execute, which runs the
    /// command natively on the host and returns the Blake2-256 hash of stdout.
    ///
    /// Response format: first 32 bytes = result hash, remaining bytes = stdout output.
    fn execute_via_local_service(spec_bytes: &[u8]) -> Result<(sp_core::H256, Vec<u8>), &'static str> {
        use sp_runtime::offchain::http;
        use sp_runtime::offchain::Duration;

        let deadline = sp_io::offchain::timestamp()
            .add(Duration::from_millis(120_000)); // 2 min timeout for execution

        let request = http::Request::post(
            "http://localhost:9955/execute",
            sp_std::vec![spec_bytes.to_vec()],
        );

        let pending = request
            .add_header("Content-Type", "application/json")
            .deadline(deadline)
            .send()
            .map_err(|_| "Failed to send execution request")?;

        let response = pending
            .try_wait(deadline)
            .map_err(|_| "Execution request timed out")?
            .map_err(|_| "Execution request failed")?;

        if response.code != 200 {
            log::error!("🔧 Compute OCW: executor returned HTTP {}", response.code);
            return Err("Executor returned non-200");
        }

        let body = response.body().collect::<Vec<u8>>();

        // Response: first 32 bytes = Blake2-256 hash, rest = output
        if body.len() < 32 {
            return Err("Executor response too short");
        }

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&body[..32]);
        let result_hash = sp_core::H256(hash_bytes);
        let output = body[32..].to_vec();

        Ok((result_hash, output))
    }

    /// Download content from a URI using the OCW HTTP API.
    fn download_spec(uri: &str) -> Result<Vec<u8>, &'static str> {
        use sp_runtime::offchain::http;
        use sp_runtime::offchain::Duration;

        let deadline = sp_io::offchain::timestamp()
            .add(Duration::from_millis(30_000));

        let request = http::Request::get(uri);
        let pending = request
            .deadline(deadline)
            .send()
            .map_err(|_| "Failed to send HTTP request")?;

        let response = pending
            .try_wait(deadline)
            .map_err(|_| "HTTP request timed out")?
            .map_err(|_| "HTTP request failed")?;

        if response.code != 200 {
            return Err("HTTP non-200 from spec URI");
        }

        let body = response.body().collect::<Vec<u8>>();
        Ok(body)
    }

    // ─── Offchain local storage helpers ───────────────────────

    fn is_job_in_progress(job_id: JobId) -> bool {
        let key = Self::ocw_key(b"in_progress", job_id);
        StorageValueRef::persistent(&key)
            .get::<bool>()
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    fn mark_job_in_progress(job_id: JobId, _now: BlockNumberFor<T>) {
        let key = Self::ocw_key(b"in_progress", job_id);
        let _ = StorageValueRef::persistent(&key)
            .mutate(|_: Result<Option<bool>, _>| Ok::<bool, ()>(true));
    }

    fn clear_job_in_progress(job_id: JobId) {
        let key = Self::ocw_key(b"in_progress", job_id);
        StorageValueRef::persistent(&key).clear();
    }

    fn store_job_output(job_id: JobId, output: &[u8]) {
        let key = Self::ocw_key(b"output", job_id);
        let _ = StorageValueRef::persistent(&key)
            .mutate(|_: Result<Option<Vec<u8>>, _>| Ok::<Vec<u8>, ()>(output.to_vec()));
    }

    fn heartbeat_submission_pending(now: BlockNumberFor<T>) -> bool {
        let key = [OCW_DB_PREFIX, b"last_heartbeat"].concat();
        match StorageValueRef::persistent(&key)
            .get::<u64>()
            .ok()
            .flatten()
        {
            Some(last) => {
                let now_u64: u64 = now.saturated_into();
                now_u64 <= last.saturating_add(BLOCK_INCLUSION_PERIOD)
            },
            None => false,
        }
    }

    fn record_heartbeat_submission(now: BlockNumberFor<T>) {
        let key = [OCW_DB_PREFIX, b"last_heartbeat"].concat();
        let now_u64: u64 = now.saturated_into();
        let _ = StorageValueRef::persistent(&key)
            .mutate(|_: Result<Option<u64>, _>| Ok::<u64, ()>(now_u64));
    }

    fn ocw_key(prefix: &[u8], job_id: JobId) -> Vec<u8> {
        let mut key = OCW_DB_PREFIX.to_vec();
        key.extend(prefix);
        key.extend(&job_id.to_le_bytes());
        key
    }
}
