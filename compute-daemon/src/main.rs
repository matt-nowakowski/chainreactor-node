//! # cr-compute — Chainreactor Compute Daemon
//!
//! Native daemon that runs alongside cr-node on compute marketplace nodes.
//! Watches the chain for assigned jobs via HTTP JSON-RPC polling, executes
//! them on the host machine, and submits results back on-chain via unsigned
//! extrinsics (same mechanism as the OCW, but from a native process).
//!
//! Replaces the OCW+sidecar pattern with a single native binary.
//! Zero Substrate dependencies — uses raw SCALE encoding + HTTP RPC.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use std::process::Command;
use std::time::Duration;
use tracing::{error, info, warn};

mod rpc;
mod scale;

struct Args {
    rpc_url: String,
    account: String,
    heartbeat_interval: u64,
    poll_interval: u64,
    job_timeout: u64,
    result_dir: String,
    result_base_url: String,
}

impl Args {
    fn parse() -> Self {
        let mut args = Args {
            rpc_url: "http://127.0.0.1:9944".to_string(),
            account: String::new(),
            heartbeat_interval: 300,
            poll_interval: 6,
            job_timeout: 300,
            result_dir: "/var/www/results".to_string(),
            result_base_url: "http://127.0.0.1/results".to_string(),
        };

        let raw: Vec<String> = std::env::args().collect();
        let mut i = 1;
        while i < raw.len() {
            match raw[i].as_str() {
                "--rpc-url" => {
                    i += 1;
                    args.rpc_url = raw.get(i).cloned().unwrap_or_default();
                }
                "--account" => {
                    i += 1;
                    args.account = raw.get(i).cloned().unwrap_or_default();
                }
                "--heartbeat-interval" => {
                    i += 1;
                    args.heartbeat_interval = raw.get(i).and_then(|s| s.parse().ok()).unwrap_or(300);
                }
                "--poll-interval" => {
                    i += 1;
                    args.poll_interval = raw.get(i).and_then(|s| s.parse().ok()).unwrap_or(6);
                }
                "--job-timeout" => {
                    i += 1;
                    args.job_timeout = raw.get(i).and_then(|s| s.parse().ok()).unwrap_or(300);
                }
                "--result-dir" => {
                    i += 1;
                    args.result_dir = raw.get(i).cloned().unwrap_or_default();
                }
                "--result-base-url" => {
                    i += 1;
                    args.result_base_url = raw.get(i).cloned().unwrap_or_default();
                }
                "--help" | "-h" => {
                    eprintln!("cr-compute — Chainreactor Compute Daemon\n");
                    eprintln!("Usage: cr-compute --account <SS58_ADDRESS> [OPTIONS]\n");
                    eprintln!("Options:");
                    eprintln!("  --rpc-url <URL>              Node RPC URL [default: http://127.0.0.1:9944]");
                    eprintln!("  --account <SS58>             Worker account SS58 address (required)");
                    eprintln!("  --heartbeat-interval <SECS>  Heartbeat interval [default: 300]");
                    eprintln!("  --poll-interval <SECS>       Job poll interval [default: 6]");
                    eprintln!("  --job-timeout <SECS>         Max job execution time [default: 300]");
                    eprintln!("  --result-dir <PATH>          Directory to save result files [default: /var/www/results]");
                    eprintln!("  --result-base-url <URL>      Base URL for result files [default: http://127.0.0.1/results]");
                    std::process::exit(0);
                }
                other => {
                    eprintln!("Unknown argument: {}", other);
                    std::process::exit(1);
                }
            }
            i += 1;
        }

        // Also check env vars
        if args.account.is_empty() {
            if let Ok(v) = std::env::var("CR_COMPUTE_ACCOUNT") {
                args.account = v;
            }
        }
        if let Ok(v) = std::env::var("CR_COMPUTE_RESULT_DIR") {
            args.result_dir = v;
        }
        if let Ok(v) = std::env::var("CR_COMPUTE_RESULT_BASE_URL") {
            args.result_base_url = v;
        }

        if args.account.is_empty() {
            eprintln!("Error: --account <SS58_ADDRESS> is required");
            std::process::exit(1);
        }

        args
    }
}

/// Compute Blake2b-256 hash (matches Substrate's BlakeTwo256).
fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("valid");
    out
}

/// Job spec from the downloaded JSON.
#[derive(serde::Deserialize, Debug)]
struct JobSpec {
    #[serde(default = "default_type")]
    r#type: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    work_dir: Option<String>,
}

fn default_type() -> String {
    "command".to_string()
}
fn default_timeout() -> u64 {
    300
}

/// Execute a job spec natively on the host.
fn execute_job(spec: &JobSpec, max_timeout: u64) -> (Vec<u8>, bool, String) {
    let timeout = spec.timeout_secs.min(max_timeout);

    match spec.r#type.as_str() {
        "command" => execute_command(spec, timeout),
        "docker" => execute_docker(spec, timeout),
        other => {
            let err = format!("unknown exec type: {}", other);
            error!("{}", err);
            (Vec::new(), false, err)
        }
    }
}

fn execute_command(spec: &JobSpec, _timeout: u64) -> (Vec<u8>, bool, String) {
    info!("  Executing: {} {:?}", spec.command, spec.args);

    let mut cmd = Command::new(&spec.command);
    cmd.args(&spec.args);

    if let Some(ref dir) = spec.work_dir {
        cmd.current_dir(dir);
    }

    match cmd.output() {
        Ok(output) => {
            let stdout = if output.stdout.len() > 1_048_576 {
                output.stdout[..1_048_576].to_vec()
            } else {
                output.stdout
            };

            if output.status.success() {
                info!("  Success: {} bytes output", stdout.len());
                (stdout, true, String::new())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(1000)
                    .collect::<String>();
                warn!("  Failed (exit {:?}): {}", output.status.code(), stderr);
                (stdout, false, stderr)
            }
        }
        Err(e) => {
            let err = format!("execution error: {}", e);
            error!("  {}", err);
            (Vec::new(), false, err)
        }
    }
}

fn execute_docker(spec: &JobSpec, timeout: u64) -> (Vec<u8>, bool, String) {
    info!("  Docker: {} {:?}", spec.command, spec.args);

    let mut docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network=none".to_string(),
        format!("--stop-timeout={}", timeout),
        spec.command.clone(),
    ];
    docker_args.extend(spec.args.iter().cloned());

    match Command::new("docker").args(&docker_args).output() {
        Ok(output) => {
            let stdout = if output.stdout.len() > 1_048_576 {
                output.stdout[..1_048_576].to_vec()
            } else {
                output.stdout
            };

            if output.status.success() {
                info!("  Docker success: {} bytes output", stdout.len());
                (stdout, true, String::new())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(1000)
                    .collect::<String>();
                warn!("  Docker failed: {}", stderr);
                (stdout, false, stderr)
            }
        }
        Err(e) => {
            let err = format!("docker error: {}", e);
            error!("  {}", err);
            (Vec::new(), false, err)
        }
    }
}

/// Download a job spec from a URI.
async fn download_spec(uri: &str) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .get(uri)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("read body failed: {}", e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cr_compute=info".into()),
        )
        .init();

    let args = Args::parse();

    // Decode the worker's public key from SS58
    let worker_pubkey = scale::ss58_decode(&args.account)
        .ok_or_else(|| format!("invalid SS58 address: {}", args.account))?;

    info!("Chainreactor Compute Daemon starting");
    info!("  Worker account: {}", args.account);
    info!("  RPC: {}", args.rpc_url);
    info!("  Heartbeat interval: {}s", args.heartbeat_interval);
    info!("  Poll interval: {}s", args.poll_interval);
    info!("  Result dir: {}", args.result_dir);
    info!("  Result base URL: {}", args.result_base_url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // Wait for node to be ready
    loop {
        match rpc::system_health(&client, &args.rpc_url).await {
            Ok(_) => {
                info!("Connected to chain node");
                break;
            }
            Err(e) => {
                warn!("Node not ready: {} — retrying in 5s", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    // Track in-progress jobs and heartbeat timing
    let mut in_progress: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut last_heartbeat = std::time::Instant::now()
        .checked_sub(Duration::from_secs(args.heartbeat_interval))
        .unwrap_or_else(std::time::Instant::now);

    // Main loop
    loop {
        // 1. Send heartbeat if interval has elapsed
        if last_heartbeat.elapsed() >= Duration::from_secs(args.heartbeat_interval) {
            match rpc::submit_unsigned_heartbeat(&client, &args.rpc_url, &worker_pubkey).await {
                Ok(hash) => {
                    info!("Heartbeat submitted (tx: {})", hash);
                    last_heartbeat = std::time::Instant::now();
                }
                Err(e) => warn!("Heartbeat failed: {}", e),
            }
        }

        // 2. Scan for assigned jobs
        match scan_and_execute(&client, &args, &worker_pubkey, &mut in_progress).await {
            Ok(count) => {
                if count > 0 {
                    info!("Processed {} job(s)", count);
                }
            }
            Err(e) => warn!("Job scan error: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(args.poll_interval)).await;
    }
}

async fn scan_and_execute(
    client: &reqwest::Client,
    args: &Args,
    worker_pubkey: &[u8; 32],
    in_progress: &mut std::collections::HashSet<u64>,
) -> Result<u32, Box<dyn std::error::Error>> {
    // Read NextJobId
    let next_id = rpc::get_next_job_id(client, &args.rpc_url).await?;
    if next_id == 0 {
        return Ok(0);
    }

    let mut executed = 0u32;

    for job_id in 0..next_id {
        if in_progress.contains(&job_id) {
            continue;
        }

        // Fetch job from storage
        let job = match rpc::get_job(client, &args.rpc_url, job_id).await? {
            Some(j) => j,
            None => continue,
        };

        // Only process jobs assigned to us with status=Assigned (1)
        if job.status != 1 {
            continue;
        }
        match job.worker {
            Some(ref w) if w == worker_pubkey => {}
            _ => continue,
        }

        info!("Found assigned job {}", job_id);
        in_progress.insert(job_id);

        // Download spec
        let spec_uri = match String::from_utf8(job.spec_uri.clone()) {
            Ok(uri) => uri,
            Err(_) => {
                error!("Job {} has invalid UTF-8 spec_uri", job_id);
                in_progress.remove(&job_id);
                continue;
            }
        };

        info!("Downloading spec from: {}", spec_uri);
        let spec_bytes = match download_spec(&spec_uri).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to download spec for job {}: {}", job_id, e);
                in_progress.remove(&job_id);
                continue;
            }
        };

        info!("Downloaded spec ({} bytes), executing...", spec_bytes.len());

        let spec: JobSpec = match serde_json::from_slice(&spec_bytes) {
            Ok(s) => s,
            Err(e) => {
                error!("Invalid job spec JSON for job {}: {}", job_id, e);
                // Submit with hash of spec bytes as fallback
                let result_hash = blake2_256(&spec_bytes);
                let result_uri = format!("{}/job-{}.json", args.result_base_url, job_id);
                let _ = rpc::submit_unsigned_result(
                    client,
                    &args.rpc_url,
                    job_id,
                    worker_pubkey,
                    &result_hash,
                    result_uri.as_bytes(),
                )
                .await;
                in_progress.remove(&job_id);
                continue;
            }
        };

        // Execute the job natively
        let (output, success, error_msg) = execute_job(&spec, args.job_timeout);

        if success {
            info!(
                "Job {} executed successfully ({} bytes output)",
                job_id,
                output.len()
            );
        } else {
            warn!("Job {} execution failed: {}", job_id, error_msg);
        }

        // Save output to result file
        let result_filename = format!("job-{}.json", job_id);
        let result_path = format!("{}/{}", args.result_dir, result_filename);
        if let Err(e) = std::fs::create_dir_all(&args.result_dir) {
            error!("Failed to create result dir {}: {}", args.result_dir, e);
        }
        match std::fs::write(&result_path, &output) {
            Ok(()) => info!("Job {} result saved to {}", job_id, result_path),
            Err(e) => error!("Failed to write result file {}: {}", result_path, e),
        }

        // Hash the output
        let result_hash = blake2_256(&output);
        info!("Job {} result hash: 0x{}", job_id, hex::encode(result_hash));

        // Build result URI
        let result_uri = format!("{}/job-{}.json", args.result_base_url, job_id);
        info!("Job {} result URI: {}", job_id, result_uri);

        // Submit result on-chain
        match rpc::submit_unsigned_result(
            client,
            &args.rpc_url,
            job_id,
            worker_pubkey,
            &result_hash,
            result_uri.as_bytes(),
        )
        .await
        {
            Ok(hash) => {
                info!("Job {} result submitted on-chain (tx: {})", job_id, hash);
                executed += 1;
            }
            Err(e) => {
                error!("Failed to submit result for job {}: {}", job_id, e);
            }
        }

        in_progress.remove(&job_id);
    }

    Ok(executed)
}
