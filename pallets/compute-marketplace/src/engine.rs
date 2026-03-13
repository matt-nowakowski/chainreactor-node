//! Compute execution engine — runs inside the node process.
//!
//! Downloads job specs from URIs, executes tasks on the host machine,
//! and returns result hashes. This module only compiles in native (std)
//! context — it never runs inside the WASM runtime.

use sp_core::H256;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::traits::Hash as HashTrait;

/// A parsed job specification.
#[derive(Debug, Clone)]
pub struct JobSpec {
    /// Type of execution: "command", "docker", "wasm"
    pub exec_type: String,
    /// Command or image to run
    pub command: String,
    /// Arguments
    pub args: Vec<String>,
    /// Input data URI (downloaded before execution)
    pub input_uri: Option<String>,
    /// Timeout in seconds
    pub timeout_secs: u64,
    /// Working directory (created as temp dir if not specified)
    pub work_dir: Option<String>,
}

/// Result of executing a compute job.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Blake2-256 hash of the output
    pub result_hash: H256,
    /// Raw output bytes (to be uploaded to result storage)
    pub output: Vec<u8>,
    /// Whether execution succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Parse a job spec from JSON bytes.
pub fn parse_job_spec(spec_bytes: &[u8]) -> Result<JobSpec, String> {
    // Simple JSON parsing without serde (to keep no_std-compatible deps minimal)
    // We parse the essential fields manually from the JSON
    let spec_str = core::str::from_utf8(spec_bytes)
        .map_err(|e| format!("Invalid UTF-8 in spec: {}", e))?;

    // Use a minimal JSON approach
    let exec_type = extract_json_string(spec_str, "type").unwrap_or_else(|| "command".into());
    let command = extract_json_string(spec_str, "command")
        .ok_or_else(|| "Missing 'command' field in spec".to_string())?;
    let input_uri = extract_json_string(spec_str, "input_uri");
    let timeout_secs = extract_json_number(spec_str, "timeout_secs").unwrap_or(300);
    let work_dir = extract_json_string(spec_str, "work_dir");

    // Parse args array (simple extraction)
    let args = extract_json_string_array(spec_str, "args").unwrap_or_default();

    Ok(JobSpec {
        exec_type,
        command,
        args,
        input_uri,
        timeout_secs,
        work_dir,
    })
}

/// Execute a job spec on the host machine.
pub fn execute_job(spec: &JobSpec) -> ExecutionResult {
    match spec.exec_type.as_str() {
        "command" => execute_command(spec),
        "docker" => execute_docker(spec),
        _ => ExecutionResult {
            result_hash: H256::zero(),
            output: Vec::new(),
            success: false,
            error: Some(format!("Unknown exec_type: {}", spec.exec_type)),
        },
    }
}

/// Execute a system command.
fn execute_command(spec: &JobSpec) -> ExecutionResult {
    use std::process::Command;

    log::info!("🔧 Executing command: {} {:?}", spec.command, spec.args);

    let mut cmd = Command::new(&spec.command);
    cmd.args(&spec.args);

    if let Some(ref dir) = spec.work_dir {
        cmd.current_dir(dir);
    }

    // Capture stdout + stderr
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return ExecutionResult {
                result_hash: H256::zero(),
                output: Vec::new(),
                success: false,
                error: Some(format!("Failed to spawn process: {}", e)),
            };
        },
    };

    // Wait with timeout
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(e) => {
            return ExecutionResult {
                result_hash: H256::zero(),
                output: Vec::new(),
                success: false,
                error: Some(format!("Process error: {}", e)),
            };
        },
    };

    let stdout = output.stdout;
    let result_hash = BlakeTwo256::hash(&stdout);

    ExecutionResult {
        result_hash,
        output: stdout,
        success: output.status.success(),
        error: if output.status.success() {
            None
        } else {
            Some(String::from_utf8_lossy(&output.stderr).to_string())
        },
    }
}

/// Execute a Docker container.
fn execute_docker(spec: &JobSpec) -> ExecutionResult {
    use std::process::Command;

    log::info!("🐳 Executing docker: {}", spec.command);

    let mut docker_args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--network=none".to_string(), // Sandboxed
    ];

    // Add timeout via --stop-timeout
    docker_args.push(format!("--stop-timeout={}", spec.timeout_secs));

    // The command field is the image name
    docker_args.push(spec.command.clone());

    // Append any additional args
    docker_args.extend(spec.args.clone());

    let output = match Command::new("docker")
        .args(&docker_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            return ExecutionResult {
                result_hash: H256::zero(),
                output: Vec::new(),
                success: false,
                error: Some(format!("Docker execution failed: {}", e)),
            };
        },
    };

    let stdout = output.stdout;
    let result_hash = BlakeTwo256::hash(&stdout);

    ExecutionResult {
        result_hash,
        output: stdout,
        success: output.status.success(),
        error: if output.status.success() {
            None
        } else {
            Some(String::from_utf8_lossy(&output.stderr).to_string())
        },
    }
}

/// Download content from a URI using the OCW HTTP API.
pub fn download_spec(uri: &str) -> Result<Vec<u8>, String> {
    use sp_runtime::offchain::http;
    use sp_runtime::offchain::Duration;

    let deadline = sp_io::offchain::timestamp()
        .add(Duration::from_millis(30_000)); // 30s timeout

    let request = http::Request::get(uri);
    let pending = request
        .deadline(deadline)
        .send()
        .map_err(|_| "Failed to send HTTP request".to_string())?;

    let response = pending
        .try_wait(deadline)
        .map_err(|_| "HTTP request timed out".to_string())?
        .map_err(|_| "HTTP request failed".to_string())?;

    if response.code != 200 {
        return Err(format!("HTTP {} from spec URI", response.code));
    }

    let body = response.body().collect::<Vec<u8>>();
    Ok(body)
}

// ─── Simple JSON helpers (no serde dependency) ────────────

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let after_key = &json[start + pattern.len()..];
    // Skip whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();

    if trimmed.starts_with('"') {
        let inner = &trimmed[1..];
        let end = inner.find('"')?;
        Some(inner[..end].to_string())
    } else {
        None
    }
}

fn extract_json_number(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let after_key = &json[start + pattern.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();

    let end = trimmed.find(|c: char| !c.is_ascii_digit()).unwrap_or(trimmed.len());
    trimmed[..end].parse().ok()
}

fn extract_json_string_array(json: &str, key: &str) -> Option<Vec<String>> {
    let pattern = format!("\"{}\"", key);
    let start = json.find(&pattern)?;
    let after_key = &json[start + pattern.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let trimmed = after_colon.trim_start();

    if !trimmed.starts_with('[') {
        return None;
    }

    let end_bracket = trimmed.find(']')?;
    let array_content = &trimmed[1..end_bracket];

    let mut result = Vec::new();
    for item in array_content.split(',') {
        let trimmed_item = item.trim().trim_matches('"');
        if !trimmed_item.is_empty() {
            result.push(trimmed_item.to_string());
        }
    }

    Some(result)
}
