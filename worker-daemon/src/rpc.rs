//! Raw HTTP JSON-RPC client for Substrate node communication.
//!
//! Constructs storage keys, decodes responses, and builds unsigned
//! extrinsics without any Substrate crate dependencies.

use crate::scale;
use parity_scale_codec::{Compact, Encode};
use serde_json::{json, Value};
use tracing::error;

/// Decoded job from chain storage.
#[derive(Debug)]
pub struct RawJob {
    pub status: u8,
    pub worker: Option<[u8; 32]>,
    pub spec_uri: Vec<u8>,
}

/// Make a JSON-RPC call.
async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });

    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("RPC request failed: {}", e))?;

    let json: Value = resp
        .json()
        .await
        .map_err(|e| format!("RPC response parse failed: {}", e))?;

    if let Some(error) = json.get("error") {
        return Err(format!("RPC error: {}", error));
    }

    Ok(json)
}

/// Check if the node is healthy.
pub async fn system_health(
    client: &reqwest::Client,
    url: &str,
) -> Result<(), String> {
    rpc_call(client, url, "system_health", json!([])).await?;
    Ok(())
}

/// Fetch a storage value by hex-encoded key.
async fn get_storage(
    client: &reqwest::Client,
    url: &str,
    storage_key: &str,
) -> Result<Option<Vec<u8>>, String> {
    let resp = rpc_call(client, url, "state_getStorage", json!([storage_key])).await?;

    match resp.get("result") {
        Some(Value::String(hex)) => {
            let bytes = hex::decode(hex.trim_start_matches("0x"))
                .map_err(|e| format!("hex decode: {}", e))?;
            Ok(Some(bytes))
        }
        Some(Value::Null) | None => Ok(None),
        _ => Err("unexpected storage result type".into()),
    }
}

/// Get NextJobId from storage.
pub async fn get_next_job_id(
    client: &reqwest::Client,
    url: &str,
) -> Result<u64, String> {
    // Storage key: twox128("ComputeMarketplace") ++ twox128("NextJobId")
    let key = format!(
        "0x{}{}",
        hex::encode(scale::twox128(b"ComputeMarketplace")),
        hex::encode(scale::twox128(b"NextJobId")),
    );

    match get_storage(client, url, &key).await? {
        Some(bytes) => {
            if bytes.len() >= 8 {
                Ok(u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            } else {
                Ok(0)
            }
        }
        None => Ok(0),
    }
}

/// Fetch and decode a job from storage.
pub async fn get_job(
    client: &reqwest::Client,
    url: &str,
    job_id: u64,
) -> Result<Option<RawJob>, String> {
    // Storage key: twox128("ComputeMarketplace") ++ twox128("Jobs") ++ blake2_128_concat(job_id)
    let job_id_encoded = job_id.to_le_bytes();
    let hash = scale::blake2_128(&job_id_encoded);
    let key = format!(
        "0x{}{}{}{}",
        hex::encode(scale::twox128(b"ComputeMarketplace")),
        hex::encode(scale::twox128(b"Jobs")),
        hex::encode(hash),
        hex::encode(job_id_encoded),
    );

    let bytes = match get_storage(client, url, &key).await? {
        Some(b) => b,
        None => return Ok(None),
    };

    // Decode the Job struct from SCALE
    decode_job(&bytes)
}

/// Decode a Job from raw SCALE bytes.
fn decode_job(data: &[u8]) -> Result<Option<RawJob>, String> {
    let mut pos = 0;

    // requester: AccountId32 (32 bytes)
    if data.len() < pos + 32 {
        return Ok(None);
    }
    pos += 32;

    // spec_hash: H256 (32 bytes)
    if data.len() < pos + 32 {
        return Ok(None);
    }
    pos += 32;

    // spec_uri: BoundedVec<u8> (compact length + bytes)
    let (uri_len, bytes_read) = scale::decode_compact_u32(&data[pos..])
        .ok_or("failed to decode spec_uri length")?;
    pos += bytes_read;
    if data.len() < pos + uri_len as usize {
        return Ok(None);
    }
    let spec_uri = data[pos..pos + uri_len as usize].to_vec();
    pos += uri_len as usize;

    // budget: u128 (16 bytes)
    if data.len() < pos + 16 {
        return Ok(None);
    }
    pos += 16;

    // status: enum u8
    if data.len() < pos + 1 {
        return Ok(None);
    }
    let status = data[pos];
    pos += 1;

    // worker: Option<AccountId32>
    if data.len() < pos + 1 {
        return Ok(None);
    }
    let worker = match data[pos] {
        0 => {
            pos += 1;
            None
        }
        1 => {
            pos += 1;
            if data.len() < pos + 32 {
                return Ok(None);
            }
            let mut w = [0u8; 32];
            w.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Some(w)
        }
        _ => return Ok(None),
    };

    Ok(Some(RawJob {
        status,
        worker,
        spec_uri,
    }))
}

/// Submit an unsigned heartbeat extrinsic.
pub async fn submit_unsigned_heartbeat(
    client: &reqwest::Client,
    url: &str,
    worker_pubkey: &[u8; 32],
) -> Result<String, String> {
    // Call data: pallet_index(52) + call_index(18) + worker(AccountId32)
    let mut call_data = Vec::new();
    call_data.push(52u8); // ComputeMarketplace pallet index
    call_data.push(18u8); // unsigned_heartbeat call index
    call_data.extend_from_slice(worker_pubkey); // worker: AccountId32

    submit_unsigned_extrinsic(client, url, &call_data).await
}

/// Submit an unsigned result extrinsic.
pub async fn submit_unsigned_result(
    client: &reqwest::Client,
    url: &str,
    job_id: u64,
    worker_pubkey: &[u8; 32],
    result_hash: &[u8; 32],
    result_uri: &[u8],
) -> Result<String, String> {
    // Call data: pallet_index(52) + call_index(19) + job_id(u64) + worker(AccountId32)
    //            + result_hash(H256) + result_uri(Vec<u8>)
    let mut call_data = Vec::new();
    call_data.push(52u8); // ComputeMarketplace pallet index
    call_data.push(19u8); // unsigned_submit_result call index
    call_data.extend_from_slice(&job_id.to_le_bytes()); // job_id: u64
    call_data.extend_from_slice(worker_pubkey); // worker: AccountId32
    call_data.extend_from_slice(result_hash); // result_hash: H256

    // result_uri: Vec<u8> — compact-encoded length + bytes
    Compact(result_uri.len() as u32).encode_to(&mut call_data);
    call_data.extend_from_slice(result_uri);

    submit_unsigned_extrinsic(client, url, &call_data).await
}

/// Build and submit an unsigned extrinsic (V4 format).
async fn submit_unsigned_extrinsic(
    client: &reqwest::Client,
    url: &str,
    call_data: &[u8],
) -> Result<String, String> {
    // Unsigned extrinsic V4 format:
    //   compact_length_prefix + version_byte(0x04) + call_data
    //
    // Version byte 0x04 = V4, unsigned (bit 7 = 0)
    let mut extrinsic = Vec::new();
    let inner_len = 1 + call_data.len(); // version byte + call
    Compact(inner_len as u32).encode_to(&mut extrinsic);
    extrinsic.push(0x04); // V4 unsigned
    extrinsic.extend_from_slice(call_data);

    let hex_ext = format!("0x{}", hex::encode(&extrinsic));

    let resp = rpc_call(
        client,
        url,
        "author_submitExtrinsic",
        json!([hex_ext]),
    )
    .await?;

    match resp.get("result") {
        Some(Value::String(hash)) => Ok(hash.clone()),
        _ => {
            error!("Unexpected submit response: {:?}", resp);
            Err(format!("submit failed: {:?}", resp))
        }
    }
}
