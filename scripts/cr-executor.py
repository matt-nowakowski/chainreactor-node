#!/usr/bin/env python3
"""
Chainreactor Compute Executor Service

Lightweight HTTP server that runs on the same machine as the node.
The OCW (running in WASM) sends job specs here via HTTP POST.
This service executes them natively and returns the Blake2-256 hash + output.

Listens on localhost:9955 (not exposed externally).
"""

import hashlib
import json
import subprocess
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9955
MAX_OUTPUT_SIZE = 1024 * 1024  # 1MB max output


def blake2_256(data: bytes) -> bytes:
    """Compute Blake2b-256 hash (matches Substrate's BlakeTwo256)."""
    return hashlib.blake2b(data, digest_size=32).digest()


def execute_command(spec: dict) -> tuple[bytes, bytes, bool, str]:
    """Execute a command spec. Returns (hash, output, success, error)."""
    command = spec.get("command", "")
    args = spec.get("args", [])
    timeout = spec.get("timeout_secs", 300)
    work_dir = spec.get("work_dir")

    print(f"  Executing: {command} {args}", flush=True)

    try:
        result = subprocess.run(
            [command] + args,
            capture_output=True,
            timeout=timeout,
            cwd=work_dir,
        )
        stdout = result.stdout[:MAX_OUTPUT_SIZE]
        result_hash = blake2_256(stdout)

        if result.returncode == 0:
            print(f"  Success: {len(stdout)} bytes output", flush=True)
            return result_hash, stdout, True, ""
        else:
            stderr = result.stderr.decode("utf-8", errors="replace")[:1000]
            print(f"  Failed (exit {result.returncode}): {stderr}", flush=True)
            return result_hash, stdout, False, stderr

    except subprocess.TimeoutExpired:
        print(f"  Timeout after {timeout}s", flush=True)
        return blake2_256(b""), b"", False, "timeout"
    except FileNotFoundError:
        print(f"  Command not found: {command}", flush=True)
        return blake2_256(b""), b"", False, f"command not found: {command}"
    except Exception as e:
        print(f"  Error: {e}", flush=True)
        return blake2_256(b""), b"", False, str(e)


def execute_docker(spec: dict) -> tuple[bytes, bytes, bool, str]:
    """Execute a Docker container spec."""
    image = spec.get("command", "")
    args = spec.get("args", [])
    timeout = spec.get("timeout_secs", 300)

    print(f"  Docker: {image} {args}", flush=True)

    docker_args = [
        "docker", "run", "--rm",
        "--network=none",
        f"--stop-timeout={timeout}",
        image,
    ] + args

    try:
        result = subprocess.run(
            docker_args,
            capture_output=True,
            timeout=timeout + 10,
        )
        stdout = result.stdout[:MAX_OUTPUT_SIZE]
        result_hash = blake2_256(stdout)

        if result.returncode == 0:
            print(f"  Success: {len(stdout)} bytes output", flush=True)
            return result_hash, stdout, True, ""
        else:
            stderr = result.stderr.decode("utf-8", errors="replace")[:1000]
            print(f"  Failed: {stderr}", flush=True)
            return result_hash, stdout, False, stderr

    except Exception as e:
        print(f"  Docker error: {e}", flush=True)
        return blake2_256(b""), b"", False, str(e)


class ExecutorHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/execute":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        print(f"\n[Execute] Received {len(body)} bytes", flush=True)

        try:
            spec = json.loads(body)
        except json.JSONDecodeError as e:
            print(f"  Invalid JSON: {e}", flush=True)
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        exec_type = spec.get("type", "command")

        if exec_type == "command":
            result_hash, output, success, error = execute_command(spec)
        elif exec_type == "docker":
            result_hash, output, success, error = execute_docker(spec)
        else:
            print(f"  Unknown type: {exec_type}", flush=True)
            result_hash = blake2_256(b"")
            output = b""
            success = False
            error = f"unknown exec_type: {exec_type}"

        # Response: 32 bytes hash + output bytes
        response_body = result_hash + output

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("X-Success", "true" if success else "false")
        if error:
            self.send_header("X-Error", error[:200])
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        # Suppress default access logs
        pass


def main():
    print(f"🔧 Chainreactor Compute Executor starting on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), ExecutorHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down executor.", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
