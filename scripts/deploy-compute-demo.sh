#!/usr/bin/env bash
set -euo pipefail

# ─── Compute Marketplace Demo Deployment ─────────────────────
# Provisions a single-node dev chain on the cheapest DO droplet
# with the cr-node-compute binary.

DO_TOKEN="${DO_API_TOKEN:?Set DO_API_TOKEN}"
SSH_KEY_ID="49900436"  # HummingbotMM
DROPLET_NAME="cr-compute-demo"
REGION="nyc1"
SIZE="s-1vcpu-2gb"  # $12/mo — 1GB too small for Substrate
IMAGE="ubuntu-22-04-x64"
BINARY_URL="https://github.com/matt-nowakowski/chainreactor-node/releases/download/v1.19.14-compute/cr-node-compute-linux-amd64"
COMPUTE_DAEMON_URL="https://github.com/matt-nowakowski/chainreactor-node/releases/download/v1.19.14-compute/cr-compute-linux-amd64"

echo "=== Creating droplet: $DROPLET_NAME ($SIZE in $REGION) ==="

# Check if droplet already exists
EXISTING=$(curl -s -X GET \
  "https://api.digitalocean.com/v2/droplets?tag_name=compute-demo" \
  -H "Authorization: Bearer $DO_TOKEN" \
  -H "Content-Type: application/json" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for d in data.get('droplets',[]):
    if d['name'] == '$DROPLET_NAME':
        print(d['id'])
        break
" 2>/dev/null || echo "")

if [ -n "$EXISTING" ]; then
  echo "Droplet already exists (ID: $EXISTING). Getting IP..."
  IP=$(curl -s -X GET \
    "https://api.digitalocean.com/v2/droplets/$EXISTING" \
    -H "Authorization: Bearer $DO_TOKEN" | python3 -c "
import json,sys
data = json.load(sys.stdin)
nets = data['droplet']['networks']['v4']
for n in nets:
    if n['type'] == 'public':
        print(n['ip_address'])
        break
")
  echo "IP: $IP"
else
  # Create droplet
  RESPONSE=$(curl -s -X POST \
    "https://api.digitalocean.com/v2/droplets" \
    -H "Authorization: Bearer $DO_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"$DROPLET_NAME\",
      \"region\": \"$REGION\",
      \"size\": \"$SIZE\",
      \"image\": \"$IMAGE\",
      \"ssh_keys\": [\"$SSH_KEY_ID\"],
      \"tags\": [\"compute-demo\"],
      \"backups\": false,
      \"monitoring\": false
    }")

  DROPLET_ID=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin)['droplet']['id'])")
  echo "Created droplet ID: $DROPLET_ID"

  # Wait for IP
  echo "Waiting for droplet to come online..."
  for i in $(seq 1 30); do
    sleep 5
    IP=$(curl -s -X GET \
      "https://api.digitalocean.com/v2/droplets/$DROPLET_ID" \
      -H "Authorization: Bearer $DO_TOKEN" | python3 -c "
import json,sys
data = json.load(sys.stdin)
nets = data['droplet']['networks']['v4']
for n in nets:
    if n['type'] == 'public':
        print(n['ip_address'])
        break
" 2>/dev/null || echo "")
    if [ -n "$IP" ]; then
      echo "Got IP: $IP"
      break
    fi
    echo "  ...waiting ($i/30)"
  done
fi

if [ -z "${IP:-}" ]; then
  echo "ERROR: Could not get droplet IP"
  exit 1
fi

# Wait for SSH
echo "=== Waiting for SSH on $IP ==="
for i in $(seq 1 20); do
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$IP" "echo ok" 2>/dev/null; then
    echo "SSH ready!"
    break
  fi
  echo "  ...waiting for SSH ($i/20)"
  sleep 5
done

echo "=== Installing binary and starting chain ==="

ssh -o StrictHostKeyChecking=no root@"$IP" bash -s -- "$BINARY_URL" "$COMPUTE_DAEMON_URL" "$IP" << 'REMOTE_SCRIPT'
set -euo pipefail
BINARY_URL="$1"
COMPUTE_DAEMON_URL="$2"
PUBLIC_IP="$3"

echo "--- Downloading compute binary ---"
cd /usr/local/bin
wget -q "$BINARY_URL" -O cr-node
chmod +x cr-node

echo "--- Creating systemd service ---"
cat > /etc/systemd/system/cr-node.service << 'EOF'
[Unit]
Description=Chainreactor Compute Marketplace Demo
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cr-node \
  --dev \
  --rpc-external \
  --rpc-cors=all \
  --rpc-methods=unsafe \
  --offchain-worker=never \
  --name "compute-demo-1"
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

echo "--- Starting node ---"
systemctl daemon-reload
systemctl enable cr-node
systemctl restart cr-node

# Wait for node to start
echo "--- Waiting for RPC to come up ---"
for i in $(seq 1 30); do
  if curl -s -X POST http://localhost:9944 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' 2>/dev/null | grep -q "result"; then
    echo "Node is running!"
    break
  fi
  sleep 2
done

echo "--- Node status ---"
curl -s -X POST http://localhost:9944 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}'
echo ""
curl -s -X POST http://localhost:9944 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"system_name","params":[]}'
echo ""

echo "--- Downloading cr-compute daemon ---"
cd /usr/local/bin
wget -q "$COMPUTE_DAEMON_URL" -O cr-compute
chmod +x cr-compute

echo "--- Creating result directory ---"
mkdir -p /var/www/results

echo "--- Creating cr-compute systemd service ---"
cat > /etc/systemd/system/cr-compute.service << 'EOF'
[Unit]
Description=Chainreactor Compute Daemon
After=cr-node.service
Requires=cr-node.service

[Service]
Type=simple
ExecStart=/usr/local/bin/cr-compute \
  --account 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty \
  --rpc-url http://127.0.0.1:9944 \
  --result-dir /var/www/results \
  --result-base-url http://${PUBLIC_IP}/results
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "--- Starting cr-compute daemon ---"
systemctl daemon-reload
systemctl enable cr-compute
systemctl restart cr-compute

REMOTE_SCRIPT

echo ""
echo "============================================"
echo "  Compute Demo Node Live!"
echo "  IP:  $IP"
echo "  RPC: ws://$IP:9944"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Inject worker key:  author_insertKey('cmkt', '//Alice', '<pubkey>')"
echo "  2. Register worker:    computeMarketplace.registerWorker(stake, capabilities)"
echo "  3. Submit a test job:  computeMarketplace.submitJob(...)"
