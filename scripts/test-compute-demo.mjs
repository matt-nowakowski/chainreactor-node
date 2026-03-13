#!/usr/bin/env node
/**
 * Compute Marketplace Demo Test
 *
 * 1. Inject cmkt key for Alice (so OCW identifies her as a worker)
 * 2. Register Alice as a compute worker
 * 3. Fund Bob from Alice
 * 4. Bob submits a job (spec_uri → simple echo command)
 * 5. Alice's OCW auto-accepts... wait — OCW doesn't auto-accept, only auto-executes assigned jobs.
 *    We need Alice to accept the job manually, then OCW executes.
 * 6. Watch for events (ResultSubmitted, JobCompleted)
 */

import { ApiPromise, WsProvider, Keyring } from '/Users/mattnowakowski/Downloads/chainreactor/server/node_modules/@polkadot/api/index.js';
import { cryptoWaitReady } from '/Users/mattnowakowski/Downloads/chainreactor/server/node_modules/@polkadot/util-crypto/index.js';
import { blake2AsHex } from '/Users/mattnowakowski/Downloads/chainreactor/server/node_modules/@polkadot/util-crypto/index.js';

const WS_URL = 'ws://167.99.144.135:9944';
const SPEC_URL = 'http://localhost:8080/test-job.json';

async function main() {
  await cryptoWaitReady();

  console.log('=== Connecting to compute demo chain ===');
  const provider = new WsProvider(WS_URL);
  const api = await ApiPromise.create({ provider });

  const keyring = new Keyring({ type: 'sr25519' });
  const alice = keyring.addFromUri('//Alice');
  const bob = keyring.addFromUri('//Bob');

  console.log(`Alice: ${alice.address}`);
  console.log(`Bob:   ${bob.address}`);

  // Listen for all compute marketplace events
  api.query.system.events((events) => {
    events.forEach(({ event }) => {
      if (event.section === 'computeMarketplace') {
        console.log(`\n📡 EVENT: ${event.section}.${event.method}`);
        console.log(`   Data: ${JSON.stringify(event.data.toHuman())}`);
      }
    });
  });

  // Check current block
  const header = await api.rpc.chain.getHeader();
  console.log(`\nCurrent block: #${header.number}`);

  // ─── Step 1: Inject cmkt key for Alice ───────────────────
  console.log('\n=== Step 1: Inject cmkt key for Alice ===');
  try {
    // Use raw RPC to avoid polkadot.js type encoding issues
    await provider.send('author_insertKey', [
      'cmkt',
      '//Alice',
      '0x' + Buffer.from(alice.publicKey).toString('hex')
    ]);
    console.log('✅ cmkt key injected for Alice');
  } catch (e) {
    console.log(`⚠️  Key injection: ${e.message} (may already exist)`);
  }

  // ─── Step 2: Set MinWorkerStake low for demo ─────────────
  console.log('\n=== Step 2: Set low MinWorkerStake (sudo) ===');
  await sendAndWait(api, api.tx.sudo.sudo(
    api.tx.computeMarketplace.setMinWorkerStake(10_000_000_000n) // 1 TRUU (10 decimals)
  ), alice);
  console.log('✅ MinWorkerStake set to 1 TRUU');

  // Also set challenge bond low
  await sendAndWait(api, api.tx.sudo.sudo(
    api.tx.computeMarketplace.setChallengeBond(5_000_000_000n) // 0.5 TRUU
  ), alice);
  console.log('✅ ChallengeBond set to 0.5 token');

  // Set heartbeat interval high so we don't need immediate heartbeats
  await sendAndWait(api, api.tx.sudo.sudo(
    api.tx.computeMarketplace.setHeartbeatInterval(100000)
  ), alice);
  console.log('✅ HeartbeatInterval set to 100000 blocks');

  // Set challenge period low for demo (10 blocks ~1min instead of 100)
  await sendAndWait(api, api.tx.sudo.sudo(
    api.tx.computeMarketplace.setChallengePeriod(10)
  ), alice);
  console.log('✅ ChallengePeriod set to 10 blocks');

  // ─── Step 3: Register Alice as a worker ──────────────────
  console.log('\n=== Step 3: Register Alice as compute worker ===');
  const capabilities = {
    cpu_cores: 1,
    memory_mb: 2048,
    gpu: 'None',
    storage_mb: 25000,
  };
  const stake = 10_000_000_000n; // 1 TRUU (10 decimals)

  try {
    await sendAndWait(api, api.tx.computeMarketplace.registerWorker(
      stake,
      capabilities
    ), alice);
    console.log('✅ Alice registered as worker');
  } catch (e) {
    console.log(`⚠️  Registration: ${e.message}`);
  }

  // Verify registration
  const workerProfile = await api.query.computeMarketplace.workers(alice.address);
  if (workerProfile.isSome) {
    console.log(`   Profile: ${JSON.stringify(workerProfile.toHuman())}`);
  }

  // ─── Step 4: Fund Bob ────────────────────────────────────
  console.log('\n=== Step 4: Fund Bob from Alice ===');
  const bobBalance = await api.query.system.account(bob.address);
  if (BigInt(bobBalance.data.free.toString()) < 100_000_000_000n) {
    await sendAndWait(api, api.tx.balances.transfer(
      bob.address,
      1_000_000_000_000n // 100 TRUU
    ), alice);
    console.log('✅ Bob funded with 100 tokens');
  } else {
    console.log('✅ Bob already funded');
  }

  // ─── Step 5: Bob submits a job ───────────────────────────
  console.log('\n=== Step 5: Bob submits a compute job ===');
  const specUri = SPEC_URL;
  const specUriBytes = Array.from(Buffer.from(specUri));
  // Hash the spec URI as a placeholder spec_hash
  const specHash = blake2AsHex(specUri, 256);
  const budget = 50_000_000_000n; // 5 TRUU
  const deadlineBlocks = 1000; // ~100 minutes
  const requirements = {
    min_cpu_cores: 1,
    min_memory_mb: 1024,
    gpu_required: 'None',
    min_storage_mb: 1000,
  };

  await sendAndWait(api, api.tx.computeMarketplace.submitJob(
    specHash,
    specUriBytes,
    budget,
    deadlineBlocks,
    requirements
  ), bob);
  console.log('✅ Job submitted');

  // Read the job
  const jobId = (await api.query.computeMarketplace.nextJobId()).toNumber() - 1;
  console.log(`   Job ID: ${jobId}`);
  const job = await api.query.computeMarketplace.jobs(jobId);
  console.log(`   Job: ${JSON.stringify(job.toHuman())}`);

  // ─── Step 6: Alice accepts the job ───────────────────────
  console.log('\n=== Step 6: Alice accepts the job ===');
  await sendAndWait(api, api.tx.computeMarketplace.acceptJob(jobId), alice);
  console.log('✅ Alice accepted the job');

  // Check updated job status
  const jobAfterAccept = await api.query.computeMarketplace.jobs(jobId);
  console.log(`   Status: ${jobAfterAccept.toHuman().status}`);

  // ─── Step 7: Wait for OCW to execute and submit result ───
  console.log('\n=== Step 7: Waiting for OCW to execute job... ===');
  console.log('   (OCW runs each block — watching for ResultSubmitted event)');

  let completed = false;
  for (let i = 0; i < 60; i++) {
    await sleep(6000); // wait ~1 block
    const currentJob = await api.query.computeMarketplace.jobs(jobId);
    const status = currentJob.toHuman().status;
    const currentBlock = (await api.rpc.chain.getHeader()).number.toNumber();
    process.stdout.write(`\r   Block #${currentBlock} — Job status: ${status}   `);

    if (status === 'Submitted' || status === 'Completed') {
      console.log('\n');
      console.log(`✅ Job result submitted! Status: ${status}`);
      console.log(`   Full job: ${JSON.stringify(currentJob.toHuman())}`);
      completed = true;

      if (status === 'Submitted') {
        console.log('\n   Waiting for challenge window to close and auto-complete...');
        // Continue watching
      } else {
        break;
      }
    }

    if (status === 'Completed') {
      completed = true;
      break;
    }
  }

  if (completed) {
    // Check final balances
    const aliceFinal = await api.query.system.account(alice.address);
    const bobFinal = await api.query.system.account(bob.address);
    console.log(`\n=== Final State ===`);
    console.log(`Alice balance: ${aliceFinal.data.free.toHuman()}`);
    console.log(`Bob balance:   ${bobFinal.data.free.toHuman()}`);
    const finalJob = await api.query.computeMarketplace.jobs(jobId);
    console.log(`Job: ${JSON.stringify(finalJob.toHuman())}`);
  } else {
    console.log('\n\n⚠️  Job did not complete within timeout. Checking logs...');
  }

  // Print recent node logs for debugging
  console.log('\n=== Recent node logs (OCW activity) ===');

  await api.disconnect();
}

function sendAndWait(api, tx, signer) {
  return new Promise((resolve, reject) => {
    let unsub;
    tx.signAndSend(signer, ({ status, dispatchError, events }) => {
      if (status.isInBlock) {
        if (dispatchError) {
          if (dispatchError.isModule) {
            const decoded = api.registry.findMetaError(dispatchError.asModule);
            reject(new Error(`${decoded.section}.${decoded.name}: ${decoded.docs}`));
          } else {
            reject(new Error(dispatchError.toString()));
          }
        } else {
          resolve({ blockHash: status.asInBlock, events });
        }
        if (unsub) unsub();
      }
    }).then(u => { unsub = u; }).catch(reject);
  });
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

main().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});
