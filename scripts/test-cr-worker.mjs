#!/usr/bin/env node
/**
 * Test script for cr-worker daemon.
 *
 * Sets up the chain (sudo config, register worker, submit job) but does NOT
 * inject the cmkt key — so the OCW won't execute anything. cr-worker handles it.
 *
 * Steps:
 * 1. Set low config values via sudo
 * 2. Register Alice as a worker
 * 3. Fund Bob
 * 4. Bob submits a job
 * 5. Alice accepts the job
 * 6. Wait for cr-worker to execute and submit the result (NOT the OCW)
 */

import { ApiPromise, WsProvider, Keyring } from '/Users/mattnowakowski/Downloads/chainreactor/server/node_modules/@polkadot/api/index.js';
import { cryptoWaitReady } from '/Users/mattnowakowski/Downloads/chainreactor/server/node_modules/@polkadot/util-crypto/index.js';
import { blake2AsHex } from '/Users/mattnowakowski/Downloads/chainreactor/server/node_modules/@polkadot/util-crypto/index.js';

const WS_URL = 'ws://167.99.144.135:9944';
const SPEC_URL = 'http://localhost:8080/test-job.json';

async function main() {
  await cryptoWaitReady();

  console.log('=== cr-worker Test: Connecting to chain ===');
  const provider = new WsProvider(WS_URL);
  const api = await ApiPromise.create({ provider });

  const keyring = new Keyring({ type: 'sr25519' });
  const alice = keyring.addFromUri('//Alice');
  const bob = keyring.addFromUri('//Bob');

  console.log(`Alice: ${alice.address}`);
  console.log(`Bob:   ${bob.address}`);

  // Listen for compute marketplace events
  api.query.system.events((events) => {
    events.forEach(({ event }) => {
      if (event.section === 'computeMarketplace') {
        console.log(`\n📡 EVENT: ${event.section}.${event.method}`);
        console.log(`   Data: ${JSON.stringify(event.data.toHuman())}`);
      }
    });
  });

  const header = await api.rpc.chain.getHeader();
  console.log(`\nCurrent block: #${header.number}`);

  // NOTE: We do NOT inject cmkt key — the OCW should NOT pick up jobs.
  // cr-worker will handle execution instead.
  console.log('\n⚠️  NO cmkt key injected — OCW will not execute jobs');
  console.log('   cr-worker daemon will handle execution\n');

  // ─── Sudo config ───
  console.log('=== Setting up sudo config ===');
  await sendAndWait(api, api.tx.sudo.sudo(
    api.tx.computeMarketplace.setMinWorkerStake(10_000_000_000n)
  ), alice);
  console.log('✅ MinWorkerStake set to 1 TRUU');

  await sendAndWait(api, api.tx.sudo.sudo(
    api.tx.computeMarketplace.setChallengeBond(5_000_000_000n)
  ), alice);
  console.log('✅ ChallengeBond set to 0.5 TRUU');

  await sendAndWait(api, api.tx.sudo.sudo(
    api.tx.computeMarketplace.setHeartbeatInterval(100000)
  ), alice);
  console.log('✅ HeartbeatInterval set to 100000 blocks');

  await sendAndWait(api, api.tx.sudo.sudo(
    api.tx.computeMarketplace.setChallengePeriod(10)
  ), alice);
  console.log('✅ ChallengePeriod set to 10 blocks');

  // ─── Register Alice as worker ───
  console.log('\n=== Register Alice as compute worker ===');
  try {
    await sendAndWait(api, api.tx.computeMarketplace.registerWorker(
      10_000_000_000n,
      { cpu_cores: 1, memory_mb: 2048, gpu: 'None', storage_mb: 25000 }
    ), alice);
    console.log('✅ Alice registered as worker');
  } catch (e) {
    console.log(`⚠️  Registration: ${e.message}`);
  }

  // ─── Fund Bob ───
  console.log('\n=== Fund Bob ===');
  const bobBalance = await api.query.system.account(bob.address);
  if (BigInt(bobBalance.data.free.toString()) < 100_000_000_000n) {
    await sendAndWait(api, api.tx.balances.transfer(bob.address, 1_000_000_000_000n), alice);
    console.log('✅ Bob funded');
  } else {
    console.log('✅ Bob already funded');
  }

  // ─── Bob submits a job ───
  console.log('\n=== Bob submits a job ===');
  const specUri = SPEC_URL;
  const specUriBytes = Array.from(Buffer.from(specUri));
  const specHash = blake2AsHex(specUri, 256);
  const budget = 50_000_000_000n;
  const deadlineBlocks = 1000;

  await sendAndWait(api, api.tx.computeMarketplace.submitJob(
    specHash, specUriBytes, budget, deadlineBlocks,
    { min_cpu_cores: 1, min_memory_mb: 1024, gpu_required: 'None', min_storage_mb: 1000 }
  ), bob);
  console.log('✅ Job submitted');

  const jobId = (await api.query.computeMarketplace.nextJobId()).toNumber() - 1;
  console.log(`   Job ID: ${jobId}`);

  // ─── Alice accepts the job ───
  console.log('\n=== Alice accepts the job ===');
  await sendAndWait(api, api.tx.computeMarketplace.acceptJob(jobId), alice);
  console.log('✅ Alice accepted the job');
  console.log('   Status: Assigned');

  // ─── Wait for cr-worker to execute ───
  console.log('\n=== Waiting for cr-worker to execute and submit result ===');
  console.log('   (cr-worker polls every 6s — watching for ResultSubmitted event)\n');

  let completed = false;
  for (let i = 0; i < 60; i++) {
    await sleep(6000);
    const currentJob = await api.query.computeMarketplace.jobs(jobId);
    const status = currentJob.toHuman().status;
    const currentBlock = (await api.rpc.chain.getHeader()).number.toNumber();
    process.stdout.write(`\r   Block #${currentBlock} — Job status: ${status}   `);

    if (status === 'Completed') {
      console.log('\n');
      console.log('✅ Job COMPLETED!');
      console.log(`   Full job: ${JSON.stringify(currentJob.toHuman())}`);
      completed = true;
      break;
    }

    if (status === 'Submitted' && !completed) {
      console.log('\n');
      console.log('✅ Result submitted by cr-worker! Waiting for challenge window...');
    }
  }

  if (completed) {
    const aliceFinal = await api.query.system.account(alice.address);
    const bobFinal = await api.query.system.account(bob.address);
    console.log(`\n=== Final State ===`);
    console.log(`Alice balance: ${aliceFinal.data.free.toHuman()}`);
    console.log(`Bob balance:   ${bobFinal.data.free.toHuman()}`);
  } else {
    console.log('\n\n⚠️  Job did not complete within timeout');
  }

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
