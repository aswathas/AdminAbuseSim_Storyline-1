/**
 * exportRaw.js — Collects raw blockchain evidence from Anvil.
 *
 * Gathers: transactions, receipts, blocks, traces, internal calls,
 *          state diffs, ABI, contract metadata, event signatures,
 *          and ground-truth attack markers.
 *
 * Supports multiple attacks — classifies each large mint + subsequent
 * staging/exit transfers as separate attack cycles.
 *
 * Usage:  node detector/exportRaw.js
 */
import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import { ACCOUNTS, PATHS, RPC_URL, SELECTORS, TOPICS } from './config.js';

// ─── Helpers ────────────────────────────────────────────────
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }
function writeJSON(dir, name, data) {
  ensureDir(dir);
  fs.writeFileSync(path.join(dir, name), JSON.stringify(data, null, 2));
}
function bigIntReplacer(_key, value) {
  return typeof value === 'bigint' ? value.toString() : value;
}
function writeJSONBigInt(dir, name, data) {
  ensureDir(dir);
  fs.writeFileSync(path.join(dir, name), JSON.stringify(data, bigIntReplacer, 2));
}

// ─── Main ───────────────────────────────────────────────────
async function main() {
  console.log('📦 Connecting to Anvil at', RPC_URL);
  const provider = new ethers.JsonRpcProvider(RPC_URL);

  const latestBlock = await provider.getBlockNumber();
  console.log(`📦 Latest block: ${latestBlock}`);

  // Scan all blocks for relevant transactions
  const allTxHashes = [];
  const blockCache  = {};

  for (let bn = 0; bn <= latestBlock; bn++) {
    const block = await provider.getBlock(bn, true);
    if (!block) continue;
    blockCache[bn] = block;
    if (block.transactions && block.transactions.length > 0) {
      for (const txHash of block.transactions) {
        allTxHashes.push({ txHash, blockNumber: bn });
      }
    }
  }

  console.log(`📦 Found ${allTxHashes.length} transactions across ${latestBlock + 1} blocks`);

  // Collect full transaction data
  const transactions = [];
  const receipts     = [];
  let tokenAddress   = null;

  const progressInterval = Math.max(1, Math.floor(allTxHashes.length / 10));

  for (let i = 0; i < allTxHashes.length; i++) {
    const { txHash } = allTxHashes[i];
    const tx = await provider.getTransaction(txHash);
    if (!tx) continue;

    if (i % progressInterval === 0) {
      console.log(`   📥 Collecting tx ${i + 1}/${allTxHashes.length}...`);
    }

    const txData = {
      hash:             tx.hash,
      blockNumber:      tx.blockNumber,
      transactionIndex: tx.index,
      from:             tx.from,
      to:               tx.to,
      nonce:            tx.nonce,
      gasLimit:         tx.gasLimit.toString(),
      gasPrice:         tx.gasPrice ? tx.gasPrice.toString() : null,
      maxFeePerGas:     tx.maxFeePerGas ? tx.maxFeePerGas.toString() : null,
      maxPriorityFeePerGas: tx.maxPriorityFeePerGas ? tx.maxPriorityFeePerGas.toString() : null,
      value:            tx.value.toString(),
      data:             tx.data,
      selector:         tx.data && tx.data.length >= 10 ? tx.data.slice(0, 10) : null,
      chainId:          tx.chainId ? tx.chainId.toString() : null,
      type:             tx.type,
    };
    transactions.push(txData);

    // Receipt
    const receipt = await provider.getTransactionReceipt(txHash);
    if (receipt) {
      if (receipt.contractAddress) {
        tokenAddress = receipt.contractAddress;
      }

      const receiptData = {
        transactionHash:   receipt.hash,
        blockNumber:       receipt.blockNumber,
        status:            receipt.status,
        gasUsed:           receipt.gasUsed.toString(),
        cumulativeGasUsed: receipt.cumulativeGasUsed.toString(),
        contractAddress:   receipt.contractAddress,
        logs: receipt.logs.map(log => ({
          address:          log.address,
          topics:           log.topics,
          data:             log.data,
          logIndex:         log.index,
          transactionIndex: log.transactionIndex,
          blockNumber:      log.blockNumber,
          transactionHash:  log.transactionHash,
          removed:          log.removed || false,
        })),
      };
      receipts.push(receiptData);
    }
  }

  console.log(`📦 Token contract deployed at: ${tokenAddress}`);

  // ─── Write raw transactions ───────────────────────────────
  for (const tx of transactions) {
    writeJSON(PATHS.rawTx, `${tx.hash}.json`, tx);
  }
  writeJSON(PATHS.rawTx, '_all_transactions.json', transactions);
  console.log(`✅ Wrote ${transactions.length} raw transactions`);

  // ─── Write raw receipts ───────────────────────────────────
  for (const r of receipts) {
    writeJSON(PATHS.rawReceipts, `${r.transactionHash}.json`, r);
  }
  writeJSON(PATHS.rawReceipts, '_all_receipts.json', receipts);
  console.log(`✅ Wrote ${receipts.length} raw receipts`);

  // ─── Write raw blocks ────────────────────────────────────
  for (const [bn, block] of Object.entries(blockCache)) {
    const blockData = {
      number:     block.number,
      hash:       block.hash,
      parentHash: block.parentHash,
      timestamp:  block.timestamp,
      gasLimit:   block.gasLimit.toString(),
      gasUsed:    block.gasUsed.toString(),
      baseFeePerGas: block.baseFeePerGas ? block.baseFeePerGas.toString() : null,
      transactions:  block.transactions,
    };
    writeJSON(PATHS.rawBlocks, `block_${bn}.json`, blockData);
  }
  console.log(`✅ Wrote ${Object.keys(blockCache).length} raw blocks`);

  // ─── Write raw traces (debug_traceTransaction) ────────────
  let tracesCollected = 0;
  for (let i = 0; i < allTxHashes.length; i++) {
    const { txHash } = allTxHashes[i];
    try {
      const trace = await provider.send('debug_traceTransaction', [txHash, { tracer: 'callTracer' }]);
      writeJSONBigInt(PATHS.rawTraces, `${txHash}.json`, trace);
      tracesCollected++;

      const internals = extractInternalCalls(trace, txHash);
      if (internals.length > 0) {
        writeJSON(PATHS.rawInternalCalls, `${txHash}.json`, internals);
      }
    } catch (e) {
      // Anvil may not support debug_traceTransaction in all configs
    }

    if (i % progressInterval === 0 && i > 0) {
      console.log(`   🔍 Tracing ${i + 1}/${allTxHashes.length}...`);
    }
  }
  console.log(`✅ Traced ${tracesCollected} transactions`);

  // ─── Write raw state diffs (if available) ─────────────────
  let stateDiffsCollected = 0;
  for (const { txHash } of allTxHashes) {
    try {
      const diff = await provider.send('debug_traceTransaction', [txHash, { tracer: 'prestateTracer', tracerConfig: { diffMode: true } }]);
      writeJSONBigInt(PATHS.rawStateDiffs, `${txHash}.json`, diff);
      stateDiffsCollected++;
    } catch (_e) {}
  }
  if (stateDiffsCollected > 0) console.log(`✅ Wrote ${stateDiffsCollected} state diffs`);
  else console.log(`ℹ️  State diffs not available from Anvil (optional)`);

  // ─── Write ABI artifact ───────────────────────────────────
  const abiPath = path.join(PATHS.root, 'out', 'DemoToken.sol', 'DemoToken.json');
  if (fs.existsSync(abiPath)) {
    const artifact = JSON.parse(fs.readFileSync(abiPath, 'utf-8'));
    writeJSON(PATHS.rawAbi, 'DemoToken.abi.json', artifact.abi);
    writeJSON(PATHS.rawAbi, 'DemoToken.metadata.json', {
      contractName: 'DemoToken',
      deployedAddress: tokenAddress,
      compiler: artifact.metadata?.compiler || 'solc',
      source: 'src/DemoToken.sol',
      note: 'ABI is enrichment only — used in with_abi mode',
    });
    console.log(`✅ Wrote ABI artifacts`);
  } else {
    console.warn(`⚠️  ABI artifact not found at ${abiPath}. Run 'forge build' first.`);
  }

  // ─── Write contract metadata ──────────────────────────────
  writeJSON(PATHS.rawContracts, 'deployed_contracts.json', {
    DemoToken: {
      address: tokenAddress,
      deployer: ACCOUNTS.owner,
      source: 'src/DemoToken.sol',
      name: 'DemoToken',
      symbol: 'DEMO',
      decimals: 18,
    },
  });
  console.log(`✅ Wrote contract metadata`);

  // ─── Write event signature reference ──────────────────────
  writeJSON(PATHS.rawEventSigs, 'known_signatures.json', {
    events: {
      'Transfer(address,address,uint256)': TOPICS.Transfer,
    },
    functions: {
      'mint(address,uint256)': SELECTORS.mint,
      'transfer(address,uint256)': SELECTORS.transfer,
    },
    note: 'Known signatures for non-ABI generic decoding fallback',
  });
  console.log(`✅ Wrote event signature reference`);

  // ─── Classify transactions and write ground truth ─────────
  const classifications = classifyTransactions(transactions, receipts, tokenAddress);
  writeJSON(PATHS.rawGroundTruth, 'ground_truth.json', classifications);
  writeJSON(PATHS.rawGroundTruth, 'attack_markers.json', classifications.attackMarkers);
  console.log(`✅ Wrote ground-truth markers`);
  console.log(`   📊 Attacks detected: ${classifications.attackMarkers.attackCycles.length}`);
  console.log(`   📊 Suspicious txs:   ${classifications.attackMarkers.attackCycles.length * 3}`);

  // ─── Summary ──────────────────────────────────────────────
  writeJSON(PATHS.raw, '_export_summary.json', {
    exportedAt:       new Date().toISOString(),
    totalTransactions: transactions.length,
    totalReceipts:     receipts.length,
    totalBlocks:       Object.keys(blockCache).length,
    tracesCollected,
    stateDiffsCollected,
    tokenAddress,
    classifications: classifications.summary,
  });

  console.log('\n🎯 Raw evidence export complete!');
  console.log(`   Token: ${tokenAddress}`);
  console.log(`   Txs:   ${transactions.length}`);
  console.log(`   See:   ${PATHS.raw}`);
}

// ─── Internal call extraction from call trace ───────────────
function extractInternalCalls(trace, txHash, depth = 0, results = []) {
  if (!trace) return results;
  if (trace.calls && Array.isArray(trace.calls)) {
    for (const call of trace.calls) {
      results.push({
        txHash,
        depth:     depth + 1,
        type:      call.type || 'CALL',
        from:      call.from,
        to:        call.to,
        value:     call.value || '0x0',
        input:     call.input,
        output:    call.output || null,
        gas:       call.gas,
        gasUsed:   call.gasUsed,
      });
      extractInternalCalls(call, txHash, depth + 1, results);
    }
  }
  return results;
}

// ─── Transaction classification (multi-attack aware) ────────
function classifyTransactions(transactions, receipts, tokenAddress) {
  const ownerAddr   = ACCOUNTS.owner.toLowerCase();
  const stagingAddr = ACCOUNTS.staging.toLowerCase();
  const exitAddr    = ACCOUNTS.exit.toLowerCase();
  const tokenAddr   = tokenAddress ? tokenAddress.toLowerCase() : null;

  const classified = [];
  const baselineMintTxs     = [];
  const baselineTransferTxs = [];

  // Attack cycle tracking — multiple attacks supported
  const attackCycles        = [];
  const suspiciousMintTxs   = [];
  const stagingTransferTxs  = [];
  const exitTransferTxs     = [];

  // Sort transactions by block number and index
  const sorted = [...transactions].sort((a, b) =>
    a.blockNumber !== b.blockNumber
      ? a.blockNumber - b.blockNumber
      : a.transactionIndex - b.transactionIndex
  );

  // Pass 1: Collect all mint amounts to establish baseline
  const allMintAmounts = [];
  for (const tx of sorted) {
    const from     = tx.from?.toLowerCase();
    const to       = tx.to?.toLowerCase();
    const selector = tx.selector;

    if (selector === SELECTORS.mint && to === tokenAddr && from === ownerAddr) {
      const receipt = receipts.find(r => r.transactionHash === tx.hash);
      let transferAmount = null;
      if (receipt) {
        for (const log of receipt.logs) {
          if (log.topics[0] === TOPICS.Transfer && log.data && log.data !== '0x') {
            transferAmount = BigInt(log.data);
          }
        }
      }
      allMintAmounts.push({ hash: tx.hash, amount: transferAmount, blockNumber: tx.blockNumber });
    }
  }

  // Determine baseline threshold using statistical approach:
  // Sort mint amounts, baseline = bottom 50% or amounts below median * 10
  const sortedAmounts = allMintAmounts
    .filter(m => m.amount !== null)
    .sort((a, b) => (a.amount < b.amount ? -1 : a.amount > b.amount ? 1 : 0));

  let baselineMaxAmount = 0n;
  if (sortedAmounts.length > 0) {
    const medianIdx = Math.floor(sortedAmounts.length / 2);
    const median = sortedAmounts[medianIdx].amount;
    // Anything > 10x median is suspicious
    baselineMaxAmount = median * 10n;
    // Fallback: if all mints are the same size, use first mint * 10
    if (baselineMaxAmount === 0n) {
      baselineMaxAmount = sortedAmounts[0].amount * 10n;
    }
  }

  // Pass 2: Classify each transaction
  let pendingSuspiciousMint = false;  // Tracks whether we're in an attack window

  for (const tx of sorted) {
    const from     = tx.from?.toLowerCase();
    const to       = tx.to?.toLowerCase();
    const selector = tx.selector;

    const receipt = receipts.find(r => r.transactionHash === tx.hash);
    let transferAmount = null;
    let transferDest   = null;
    if (receipt) {
      for (const log of receipt.logs) {
        if (log.topics[0] === TOPICS.Transfer && log.data && log.data !== '0x') {
          transferAmount = BigInt(log.data);
          transferDest = log.topics[2] ? '0x' + log.topics[2].slice(26) : null;
        }
      }
    }

    let classification = 'baseline';
    let isSuspicious   = false;

    if (!tx.to) {
      // Contract deployment
      classification = 'contract_deployment';
    } else if (selector === SELECTORS.mint && to === tokenAddr && from === ownerAddr) {
      // Owner mint — suspicious if amount exceeds baseline threshold
      if (transferAmount && transferAmount > baselineMaxAmount) {
        classification = 'suspicious_mint';
        isSuspicious = true;
        suspiciousMintTxs.push(tx.hash);
        pendingSuspiciousMint = true;
      } else {
        classification = 'baseline_mint';
        baselineMintTxs.push(tx.hash);
      }
    } else if (selector === SELECTORS.transfer && to === tokenAddr) {
      // Transfer — check for suspicious staging/exit patterns
      if (from === ownerAddr && transferDest && transferDest.toLowerCase() === stagingAddr) {
        // Owner → staging with large amount = suspicious staging
        if (transferAmount && transferAmount > baselineMaxAmount) {
          classification = 'suspicious_staging_transfer';
          isSuspicious = true;
          stagingTransferTxs.push(tx.hash);
        } else {
          classification = 'baseline_transfer';
          baselineTransferTxs.push(tx.hash);
        }
      } else if (from === stagingAddr && transferDest && transferDest.toLowerCase() === exitAddr) {
        // Staging → exit = suspicious exit
        if (transferAmount && transferAmount > baselineMaxAmount) {
          classification = 'suspicious_exit_transfer';
          isSuspicious = true;
          exitTransferTxs.push(tx.hash);

          // Complete attack cycle
          const cycleIdx = exitTransferTxs.length - 1;
          attackCycles.push({
            cycleIndex: cycleIdx,
            mintTxHash: suspiciousMintTxs[cycleIdx] || null,
            stagingTxHash: stagingTransferTxs[cycleIdx] || null,
            exitTxHash: tx.hash,
          });
          pendingSuspiciousMint = false;
        } else {
          classification = 'baseline_transfer';
          baselineTransferTxs.push(tx.hash);
        }
      } else {
        classification = 'baseline_transfer';
        baselineTransferTxs.push(tx.hash);
      }
    }

    classified.push({
      hash:           tx.hash,
      classification,
      isSuspicious,
      blockNumber:    tx.blockNumber,
      from:           tx.from,
      to:             tx.to,
      selector,
      transferAmount: transferAmount ? transferAmount.toString() : null,
    });
  }

  return {
    classified,
    attackMarkers: {
      // Legacy single-attack fields (for backward compat — uses first attack)
      suspiciousMintTxHash:   suspiciousMintTxs[0] || null,
      stagingTransferTxHash:  stagingTransferTxs[0] || null,
      exitTransferTxHash:     exitTransferTxs[0] || null,

      // Multi-attack fields
      attackCycles,
      allSuspiciousMintTxs: suspiciousMintTxs,
      allStagingTransferTxs: stagingTransferTxs,
      allExitTransferTxs: exitTransferTxs,

      privilegedActorAddress: ACCOUNTS.owner,
      stagingWalletAddress:   ACCOUNTS.staging,
      exitWalletAddress:      ACCOUNTS.exit,
      tokenContractAddress:   tokenAddress,
      baselineThreshold:      baselineMaxAmount.toString(),

      expectedSuspiciousPath: [
        `mint → ${ACCOUNTS.owner} (privileged actor)`,
        `transfer → ${ACCOUNTS.staging} (staging wallet)`,
        `transfer → ${ACCOUNTS.exit} (exit wallet)`,
      ],
      expectedSignalOutcome: 'Suspicious privileged mint followed by rapid fund extraction',
    },
    summary: {
      totalTransactions:      sorted.length,
      baselineMints:          baselineMintTxs.length,
      baselineTransfers:      baselineTransferTxs.length,
      suspiciousMints:        suspiciousMintTxs.length,
      suspiciousStaging:      stagingTransferTxs.length,
      suspiciousExits:        exitTransferTxs.length,
      totalAttackCycles:      attackCycles.length,
      totalSuspicious:        suspiciousMintTxs.length + stagingTransferTxs.length + exitTransferTxs.length,
    },
  };
}

main().catch(console.error);
