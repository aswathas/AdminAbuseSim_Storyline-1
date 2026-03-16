/**
 * normalize.js — Converts raw evidence into clean common structured records.
 *
 * Produces one normalized record per transaction with associated event data.
 * Does NOT destroy raw truth — purely additive structuring.
 *
 * Usage:  node detector/normalize.js
 */
import fs from 'fs';
import path from 'path';
import { PATHS, TOPICS, SELECTORS, ACCOUNTS } from './config.js';

function readJSON(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

export function normalize() {
  console.log('🔄 Normalizing raw evidence...');

  const txFile      = path.join(PATHS.rawTx, '_all_transactions.json');
  const receiptFile = path.join(PATHS.rawReceipts, '_all_receipts.json');
  const gtFile      = path.join(PATHS.rawGroundTruth, 'ground_truth.json');

  const transactions = readJSON(txFile);
  const receipts     = readJSON(receiptFile);
  const groundTruth  = readJSON(gtFile);

  // Build receipt map
  const receiptMap = {};
  for (const r of receipts) {
    receiptMap[r.transactionHash] = r;
  }

  // Build classification map
  const classMap = {};
  for (const c of groundTruth.classified) {
    classMap[c.hash] = c;
  }

  // Read block data for timestamps
  const blockTimestamps = {};
  const blockDir = PATHS.rawBlocks;
  if (fs.existsSync(blockDir)) {
    for (const f of fs.readdirSync(blockDir)) {
      if (f.startsWith('block_') && f.endsWith('.json')) {
        const block = readJSON(path.join(blockDir, f));
        blockTimestamps[block.number] = block.timestamp;
      }
    }
  }

  // Check for traces
  const traceDir = PATHS.rawTraces;
  const traceExists = fs.existsSync(traceDir);

  // Check for internal calls
  const internalDir = PATHS.rawInternalCalls;
  const internalExists = fs.existsSync(internalDir);

  const normalized = [];

  for (const tx of transactions) {
    const receipt = receiptMap[tx.hash];
    const cls     = classMap[tx.hash];

    // Extract Transfer events from receipt logs
    const transferEvents = [];
    if (receipt) {
      for (const log of receipt.logs) {
        if (log.topics[0] === TOPICS.Transfer) {
          const from   = '0x' + log.topics[1].slice(26);
          const to     = '0x' + log.topics[2].slice(26);
          const amount = log.data && log.data !== '0x' ? BigInt(log.data).toString() : '0';
          transferEvents.push({ from, to, amount, logIndex: log.logIndex });
        }
      }
    }

    const hasTrace = traceExists && fs.existsSync(path.join(traceDir, `${tx.hash}.json`));
    const hasInternalCalls = internalExists && fs.existsSync(path.join(internalDir, `${tx.hash}.json`));

    const record = {
      txHash:               tx.hash,
      blockNumber:          tx.blockNumber,
      timestamp:            blockTimestamps[tx.blockNumber] || null,
      actorAddress:         tx.from,
      targetAddress:        tx.to,
      selector:             tx.selector,
      status:               receipt ? receipt.status : null,
      value:                tx.value,
      gasUsed:              receipt ? receipt.gasUsed : null,

      // Token transfer movement
      tokenTransfers:       transferEvents,
      hasTokenTransfer:     transferEvents.length > 0,
      primaryTransferAmount: transferEvents.length > 0 ? transferEvents[0].amount : null,
      primaryTransferFrom:   transferEvents.length > 0 ? transferEvents[0].from : null,
      primaryTransferTo:     transferEvents.length > 0 ? transferEvents[0].to : null,

      // Event source
      eventSourceAddress:   receipt && receipt.logs.length > 0 ? receipt.logs[0].address : null,
      recognizedTransfer:   transferEvents.length > 0,

      // Trace metadata
      hasTrace,
      hasInternalCalls,

      // Classification and ground truth
      classification:       cls ? cls.classification : 'unknown',
      isSuspicious:         cls ? cls.isSuspicious : false,
      groundTruthLinked:    cls ? cls.isSuspicious : false,

      // Raw log count
      rawLogCount:          receipt ? receipt.logs.length : 0,
    };

    normalized.push(record);
  }

  // Sort by block number then transaction index
  normalized.sort((a, b) => {
    if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
    return 0;
  });

  ensureDir(PATHS.normalized);
  fs.writeFileSync(
    path.join(PATHS.normalized, 'normalized_records.json'),
    JSON.stringify(normalized, null, 2)
  );

  console.log(`✅ Normalized ${normalized.length} records → ${PATHS.normalized}`);
  return normalized;
}

// Run directly
if (process.argv[1] && process.argv[1].includes('normalize')) {
  normalize();
}
