/**
 * decode.js — Creates human-readable decoded event and action views.
 *
 * Two modes:
 *   with_abi    → precise ABI decoding of function names, args, event names + fields
 *   without_abi → generic decoding from selectors, standard Transfer topic, amounts
 *
 * Usage:  node detector/decode.js [with_abi|without_abi]
 */
import fs from 'fs';
import path from 'path';
import { ethers } from 'ethers';
import { PATHS, TOPICS, SELECTORS, ACCOUNTS } from './config.js';

function readJSON(fp) { return JSON.parse(fs.readFileSync(fp, 'utf-8')); }
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

export function decode(mode = 'without_abi') {
  console.log(`🔍 Decoding in ${mode} mode...`);

  const normalized = readJSON(path.join(PATHS.normalized, 'normalized_records.json'));
  const receipts   = readJSON(path.join(PATHS.rawReceipts, '_all_receipts.json'));
  const transactions = readJSON(path.join(PATHS.rawTx, '_all_transactions.json'));

  // Build maps
  const receiptMap = {};
  for (const r of receipts) receiptMap[r.transactionHash] = r;
  const txMap = {};
  for (const t of transactions) txMap[t.hash] = t;

  // Load ABI if with_abi
  let iface = null;
  if (mode === 'with_abi') {
    const abiPath = path.join(PATHS.rawAbi, 'DemoToken.abi.json');
    if (fs.existsSync(abiPath)) {
      const abi = readJSON(abiPath);
      iface = new ethers.Interface(abi);
      console.log('   📖 ABI loaded for precise decoding');
    } else {
      console.warn('   ⚠️  ABI not found — falling back to generic mode');
      mode = 'without_abi';
    }
  }

  const decoded = [];

  for (const record of normalized) {
    const receipt = receiptMap[record.txHash];
    const rawTx   = txMap[record.txHash];

    // ─── Decode function call ─────────────────────────────
    let decodedFunctionName = null;
    let decodedFunctionArgs = null;

    if (mode === 'with_abi' && iface && rawTx && rawTx.data && rawTx.data.length >= 10) {
      try {
        const parsed = iface.parseTransaction({ data: rawTx.data });
        if (parsed) {
          decodedFunctionName = parsed.name;
          decodedFunctionArgs = {};
          for (const [key, value] of Object.entries(parsed.args)) {
            if (isNaN(key)) {
              decodedFunctionArgs[key] = typeof value === 'bigint' ? value.toString() : value;
            }
          }
        }
      } catch (_e) {
        // Deployment or unknown function
      }
    } else if (mode === 'without_abi' && rawTx) {
      // Generic selector matching
      if (rawTx.selector === SELECTORS.mint) {
        decodedFunctionName = 'unknown_sensitive_like_call';
        decodedFunctionArgs = { selector: rawTx.selector, note: 'Matches known mint-like selector pattern' };
      } else if (rawTx.selector === SELECTORS.transfer) {
        decodedFunctionName = 'unknown_transfer_like_call';
        decodedFunctionArgs = { selector: rawTx.selector, note: 'Matches known transfer-like selector pattern' };
      } else if (rawTx.data && rawTx.data.length > 2) {
        decodedFunctionName = 'unknown_call';
        decodedFunctionArgs = { selector: rawTx.selector };
      }
    }

    // ─── Decode events ────────────────────────────────────
    const decodedEvents = [];
    if (receipt) {
      for (const log of receipt.logs) {
        let eventName   = null;
        let eventFields = null;

        if (mode === 'with_abi' && iface) {
          try {
            const parsed = iface.parseLog({ topics: log.topics, data: log.data });
            if (parsed) {
              eventName = parsed.name;
              eventFields = {};
              for (const [key, value] of Object.entries(parsed.args)) {
                if (isNaN(key)) {
                  eventFields[key] = typeof value === 'bigint' ? value.toString() : value;
                }
              }
            }
          } catch (_e) {}
        } else if (mode === 'without_abi') {
          // Generic: recognize standard Transfer(address,address,uint256)
          if (log.topics[0] === TOPICS.Transfer) {
            eventName = 'Transfer (standard ERC20 pattern)';
            const from   = log.topics[1] ? '0x' + log.topics[1].slice(26) : null;
            const to     = log.topics[2] ? '0x' + log.topics[2].slice(26) : null;
            const amount = log.data && log.data !== '0x' ? BigInt(log.data).toString() : '0';
            eventFields = { from, to, amount, inferredFrom: 'standard_topic_matching' };
          } else {
            eventName = 'unknown_event';
            eventFields = { topic0: log.topics[0] };
          }
        }

        decodedEvents.push({
          address:    log.address,
          rawTopics:  log.topics,
          rawData:    log.data,
          eventName:  eventName,
          eventFields: eventFields,
          logIndex:   log.logIndex,
        });
      }
    }

    // ─── Build decoded record ─────────────────────────────
    decoded.push({
      txHash:                  record.txHash,
      blockNumber:             record.blockNumber,
      selector:                record.selector,
      decodedFunctionName,
      decodedFunctionArgs,
      decodedEvents,
      classification:          record.classification,
      groundTruthAttackLinked: record.groundTruthLinked,
      decodeMode:              mode,
      decodeConfidence:        mode === 'with_abi' ? 'high' : 'low',
      actorAddress:            record.actorAddress,
      targetAddress:           record.targetAddress,
    });
  }

  // Write decoded output
  const outDir = path.join(PATHS.decoded, mode);
  ensureDir(outDir);
  fs.writeFileSync(
    path.join(outDir, 'decoded_records.json'),
    JSON.stringify(decoded, null, 2)
  );

  // Write a human-friendly summary
  const summary = decoded.map(d => ({
    txHash:           d.txHash.slice(0, 18) + '...',
    function:         d.decodedFunctionName || '(deployment)',
    events:           d.decodedEvents.map(e => e.eventName).join(', ') || '(none)',
    classification:   d.classification,
    attackLinked:     d.groundTruthAttackLinked,
    mode:             d.decodeMode,
  }));
  fs.writeFileSync(
    path.join(outDir, 'decoded_summary.json'),
    JSON.stringify(summary, null, 2)
  );

  console.log(`✅ Decoded ${decoded.length} records (${mode}) → ${outDir}`);
  return decoded;
}

// Run directly
if (process.argv[1] && process.argv[1].includes('decode')) {
  const mode = process.argv[2] || 'without_abi';
  decode(mode);
}
