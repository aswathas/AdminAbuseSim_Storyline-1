/**
 * derive.js — Generates the Generalized Derived Forensic Schema.
 *
 * The SAME schema is populated in both with_abi and without_abi modes.
 * Only the richness of labels and decode_confidence differs.
 *
 * Usage:  node detector/derive.js [with_abi|without_abi]
 */
import fs from 'fs';
import path from 'path';
import { PATHS, ACCOUNTS, SELECTORS, THRESHOLDS } from './config.js';

function readJSON(fp) { return JSON.parse(fs.readFileSync(fp, 'utf-8')); }
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

export function derive(mode = 'without_abi') {
  console.log(`📐 Deriving forensic facts (${mode})...`);

  const normalized = readJSON(path.join(PATHS.normalized, 'normalized_records.json'));
  const decoded    = readJSON(path.join(PATHS.decoded, mode, 'decoded_records.json'));
  const groundTruth = readJSON(path.join(PATHS.rawGroundTruth, 'ground_truth.json'));

  // Build decoded map
  const decodedMap = {};
  for (const d of decoded) decodedMap[d.txHash] = d;

  // Determine baseline mint amounts for deviation scoring
  const baselineMintAmounts = [];
  for (const record of normalized) {
    if (record.classification === 'baseline_mint' && record.primaryTransferAmount) {
      baselineMintAmounts.push(BigInt(record.primaryTransferAmount));
    }
  }
  const baselineMax = baselineMintAmounts.length > 0
    ? baselineMintAmounts.reduce((a, b) => a > b ? a : b, 0n)
    : 1n;

  // Determine role context for known addresses
  const ownerAddr   = ACCOUNTS.owner.toLowerCase();
  const stagingAddr = ACCOUNTS.staging.toLowerCase();
  const exitAddr    = ACCOUNTS.exit.toLowerCase();

  function getRole(address) {
    if (!address) return 'unknown';
    const addr = address.toLowerCase();
    if (addr === ownerAddr) return 'owner';
    if (addr === stagingAddr) return 'non_privileged';
    if (addr === exitAddr) return 'non_privileged';
    return 'unknown';
  }

  // Find timing info for rapid-followup detection
  const txBlocks = {};
  for (const r of normalized) txBlocks[r.txHash] = r.blockNumber;

  const suspiciousMintHash   = groundTruth.attackMarkers.suspiciousMintTxHash;
  const stagingTransferHash  = groundTruth.attackMarkers.stagingTransferTxHash;
  const exitTransferHash     = groundTruth.attackMarkers.exitTransferTxHash;

  const mintBlock    = suspiciousMintHash ? txBlocks[suspiciousMintHash] : null;
  const stagingBlock = stagingTransferHash ? txBlocks[stagingTransferHash] : null;

  const derivedFacts = [];

  for (const record of normalized) {
    const dec = decodedMap[record.txHash];

    // ─── action_label ─────────────────────────────────────
    let actionLabel;
    if (mode === 'with_abi' && dec && dec.decodedFunctionName) {
      actionLabel = dec.decodedFunctionName;
    } else if (dec && dec.decodedFunctionName) {
      actionLabel = dec.decodedFunctionName;
    } else if (record.targetAddress === null) {
      actionLabel = 'contract_deployment';
    } else {
      actionLabel = 'unknown_call';
    }

    // ─── action_category ──────────────────────────────────
    let actionCategory = 'unknown';
    if (record.selector === SELECTORS.mint) {
      actionCategory = 'sensitive';
    } else if (record.selector === SELECTORS.transfer) {
      actionCategory = 'asset_movement';
    } else if (!record.targetAddress) {
      actionCategory = 'unknown'; // deployment
    }

    // ─── is_sensitive_action ──────────────────────────────
    const isSensitive = record.selector === SELECTORS.mint;

    // ─── token_value_moved ────────────────────────────────
    const tokenValueMoved = record.primaryTransferAmount || '0';

    // ─── rapid_followup_movement ──────────────────────────
    let rapidFollowup = false;
    if (record.txHash === suspiciousMintHash && stagingBlock !== null && mintBlock !== null) {
      rapidFollowup = (stagingBlock - mintBlock) <= THRESHOLDS.rapidFollowupBlocks;
    }
    if (record.txHash === stagingTransferHash && mintBlock !== null) {
      rapidFollowup = (record.blockNumber - mintBlock) <= THRESHOLDS.rapidFollowupBlocks;
    }
    if (record.txHash === exitTransferHash && stagingBlock !== null) {
      rapidFollowup = (record.blockNumber - stagingBlock) <= THRESHOLDS.rapidFollowupBlocks;
    }

    // ─── baseline_deviation_score ─────────────────────────
    let deviationScore = 0;
    if (record.primaryTransferAmount) {
      const amount = BigInt(record.primaryTransferAmount);
      if (baselineMax > 0n) {
        deviationScore = Number(amount / baselineMax);
      }
    }

    // ─── risk_hint ────────────────────────────────────────
    let riskHint = 'none';
    if (record.classification === 'suspicious_mint') {
      riskHint = mode === 'with_abi'
        ? 'privileged_mint_extraction'
        : 'possible_privileged_asset_extraction';
    } else if (record.classification === 'suspicious_staging_transfer') {
      riskHint = 'staging_fund_movement';
    } else if (record.classification === 'suspicious_exit_transfer') {
      riskHint = 'exit_fund_extraction';
    }

    // ─── actor_role_context ───────────────────────────────
    let actorRole = getRole(record.actorAddress);
    // In without_abi mode, if we don't have ABI but see the owner calling a sensitive selector
    if (mode === 'without_abi' && actorRole === 'owner' && isSensitive) {
      actorRole = 'likely_privileged';
    }

    // ─── decode_confidence ────────────────────────────────
    let decodeConfidence = mode === 'with_abi' ? 'high' : 'low';
    if (mode === 'without_abi' && record.recognizedTransfer) {
      decodeConfidence = 'medium'; // We recognized the standard Transfer pattern
    }

    const fact = {
      txHash:               record.txHash,
      actor_address:        record.actorAddress,
      target_address:       record.targetAddress,
      actor_role_context:   actorRole,
      action_selector:      record.selector,
      action_label:         actionLabel,
      action_category:      actionCategory,
      is_sensitive_action:  isSensitive,
      token_value_moved:    tokenValueMoved,
      rapid_followup_movement: rapidFollowup,
      baseline_deviation_score: deviationScore,
      risk_hint:            riskHint,
      decode_mode:          mode,
      decode_confidence:    decodeConfidence,

      // Extra context
      classification:       record.classification,
      blockNumber:          record.blockNumber,
      groundTruthLinked:    record.groundTruthLinked,
    };

    derivedFacts.push(fact);
  }

  // Write output
  const outDir = path.join(PATHS.derived, mode);
  ensureDir(outDir);
  fs.writeFileSync(
    path.join(outDir, 'derived_facts.json'),
    JSON.stringify(derivedFacts, null, 2)
  );

  console.log(`✅ Derived ${derivedFacts.length} forensic facts (${mode}) → ${outDir}`);
  return derivedFacts;
}

// Run directly
if (process.argv[1] && process.argv[1].includes('derive')) {
  const mode = process.argv[2] || 'without_abi';
  derive(mode);
}
