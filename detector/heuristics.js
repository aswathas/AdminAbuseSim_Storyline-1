/**
 * heuristics.js — Three clean rule functions for forensic detection.
 *
 * H1: Sensitive Action With Large Movement
 * H2: Rapid Follow-Up Extraction
 * H3: Deviation From Baseline
 *
 * Usage:  node detector/heuristics.js [with_abi|without_abi]
 */
import fs from 'fs';
import path from 'path';
import { PATHS, THRESHOLDS } from './config.js';

function readJSON(fp) { return JSON.parse(fs.readFileSync(fp, 'utf-8')); }
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

// ─── H1: Sensitive Action With Large Movement ──────────────
export function H1_SensitiveActionLargeMovement(fact) {
  if (!fact.is_sensitive_action) return { triggered: false, reason: null };
  const amount = BigInt(fact.token_value_moved || '0');
  if (amount === 0n) return { triggered: false, reason: null };

  // Check if the amount is abnormally large (deviation score > threshold)
  if (fact.baseline_deviation_score >= THRESHOLDS.largeMultiplier) {
    return {
      triggered: true,
      reason: `Sensitive action with large token movement: deviation score ${fact.baseline_deviation_score}x baseline (threshold: ${THRESHOLDS.largeMultiplier}x)`,
    };
  }
  return { triggered: false, reason: null };
}

// ─── H2: Rapid Follow-Up Extraction ────────────────────────
export function H2_RapidFollowUpExtraction(fact, allFacts) {
  if (!fact.is_sensitive_action) return { triggered: false, reason: null };

  // Check if there's rapid follow-up movement after this suspicious action
  const subsequentSuspicious = allFacts.filter(f =>
    f.blockNumber >= fact.blockNumber &&
    f.txHash !== fact.txHash &&
    f.rapid_followup_movement &&
    (f.classification === 'suspicious_staging_transfer' || f.classification === 'suspicious_exit_transfer')
  );

  if (subsequentSuspicious.length > 0) {
    return {
      triggered: true,
      reason: `Rapid fund extraction detected: ${subsequentSuspicious.length} suspicious follow-up transfer(s) within ${THRESHOLDS.rapidFollowupBlocks} blocks`,
    };
  }
  return { triggered: false, reason: null };
}

// ─── H3: Deviation From Baseline ───────────────────────────
export function H3_DeviationFromBaseline(fact) {
  if (fact.baseline_deviation_score >= THRESHOLDS.highDeviationThreshold) {
    return {
      triggered: true,
      reason: `Extreme baseline deviation: ${fact.baseline_deviation_score}x normal activity (threshold: ${THRESHOLDS.highDeviationThreshold}x)`,
    };
  }
  return { triggered: false, reason: null };
}

// ─── Run heuristics on all derived facts ────────────────────
export function runHeuristics(mode = 'without_abi') {
  console.log(`🧠 Running heuristics (${mode})...`);

  const facts = readJSON(path.join(PATHS.derived, mode, 'derived_facts.json'));

  const results = [];

  for (const fact of facts) {
    const h1 = H1_SensitiveActionLargeMovement(fact);
    const h2 = H2_RapidFollowUpExtraction(fact, facts);
    const h3 = H3_DeviationFromBaseline(fact);

    results.push({
      txHash:          fact.txHash,
      classification:  fact.classification,
      blockNumber:     fact.blockNumber,
      actor:           fact.actor_address,
      decodeMode:      mode,
      H1: h1,
      H2: h2,
      H3: h3,
      anyTriggered:    h1.triggered || h2.triggered || h3.triggered,
    });
  }

  const outDir = path.join(PATHS.derived, mode);
  ensureDir(outDir);
  fs.writeFileSync(
    path.join(outDir, 'heuristic_results.json'),
    JSON.stringify(results, null, 2)
  );

  const triggered = results.filter(r => r.anyTriggered);
  console.log(`✅ Heuristics: ${triggered.length} of ${results.length} transactions triggered rules (${mode})`);
  return results;
}

// Run directly
if (process.argv[1] && process.argv[1].includes('heuristics')) {
  const mode = process.argv[2] || 'without_abi';
  runHeuristics(mode);
}
