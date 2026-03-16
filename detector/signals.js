/**
 * signals.js — Final analyst-facing suspicious findings.
 *
 * Signal families:
 *   without_abi: "Possible Privileged Asset Extraction"
 *   with_abi:    "Abnormal Privileged Mint and Extraction"
 *
 * Confidence logic:
 *   Medium  → H1 only
 *   High    → H1 + H2
 *   High+   → H1 + H2 + H3 (stronger explanation)
 *
 * Usage:  node detector/signals.js [with_abi|without_abi]
 */
import fs from 'fs';
import path from 'path';
import { PATHS } from './config.js';

function readJSON(fp) { return JSON.parse(fs.readFileSync(fp, 'utf-8')); }
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

export function generateSignals(mode = 'without_abi') {
  console.log(`🚨 Generating signals (${mode})...`);

  const heurResults  = readJSON(path.join(PATHS.derived, mode, 'heuristic_results.json'));
  const derivedFacts = readJSON(path.join(PATHS.derived, mode, 'derived_facts.json'));
  const groundTruth  = readJSON(path.join(PATHS.rawGroundTruth, 'attack_markers.json'));

  // Build derived facts map
  const factMap = {};
  for (const f of derivedFacts) factMap[f.txHash] = f;

  const signals = [];

  for (const hr of heurResults) {
    if (!hr.H1.triggered) continue; // Signal only fires if H1 is true at minimum

    const fact = factMap[hr.txHash];

    // ─── Signal name depends on mode ──────────────────────
    const signalName = mode === 'with_abi'
      ? 'Abnormal Privileged Mint and Extraction'
      : 'Possible Privileged Asset Extraction';

    // ─── Confidence logic ─────────────────────────────────
    let confidence;
    let why;

    if (hr.H1.triggered && hr.H2.triggered && hr.H3.triggered) {
      confidence = 'high';
      why = `All three heuristics triggered: sensitive privileged action with massive token movement (${hr.H1.reason}), rapid subsequent extraction (${hr.H2.reason}), and extreme baseline deviation (${hr.H3.reason}). This strongly indicates a coordinated privileged mint-and-extract attack.`;
    } else if (hr.H1.triggered && hr.H2.triggered) {
      confidence = 'high';
      why = `Sensitive privileged action with large movement (${hr.H1.reason}) followed by rapid extraction (${hr.H2.reason}). Pattern consistent with privileged asset extraction.`;
    } else {
      confidence = 'medium';
      why = `Sensitive privileged action with unusually large token movement detected (${hr.H1.reason}). Further monitoring recommended.`;
    }

    // ─── Triggered heuristics list ────────────────────────
    const triggeredHeuristics = [];
    if (hr.H1.triggered) triggeredHeuristics.push({ id: 'H1', name: 'Sensitive Action With Large Movement', reason: hr.H1.reason });
    if (hr.H2.triggered) triggeredHeuristics.push({ id: 'H2', name: 'Rapid Follow-Up Extraction', reason: hr.H2.reason });
    if (hr.H3.triggered) triggeredHeuristics.push({ id: 'H3', name: 'Deviation From Baseline', reason: hr.H3.reason });

    // ─── Supporting evidence ──────────────────────────────
    const supportingEvidence = [hr.txHash];
    if (groundTruth.stagingTransferTxHash) supportingEvidence.push(groundTruth.stagingTransferTxHash);
    if (groundTruth.exitTransferTxHash) supportingEvidence.push(groundTruth.exitTransferTxHash);

    // ─── Ground truth linkage ─────────────────────────────
    const linkedGroundTruth = hr.txHash === groundTruth.suspiciousMintTxHash;

    const signal = {
      signalName,
      txHash:                hr.txHash,
      actor:                 hr.actor,
      target:                fact ? fact.target_address : null,
      confidence,
      triggeredHeuristics,
      why,
      decodeMode:            mode,
      supportingEvidence,
      linkedGroundTruthMarker: linkedGroundTruth,
      blockNumber:           hr.blockNumber,
      classification:        hr.classification,
      timestamp:             new Date().toISOString(),
    };

    signals.push(signal);
  }

  // Write signals
  const outDir = path.join(PATHS.signals, mode);
  ensureDir(outDir);
  fs.writeFileSync(
    path.join(outDir, 'signals.json'),
    JSON.stringify(signals, null, 2)
  );

  // Write a compact summary
  const summary = {
    mode,
    totalSignals: signals.length,
    highConfidence: signals.filter(s => s.confidence === 'high').length,
    mediumConfidence: signals.filter(s => s.confidence === 'medium').length,
    linkedToGroundTruth: signals.filter(s => s.linkedGroundTruthMarker).length,
    signals: signals.map(s => ({
      name: s.signalName,
      txHash: s.txHash.slice(0, 18) + '...',
      confidence: s.confidence,
      heuristics: s.triggeredHeuristics.map(h => h.id).join('+'),
      groundTruth: s.linkedGroundTruthMarker,
    })),
  };
  fs.writeFileSync(
    path.join(outDir, 'signal_summary.json'),
    JSON.stringify(summary, null, 2)
  );

  console.log(`✅ Generated ${signals.length} signal(s) (${mode})`);
  if (signals.length > 0) {
    for (const s of signals) {
      console.log(`   🚨 ${s.signalName} [${s.confidence}] — ${s.triggeredHeuristics.map(h => h.id).join('+')}`);
    }
  }
  return signals;
}

// Run directly
if (process.argv[1] && process.argv[1].includes('signals')) {
  const mode = process.argv[2] || 'without_abi';
  generateSignals(mode);
}
