/**
 * runPipeline.js — Orchestrates the full forensic analysis pipeline.
 *
 * Every run creates a new timestamped folder under runs/ containing
 * all pipeline outputs (normalized, decoded, derived, signals, reports, graphs).
 *
 * Usage:
 *   node detector/runPipeline.js without_abi   — run without ABI mode
 *   node detector/runPipeline.js with_abi      — run with ABI mode
 *   node detector/runPipeline.js all           — run both modes (default)
 *
 * Prerequisites:
 *   1. Anvil running
 *   2. Contracts deployed (forge script script/Deploy.s.sol ...)
 *   3. Attack simulated (forge script script/SimulateAttack.s.sol ...)
 *   4. Raw evidence exported (node detector/exportRaw.js)
 */
import fs from 'fs';
import path from 'path';
import { PATHS, setRunDir } from './config.js';
import { normalize } from './normalize.js';
import { decode } from './decode.js';
import { derive } from './derive.js';
import { runHeuristics } from './heuristics.js';
import { generateSignals } from './signals.js';
import { generateReport } from './reportOllama.js';
import { generateGraphs } from './graphs.js';

function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

function generateRunId() {
  const now = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;
}

function copyRawSnapshotToRun(runDir) {
  // Copy a lightweight snapshot of raw evidence into the run folder for self-containment
  const rawSnapshotDir = path.join(runDir, 'raw_snapshot');
  ensureDir(rawSnapshotDir);

  // Copy key summary files (not all individual tx files to save space)
  const filesToCopy = [
    { src: path.join(PATHS.rawTx, '_all_transactions.json'), dst: path.join(rawSnapshotDir, 'all_transactions.json') },
    { src: path.join(PATHS.rawReceipts, '_all_receipts.json'), dst: path.join(rawSnapshotDir, 'all_receipts.json') },
    { src: path.join(PATHS.rawGroundTruth, 'ground_truth.json'), dst: path.join(rawSnapshotDir, 'ground_truth.json') },
    { src: path.join(PATHS.rawGroundTruth, 'attack_markers.json'), dst: path.join(rawSnapshotDir, 'attack_markers.json') },
    { src: path.join(PATHS.rawContracts, 'deployed_contracts.json'), dst: path.join(rawSnapshotDir, 'deployed_contracts.json') },
    { src: path.join(PATHS.raw, '_export_summary.json'), dst: path.join(rawSnapshotDir, 'export_summary.json') },
  ];

  // Copy ABI
  const abiSrc = path.join(PATHS.rawAbi, 'DemoToken.abi.json');
  if (fs.existsSync(abiSrc)) {
    filesToCopy.push({ src: abiSrc, dst: path.join(rawSnapshotDir, 'DemoToken.abi.json') });
  }

  const abiMeta = path.join(PATHS.rawAbi, 'DemoToken.metadata.json');
  if (fs.existsSync(abiMeta)) {
    filesToCopy.push({ src: abiMeta, dst: path.join(rawSnapshotDir, 'DemoToken.metadata.json') });
  }

  // Copy event signatures
  const sigSrc = path.join(PATHS.rawEventSigs, 'known_signatures.json');
  if (fs.existsSync(sigSrc)) {
    filesToCopy.push({ src: sigSrc, dst: path.join(rawSnapshotDir, 'known_signatures.json') });
  }

  for (const { src, dst } of filesToCopy) {
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, dst);
    }
  }

  console.log(`   📋 Raw evidence snapshot copied to run folder`);
}

function writeRunManifest(runDir, runId, modes, elapsed) {
  const manifest = {
    runId,
    createdAt: new Date().toISOString(),
    elapsedSeconds: elapsed,
    modes,
    pipelineVersion: 'AdminAttackSim Forensics MVP v1.0',
    contents: {
      raw_snapshot: 'Lightweight copy of raw evidence for this run',
      normalized: 'Clean structured transaction records',
      decoded: 'Human-readable decoded event/action views (per mode)',
      derived: 'Generalized forensic facts + heuristic results (per mode)',
      signals: 'Final suspicious findings (per mode)',
      reports: 'Decoded forensic report + Ollama narrative report (per mode)',
      graphs: 'Trace graph + incident timeline JSON/Mermaid (per mode)',
    },
  };
  fs.writeFileSync(path.join(runDir, 'run_manifest.json'), JSON.stringify(manifest, null, 2));
}

async function runPipeline(mode) {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  FORENSIC PIPELINE — ${mode.toUpperCase()}`);
  console.log(`${'═'.repeat(60)}\n`);

  const startTime = Date.now();

  // Step 1: Normalize (shared — only run once)
  normalize();

  // Step 2: Decode
  decode(mode);

  // Step 3: Derive forensic facts
  derive(mode);

  // Step 4: Run heuristics
  runHeuristics(mode);

  // Step 5: Generate signals
  generateSignals(mode);

  // Step 6: Generate graphs
  generateGraphs(mode);

  // Step 7: Generate BOTH reports (decoded + narrative)
  try {
    await generateReport(mode);
  } catch (e) {
    console.warn(`⚠️  Report generation failed: ${e.message}`);
    console.warn(`   Reports can be generated later with: node detector/reportOllama.js ${mode}`);
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`\n✅ Pipeline complete (${mode}) in ${elapsed}s\n`);
  return parseFloat(elapsed);
}

async function main() {
  const arg = process.argv[2] || 'all';
  const runId = generateRunId();
  const runDir = setRunDir(runId);
  const totalStart = Date.now();

  console.log(`\n${'█'.repeat(60)}`);
  console.log(`  FORENSIC ANALYSIS RUN: ${runId}`);
  console.log(`  Output: ${runDir}`);
  console.log(`${'█'.repeat(60)}\n`);

  // Copy raw evidence snapshot into run folder
  copyRawSnapshotToRun(runDir);

  const modes = [];
  if (arg === 'all') {
    await runPipeline('without_abi');
    modes.push('without_abi');
    await runPipeline('with_abi');
    modes.push('with_abi');
  } else {
    await runPipeline(arg);
    modes.push(arg);
  }

  const totalElapsed = ((Date.now() - totalStart) / 1000).toFixed(1);
  writeRunManifest(runDir, runId, modes, parseFloat(totalElapsed));

  console.log(`${'█'.repeat(60)}`);
  console.log(`  RUN COMPLETE: ${runId}`);
  console.log(`  Duration: ${totalElapsed}s`);
  console.log(`${'█'.repeat(60)}`);
  console.log(`\n📂 All outputs saved to: ${runDir}`);
  console.log(`\nInspect results:`);
  console.log(`  ${path.join(runDir, 'run_manifest.json')}          — Run metadata`);
  console.log(`  ${path.join(runDir, 'raw_snapshot/')}              — Evidence snapshot`);
  console.log(`  ${path.join(runDir, 'normalized/')}                — Structured records`);
  console.log(`  ${path.join(runDir, 'decoded/')}                   — Decoded views`);
  console.log(`  ${path.join(runDir, 'derived/')}                   — Forensic facts`);
  console.log(`  ${path.join(runDir, 'signals/')}                   — Suspicious findings`);
  console.log(`  ${path.join(runDir, 'reports/')}                   — Forensic reports`);
  console.log(`  ${path.join(runDir, 'graphs/')}                    — Graph visualizations`);
}

main().catch(console.error);
