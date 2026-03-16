/**
 * config.js — Central configuration for the forensics pipeline.
 * All addresses, paths, and constants live here.
 *
 * Supports run-based output: call setRunDir(runId) to redirect all
 * output paths into runs/<runId>/.
 */
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const ROOT       = path.resolve(__dirname, '..');

// ─── Anvil deterministic accounts ───────────────────────────
export const ACCOUNTS = {
  owner:   '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
  user1:   '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
  user2:   '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
  staging: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
  exit:    '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
};

// Private keys (Anvil defaults — never use on mainnet)
export const PRIVATE_KEYS = {
  owner:   '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  user1:   '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  user2:   '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
  staging: '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
};

// ─── RPC ────────────────────────────────────────────────────
export const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8545';

// ─── Well-known selectors and topics ────────────────────────
export const SELECTORS = {
  mint:     '0x40c10f19',   // mint(address,uint256)
  transfer: '0xa9059cbb',  // transfer(address,uint256)
};

export const TOPICS = {
  Transfer: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
};

// ─── Paths (mutable — redirected by setRunDir) ──────────────
export const PATHS = {
  root:             ROOT,
  runs:             path.join(ROOT, 'runs'),
  raw:              path.join(ROOT, 'raw'),
  rawTx:            path.join(ROOT, 'raw', 'transactions'),
  rawReceipts:      path.join(ROOT, 'raw', 'receipts'),
  rawBlocks:        path.join(ROOT, 'raw', 'blocks'),
  rawTraces:        path.join(ROOT, 'raw', 'traces'),
  rawInternalCalls: path.join(ROOT, 'raw', 'internal_calls'),
  rawStateDiffs:    path.join(ROOT, 'raw', 'state_diffs'),
  rawAbi:           path.join(ROOT, 'raw', 'abi'),
  rawContracts:     path.join(ROOT, 'raw', 'contracts'),
  rawGroundTruth:   path.join(ROOT, 'raw', 'ground_truth'),
  rawEventSigs:     path.join(ROOT, 'raw', 'event_signatures'),
  normalized:       path.join(ROOT, 'normalized'),
  decoded:          path.join(ROOT, 'decoded'),
  derived:          path.join(ROOT, 'derived'),
  signals:          path.join(ROOT, 'signals'),
  reports:          path.join(ROOT, 'reports'),
  graphs:           path.join(ROOT, 'graphs'),
  artifacts:        path.join(ROOT, 'artifacts'),
  broadcast:        path.join(ROOT, 'broadcast'),
};

/**
 * Redirect ALL output paths into runs/<runId>/.
 * Raw evidence is read from the default raw/ folder,
 * but all pipeline outputs go into the run folder.
 *
 * @param {string} runId — e.g. "2026-03-17_00-30-15"
 * @returns {string} the absolute run directory path
 */
export function setRunDir(runId) {
  const runDir = path.join(ROOT, 'runs', runId);
  fs.mkdirSync(runDir, { recursive: true });

  // Copy raw evidence reference into run folder
  PATHS.runDir     = runDir;
  PATHS.runId      = runId;

  // Output paths → all inside the run folder
  PATHS.normalized = path.join(runDir, 'normalized');
  PATHS.decoded    = path.join(runDir, 'decoded');
  PATHS.derived    = path.join(runDir, 'derived');
  PATHS.signals    = path.join(runDir, 'signals');
  PATHS.reports    = path.join(runDir, 'reports');
  PATHS.graphs     = path.join(runDir, 'graphs');

  console.log(`📂 Run output directory: ${runDir}`);
  return runDir;
}

// ─── Ollama ─────────────────────────────────────────────────
export const OLLAMA = {
  url:   process.env.OLLAMA_URL   || 'http://127.0.0.1:11434',
  model: process.env.OLLAMA_MODEL || 'gemma3:1b',
};

// ─── Forensic thresholds ────────────────────────────────────
export const THRESHOLDS = {
  /** Mint amounts above this factor × baseline-max are flagged */
  largeMultiplier:        10,
  /** Rapid follow-up: blocks between mint and first move */
  rapidFollowupBlocks:    5,
  /** Baseline-deviation: suspicious / baseline-max ratio for high score */
  highDeviationThreshold: 100,
};
