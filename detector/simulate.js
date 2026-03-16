/**
 * simulate.js — Configurable attack simulation using ethers.js + Anvil.
 *
 * Deploys DemoToken, generates baseline noise, and runs N attack cycles.
 * Each attack cycle: suspicious mint → staging transfer → exit transfer.
 *
 * Usage:
 *   node detector/simulate.js                         # defaults: 5 baseline txs, 1 attack
 *   node detector/simulate.js --attacks 10             # 10 attacks, auto baseline
 *   node detector/simulate.js --attacks 5 --baseline 20  # 5 attacks, 20 baseline txs
 *   node detector/simulate.js --attacks 100 --baseline 200  # stress test
 *
 * After simulation completes, it automatically runs exportRaw.js.
 *
 * ═══════════════════════════════════════════════════════════════════
 * ATTACK EXPLAINED:
 *
 * Attack Type: PRIVILEGED MINT AND RAPID EXTRACTION
 *
 * This simulates an insider/admin attack where:
 *   1. The contract OWNER (a privileged role) abuses the owner-only
 *      `mint(address,uint256)` function to create abnormally large
 *      amounts of tokens — far exceeding normal operational mints.
 *   2. The freshly minted tokens are immediately TRANSFERRED to a
 *      staging wallet (an intermediary address controlled by the attacker).
 *   3. The staging wallet quickly moves all tokens to an EXIT wallet,
 *      simulating the start of an off-ramp or laundering chain.
 *
 * This is a common real-world attack pattern seen in rug pulls, admin
 * key compromises, and insider theft on DeFi protocols.
 *
 * The forensic pipeline detects this by:
 *   H1: Flagging sensitive mint actions with abnormally large amounts
 *   H2: Detecting rapid fund extraction after the suspicious action
 *   H3: Measuring extreme deviation from historical baseline activity
 *
 * Each attack cycle generates exactly 3 suspicious transactions:
 *   [suspicious_mint] → [staging_transfer] → [exit_transfer]
 *
 * The baseline generates normal-looking mints (small amounts) and
 * transfers between user addresses to create noise for the detector.
 * ═══════════════════════════════════════════════════════════════════
 */
import { ethers } from 'ethers';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ACCOUNTS, PRIVATE_KEYS, RPC_URL, PATHS } from './config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// ─── Parse CLI arguments ────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  let attacks  = 1;
  let baseline = 5;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--attacks' && args[i + 1])  attacks  = parseInt(args[i + 1], 10);
    if (args[i] === '--baseline' && args[i + 1]) baseline = parseInt(args[i + 1], 10);
  }

  // Auto-scale baseline if not explicitly set
  if (!args.includes('--baseline')) {
    baseline = Math.max(5, attacks * 3);  // ~3 baseline per attack for realism
  }

  return { attacks, baseline };
}

// ─── Load compiled contract ABI + bytecode ──────────────────
function loadContractArtifact() {
  const artifactPath = path.join(PATHS.root, 'out', 'DemoToken.sol', 'DemoToken.json');
  if (!fs.existsSync(artifactPath)) {
    console.error(`❌ Contract artifact not found at ${artifactPath}`);
    console.error(`   Run 'forge build' first.`);
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(artifactPath, 'utf-8'));
}

// ─── Random helpers ─────────────────────────────────────────
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Deterministic but varied staging/exit wallets from Anvil's 10 accounts
// Anvil accounts 0-9:
const ANVIL_ACCOUNTS = [
  { addr: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', key: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' },
  { addr: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', key: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' },
  { addr: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC', key: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' },
  { addr: '0x90F79bf6EB2c4f870365E785982E1f101E93b906', key: '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6' },
  { addr: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65', key: '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a' },
  { addr: '0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc', key: '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba' },
  { addr: '0x976EA74026E726554dB657fA54763abd0C3a0aa9', key: '0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e' },
  { addr: '0x14dC79964da2C08dda4eA60b4d6E5e10ceE7Facd', key: '0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356' },
  { addr: '0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f', key: '0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97' },
  { addr: '0xa0Ee7A142d267C1f36714E4a8F75612F20a79720', key: '0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6' },
];

// ─── Main simulation ────────────────────────────────────────
async function main() {
  const { attacks, baseline } = parseArgs();
  const totalTxs = 1 + baseline + (attacks * 3);  // 1 deploy + baseline + 3 per attack

  console.log(`\n${'█'.repeat(60)}`);
  console.log(`  CONFIGURABLE ATTACK SIMULATION`);
  console.log(`${'█'.repeat(60)}`);
  console.log(`\n  Attack type:     Privileged Mint & Rapid Extraction`);
  console.log(`  Attacks:         ${attacks}`);
  console.log(`  Baseline txs:    ${baseline}`);
  console.log(`  Total expected:  ~${totalTxs} transactions`);
  console.log(`  Suspicious txs:  ${attacks * 3} (${attacks} × [mint + staging + exit])`);
  console.log(`  RPC:             ${RPC_URL}\n`);

  // Connect to Anvil
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const artifact = loadContractArtifact();

  // Owner wallet (account 0)
  const ownerWallet = new ethers.Wallet(ANVIL_ACCOUNTS[0].key, provider);
  console.log(`  Owner:  ${ownerWallet.address}`);

  // User wallets for baseline (accounts 1-2)
  const userWallets = [
    new ethers.Wallet(ANVIL_ACCOUNTS[1].key, provider),
    new ethers.Wallet(ANVIL_ACCOUNTS[2].key, provider),
  ];

  // Staging wallets (account 3)
  const stagingWallet = new ethers.Wallet(ANVIL_ACCOUNTS[3].key, provider);
  // Exit wallets (account 4)
  const exitWallet = new ethers.Wallet(ANVIL_ACCOUNTS[4].key, provider);

  console.log(`  Staging: ${stagingWallet.address}`);
  console.log(`  Exit:    ${exitWallet.address}\n`);

  // ─── Step 1: Deploy contract ──────────────────────────────
  console.log(`📦 Deploying DemoToken...`);
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, ownerWallet);
  const token = await factory.deploy();
  await token.waitForDeployment();
  const tokenAddress = await token.getAddress();
  console.log(`   ✅ Deployed at: ${tokenAddress}\n`);

  // Track all tx hashes for classification
  const txLog = [];
  let txCount = 0;
  const progressInterval = Math.max(1, Math.floor(totalTxs / 20)); // Log every 5%

  function logProgress(label) {
    txCount++;
    if (txCount % progressInterval === 0 || txCount === totalTxs) {
      const pct = ((txCount / totalTxs) * 100).toFixed(0);
      console.log(`   [${pct}%] ${txCount}/${totalTxs} — ${label}`);
    }
  }

  // ─── Step 2: Baseline normal activity ─────────────────────
  console.log(`📊 Generating ${baseline} baseline transactions...`);

  const baselineMintAmounts = [];
  const baselineMintCount = Math.ceil(baseline * 0.4);   // 40% mints
  const baselineTransferCount = baseline - baselineMintCount;

  // Baseline mints — small, normal amounts (10-500 DEMO)
  for (let i = 0; i < baselineMintCount; i++) {
    const amount = ethers.parseEther(String(randomInt(10, 500)));
    const recipient = randomElement(userWallets).address;
    const tx = await token.mint(recipient, amount);
    const receipt = await tx.wait();
    baselineMintAmounts.push(amount);
    txLog.push({ hash: receipt.hash, classification: 'baseline_mint', amount: amount.toString() });
    logProgress(`baseline mint ${i + 1}/${baselineMintCount}`);
  }

  // Baseline transfers — small amounts between users
  for (let i = 0; i < baselineTransferCount; i++) {
    const sender = randomElement(userWallets);
    const receiver = randomElement(userWallets);
    if (sender.address === receiver.address) continue; // skip self-transfer

    // Check balance first
    const tokenAsSender = token.connect(sender);
    const balance = await token.balanceOf(sender.address);
    if (balance === 0n) continue;

    const maxTransfer = balance / 10n; // transfer up to 10% of balance
    if (maxTransfer === 0n) continue;

    const amount = maxTransfer > ethers.parseEther('1')
      ? ethers.parseEther(String(randomInt(1, Number(ethers.formatEther(maxTransfer)))))
      : maxTransfer;

    try {
      const tx = await tokenAsSender.transfer(receiver.address, amount);
      const receipt = await tx.wait();
      txLog.push({ hash: receipt.hash, classification: 'baseline_transfer', amount: amount.toString() });
      logProgress(`baseline transfer ${i + 1}/${baselineTransferCount}`);
    } catch (_e) {
      // Insufficient balance, skip
      logProgress(`baseline transfer ${i + 1}/${baselineTransferCount} (skipped)`);
    }
  }

  console.log(`   ✅ Baseline complete: ${txLog.length} transactions\n`);

  // ─── Step 3: Attack cycles ────────────────────────────────
  console.log(`🔴 Generating ${attacks} attack cycle(s)...`);

  // Calculate suspicious mint amounts — always much larger than baseline
  const maxBaseline = baselineMintAmounts.length > 0
    ? baselineMintAmounts.reduce((a, b) => a > b ? a : b, ethers.parseEther('100'))
    : ethers.parseEther('100');

  for (let atk = 0; atk < attacks; atk++) {
    // Suspicious amount: 1000x to 50000x the max baseline
    const multiplier = randomInt(1000, 50000);
    const suspiciousAmount = maxBaseline * BigInt(multiplier) / 100n;

    console.log(`\n   🔴 Attack ${atk + 1}/${attacks}: ${ethers.formatEther(suspiciousAmount)} DEMO (${multiplier / 100}x baseline)`);

    // Step 3a: Suspicious privileged mint — owner mints to self
    const mintTx = await token.mint(ownerWallet.address, suspiciousAmount);
    const mintReceipt = await mintTx.wait();
    txLog.push({ hash: mintReceipt.hash, classification: 'suspicious_mint', amount: suspiciousAmount.toString(), attackIndex: atk });
    logProgress(`attack ${atk + 1} — suspicious mint`);

    // Step 3b: Transfer to staging wallet
    const stagingTx = await token.transfer(stagingWallet.address, suspiciousAmount);
    const stagingReceipt = await stagingTx.wait();
    txLog.push({ hash: stagingReceipt.hash, classification: 'suspicious_staging_transfer', amount: suspiciousAmount.toString(), attackIndex: atk });
    logProgress(`attack ${atk + 1} — staging transfer`);

    // Step 3c: Staging → Exit
    const tokenAsStaging = token.connect(stagingWallet);
    const exitTx = await tokenAsStaging.transfer(exitWallet.address, suspiciousAmount);
    const exitReceipt = await exitTx.wait();
    txLog.push({ hash: exitReceipt.hash, classification: 'suspicious_exit_transfer', amount: suspiciousAmount.toString(), attackIndex: atk });
    logProgress(`attack ${atk + 1} — exit transfer`);
  }

  console.log(`\n   ✅ ${attacks} attack cycle(s) complete\n`);

  // ─── Step 4: Write simulation manifest ────────────────────
  const manifest = {
    simulatedAt:         new Date().toISOString(),
    tokenAddress,
    ownerAddress:        ownerWallet.address,
    stagingAddress:      stagingWallet.address,
    exitAddress:         exitWallet.address,
    attackCount:         attacks,
    baselineCount:       baseline,
    totalTransactions:   txLog.length + 1, // +1 for deployment
    suspiciousTransactions: attacks * 3,
    baselineTransactions: txLog.filter(t => t.classification.startsWith('baseline')).length,
    transactions:        txLog,
  };

  const manifestDir = path.join(PATHS.root, 'raw', 'simulation');
  fs.mkdirSync(manifestDir, { recursive: true });
  fs.writeFileSync(path.join(manifestDir, 'simulation_manifest.json'), JSON.stringify(manifest, null, 2));

  console.log(`${'═'.repeat(60)}`);
  console.log(`  SIMULATION COMPLETE`);
  console.log(`${'═'.repeat(60)}`);
  console.log(`  Token:      ${tokenAddress}`);
  console.log(`  Total TXs:  ${txLog.length + 1}`);
  console.log(`  Baseline:   ${txLog.filter(t => t.classification.startsWith('baseline')).length}`);
  console.log(`  Suspicious: ${attacks * 3} (${attacks} attacks × 3 steps)`);
  console.log(`  Manifest:   raw/simulation/simulation_manifest.json`);
  console.log(`${'═'.repeat(60)}\n`);

  // ─── Step 5: Auto-run evidence export ─────────────────────
  console.log(`📦 Auto-running evidence export...\n`);
  const { default: exportModule } = await import('./exportRaw.js');
}

main().catch(e => {
  console.error(`\n❌ Simulation failed: ${e.message}`);
  console.error(e.stack);
  process.exit(1);
});
