# 🔬 Simulation & Detection Report — AdminAttackSim

> Complete documentation of the attack simulation, detection methodology, and how the forensic tool works.

---

## Table of Contents

1. [What Is This Tool?](#1-what-is-this-tool)
2. [The Attack: Privileged Mint & Rapid Extraction](#2-the-attack-privileged-mint--rapid-extraction)
3. [How The Simulation Works](#3-how-the-simulation-works)
4. [How The Forensic Tool Detects Attacks](#4-how-the-forensic-tool-detects-attacks)
5. [Pipeline Deep Dive](#5-pipeline-deep-dive)
6. [Two Analysis Modes: With vs Without ABI](#6-two-analysis-modes-with-vs-without-abi)
7. [Scaling: Testing With 100 or 1000 Attacks](#7-scaling-testing-with-100-or-1000-attacks)
8. [Understanding The Reports](#8-understanding-the-reports)
9. [Ground Truth & Accuracy Validation](#9-ground-truth--accuracy-validation)

---

## 1. What Is This Tool?

AdminAttackSim is a **local blockchain forensics MVP** that:

1. **Simulates** a realistic attack on a local EVM chain (Anvil)
2. **Collects** raw blockchain evidence (transactions, receipts, traces, state diffs)
3. **Analyzes** the evidence through a multi-stage forensic pipeline
4. **Detects** suspicious activity using rule-based heuristics
5. **Reports** findings via two reports: a tool-generated accuracy report and an LLM-narrated report

The tool demonstrates that **blockchain forensic detection works even without ABI access** — a critical capability for real-world investigations where contract source code is often unavailable.

---

## 2. The Attack: Privileged Mint & Rapid Extraction

### What Is This Attack?

This is an **insider/admin abuse attack** — one of the most common attack vectors in DeFi and token ecosystems. It simulates a scenario where:

> A trusted administrator (contract owner) abuses their privileged access to secretly mint an enormous quantity of tokens, then quickly moves those tokens through intermediary wallets to extract value.

### Real-World Examples

This pattern has been observed in:
- **Rug pulls**: Project owners minting tokens before dumping
- **Admin key compromises**: Stolen keys used to mint tokens
- **Insider theft**: Employees of DeFi protocols minting unauthorized tokens
- **Bridge exploits**: Minting unbacked tokens on destination chains

### Attack Anatomy

```
┌─────────────────────────────────────────────────────────────────┐
│                     ATTACK FLOW (per cycle)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Step 1: PRIVILEGED MINT                                        │
│   ─────────────────────────                                      │
│   The owner calls mint(ownerAddress, HUGE_AMOUNT)                │
│   This creates tokens from nothing (zero address → owner)        │
│   Amount: 1,000x to 50,000x the normal baseline mint            │
│                                                                  │
│   Step 2: STAGING TRANSFER                                       │
│   ────────────────────────                                       │
│   The owner calls transfer(stagingWallet, HUGE_AMOUNT)           │
│   Moves all minted tokens to an intermediary address             │
│   Purpose: distance the owner from the exit point                │
│                                                                  │
│   Step 3: EXIT TRANSFER                                          │
│   ──────────────────────                                         │
│   The staging wallet calls transfer(exitWallet, HUGE_AMOUNT)     │
│   Final hop before off-ramping or laundering                     │
│   The attacker now controls the funds at a clean address         │
│                                                                  │
│   Total suspicious transactions per attack: 3                    │
│   Total on-chain evidence per attack: 3 transactions + 3 events  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Is This Hard To Detect?

1. **The `mint` function is legitimate** — contracts have mint functions for valid reasons
2. **Individual transfers look normal** — the `transfer` function is standard ERC20
3. **No exploits involved** — no reentrancy, no flash loans, no price manipulation
4. **It's authorized** — the owner has permission to call mint
5. **Without ABI**, an analyst can't even see that `mint` was called — they only see a selector `0x40c10f19`

### What Makes It Suspicious?

- The mint **amount** is 100x-50,000x larger than historical baseline
- The funds are extracted **rapidly** — within a few blocks
- The flow path is linear: **mint → staging → exit** (no legitimate business reason)
- The owner mints to **themselves**, not to users or liquidity pools

---

## 3. How The Simulation Works

### Configurable Parameters

The simulation is fully configurable via CLI:

```bash
# Default: 1 attack, 5 baseline transactions
node detector/simulate.js

# Custom: specify attacks and baseline
node detector/simulate.js --attacks 5 --baseline 20

# Stress test: 100 attacks with 200 baseline noise
node detector/simulate.js --attacks 100 --baseline 200

# High volume: 1000 attacks
node detector/simulate.js --attacks 1000 --baseline 2000
```

### What Happens During Simulation

#### Phase 1: Contract Deployment (1 transaction)
```
Deploy DemoToken.sol → creates a minimal ERC20-like token
Functions: mint(address,uint256), transfer(address,uint256), balanceOf(address)
Owner: 0xf39F...2266 (Anvil account 0)
```

#### Phase 2: Baseline Normal Activity (N transactions)
```
40% of baseline = Normal mints (10-500 DEMO tokens to random users)
60% of baseline = Normal transfers (small amounts between users)

These establish what "normal" looks like on this contract.
The detector uses this to calculate baseline deviation scores.
```

#### Phase 3: Attack Cycles (3 × N_attacks transactions)
```
For each attack:
  1. Suspicious mint:      owner mints 1000x-50000x baseline to self
  2. Staging transfer:     owner sends all to staging wallet
  3. Exit transfer:        staging wallet sends all to exit wallet
```

### Transaction Count Formula

```
Total transactions = 1 (deploy) + baseline_count + (attacks × 3)

Examples:
  1 attack, 5 baseline  →  1 + 5 + 3  = 9 transactions
  5 attacks, 20 baseline → 1 + 20 + 15 = 36 transactions
  100 attacks, 200 base  → 1 + 200 + 300 = 501 transactions
```

### Accounts Used (Anvil Defaults)

| Account | Role | Address |
|---------|------|---------|
| Account 0 | Owner (Attacker) | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| Account 1 | User 1 (Benign) | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` |
| Account 2 | User 2 (Benign) | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` |
| Account 3 | Staging Wallet | `0x90F79bf6EB2c4f870365E785982E1f101E93b906` |
| Account 4 | Exit Wallet | `0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65` |

---

## 4. How The Forensic Tool Detects Attacks

### Detection Philosophy

> **ABI is enrichment, not the foundation of detection.**

The tool can detect this attack **even without the contract ABI**. This is critical because:
- In real investigations, source code is often unavailable
- Attackers may deploy unverified contracts
- ABI access should improve labels, not change detection outcomes

### The Three Heuristics

#### H1: Sensitive Action With Large Movement
```
IF:   The transaction calls a sensitive function (mint-like selector)
AND:  The token movement amount > 10× the baseline maximum
THEN: Flag as suspicious

This catches: Privileged mints that are abnormally large
```

#### H2: Rapid Follow-Up Extraction
```
IF:   A sensitive action (mint) was just performed
AND:  Within 5 blocks, tokens are moved to staging/exit addresses
THEN: Flag as rapid extraction

This catches: Quick fund movement after suspicious minting
```

#### H3: Deviation From Baseline
```
IF:   The token amount in this transaction > 100× the baseline maximum
THEN: Flag as extreme deviation

This catches: Any transaction with amounts that are wildly out of norm
```

### Signal Confidence Levels

```
H1 only                → MEDIUM confidence
H1 + H2               → HIGH confidence
H1 + H2 + H3          → HIGH confidence (strongest evidence)
```

In our simulation, all three typically fire → **HIGH confidence**.

---

## 5. Pipeline Deep Dive

The forensic pipeline runs in 8 sequential stages:

### Stage A: Raw Evidence Collection (`exportRaw.js`)

Connects to Anvil and collects:
- **All transactions** — full calldata, sender, receiver, value
- **All receipts** — status, gas, event logs
- **All blocks** — timestamps, block metadata
- **Trace data** — `debug_traceTransaction` with callTracer (execution trace)
- **State diffs** — `prestateTracer` with diffMode (storage changes)
- **ABI artifact** — from Foundry compile output
- **Event signatures** — known Transfer, mint selectors
- **Ground truth markers** — which transactions are suspicious (for validation)

### Stage B: Normalization (`normalize.js`)

Converts raw evidence into structured records:
- Extracts Transfer events from receipt logs
- Links transactions with their receipts
- Identifies primary token transfers (from, to, amount)
- Associates ground truth classifications

```
Input:  raw/transactions/*.json + raw/receipts/*.json
Output: normalized/normalized_records.json
```

### Stage C: Decoding (`decode.js`)

Creates human-readable decoded views based on mode:

**With ABI mode:**
```json
{
  "decodedFunctionName": "mint",
  "decodedFunctionArgs": { "to": "0xf39F...", "amount": "1000000..." },
  "decodedEvents": [{ "eventName": "Transfer", "eventFields": { "from": "0x0000...", "to": "0xf39F...", "value": "1000000..." } }],
  "decodeConfidence": "high"
}
```

**Without ABI mode:**
```json
{
  "decodedFunctionName": "unknown_sensitive_like_call",
  "decodedFunctionArgs": { "selector": "0x40c10f19", "note": "Matches known mint-like selector pattern" },
  "decodedEvents": [{ "eventName": "Transfer (standard ERC20 pattern)", "eventFields": { "from": "0x0000...", "to": "0xf39F...", "amount": "1000000...", "inferredFrom": "standard_topic_matching" } }],
  "decodeConfidence": "low"
}
```

### Stage D: Derived Facts (`derive.js`)

Populates the **Generalized Derived Forensic Schema**:

| Field | Description |
|-------|-------------|
| `actor_role_context` | owner, likely_privileged, non_privileged, unknown |
| `action_label` | mint, transfer, unknown_sensitive_like_call |
| `action_category` | sensitive, asset_movement, unknown |
| `is_sensitive_action` | true if selector matches mint-like pattern |
| `token_value_moved` | amount of tokens transferred |
| `rapid_followup_movement` | true if extraction happens within N blocks |
| `baseline_deviation_score` | Nx — how many times larger than baseline |
| `risk_hint` | privileged_mint_extraction, staging_fund_movement, etc. |
| `decode_confidence` | high (with ABI) or low/medium (without ABI) |

### Stage E: Heuristics (`heuristics.js`)

Applies H1, H2, H3 rules to each derived fact. Outputs per-transaction results:
```json
{
  "txHash": "0xbc0e...",
  "H1": { "triggered": true, "reason": "Deviation score 196x (threshold: 10x)" },
  "H2": { "triggered": true, "reason": "2 follow-up transfers within 5 blocks" },
  "H3": { "triggered": true, "reason": "196x normal activity (threshold: 100x)" },
  "anyTriggered": true
}
```

### Stage F: Signals (`signals.js`)

Generates final analyst-facing findings:
- Groups triggered heuristics
- Assigns confidence (medium/high)
- Links to ground truth
- Compiles supporting evidence chain

### Stage G: Reports (`reportOllama.js`)

Generates **two reports** per mode:

1. **Decoded Forensic Report** — Tool accuracy report with:
   - Precision, recall, false positive rate
   - Ground truth validation table
   - Transaction-by-transaction decoded breakdown
   - Attack path visualization
   - Evidence inventory

2. **Narrative Forensic Report** — Ollama (gemma3:1b) report with:
   - Professional incident summary
   - Timeline of events
   - Attack methodology analysis
   - Detection reasoning explanation
   - IOCs and next steps

### Stage H: Graphs (`graphs.js`)

Generates two graph types:

1. **Trace Graph** — Token value flow (who sent what to whom)
2. **Incident Timeline** — Chronological event sequence

Both output as JSON (machine-readable) and Mermaid (visual).

---

## 6. Two Analysis Modes: With vs Without ABI

| Aspect | WITHOUT ABI | WITH ABI |
|--------|-------------|----------|
| **Function decoding** | `unknown_sensitive_like_call` (selector matching) | `mint` (exact name from ABI) |
| **Event decoding** | `Transfer (standard ERC20 pattern)` (topic matching) | `Transfer` (with exact field names) |
| **Argument values** | Not decoded — raw calldata available | Fully decoded: `to`, `amount` |
| **Decode confidence** | Low–Medium | High |
| **Signal name** | "Possible Privileged Asset Extraction" | "Abnormal Privileged Mint and Extraction" |
| **Detection result** | ✅ SAME — HIGH confidence | ✅ SAME — HIGH confidence |
| **Heuristics fired** | H1 + H2 + H3 | H1 + H2 + H3 |
| **When to use** | Unknown contracts, unverified code | Verified contracts, known protocols |

### Key Insight

Both modes use the **exact same derived schema**, **same heuristics**, and produce the **same signal**. The difference is purely in label richness and analyst confidence in the decode:

```
Without ABI:  "Something sensitive happened with a HUGE amount, followed by rapid extraction"
With ABI:     "The owner called mint() for 87,028 DEMO (196x baseline), then rapidly transferred it out"
```

Both are correct. ABI just adds names.

---

## 7. Scaling: Testing With 100 or 1000 Attacks

### Quick Commands

```bash
# Start Anvil first
anvil --host 127.0.0.1 --port 8545 --block-time 1

# 10 attacks with noise
node detector/simulate.js --attacks 10 --baseline 30

# 100 attacks (stress test)
node detector/simulate.js --attacks 100 --baseline 200

# Export evidence then run pipeline
node detector/exportRaw.js
node detector/runPipeline.js all
```

### What To Watch For

| Scale | Transactions | Expected Signals | Caution |
|-------|-------------|-----------------|---------|
| 1 attack | ~9 | 1 signal | Quick test, fast |
| 5 attacks | ~31 | 5 signals | Good for demos |
| 10 attacks | ~61 | 10 signals | Tests consistency |
| 50 attacks | ~251 | 50 signals | Tests scaling |
| 100 attacks | ~501 | 100 signals | Moderate stress |
| 1000 attacks | ~4001 | 1000 signals | Heavy — may take minutes on Anvil |

### Accuracy Expectations

With the current heuristics:
- **Recall** should remain 100% (all attacks detected)
- **Precision** should remain 100% (no false positives on baseline mints)
- H2 may trigger on some baseline mints near attack windows (minor edge case)

---

## 8. Understanding The Reports

### Report 1: Decoded Forensic Report

This is generated **entirely by the tool** (no LLM involved). It contains:

- **Executive Summary** — Counts and overall outcome
- **Accuracy Scorecard** — Precision, recall, false positive rate with green/yellow/red ratings
- **Ground Truth Validation** — Checks each known attack tx against detection results
- **Transaction-by-Transaction Breakdown** — Every single tx with its decoded data, classification, heuristic triggers, and evidence
- **Signal Details** — Full explanation of why the signal fired
- **Attack Path Reconstruction** — ASCII diagram of the fund flow
- **Evidence Inventory** — Complete list of evidence types and counts

### Report 2: Narrative Forensic Report

This is generated **by Ollama (gemma3:1b)** as an explanation layer. It receives all pipeline evidence as context and produces a professional forensic narrative:

- Written in investigative tone
- References specific transaction hashes and addresses
- Explains the attack methodology
- Lists indicators of compromise (IOCs)
- Suggests next investigative steps

**Important**: The LLM does NOT perform detection — it only explains what the rules already found.

---

## 9. Ground Truth & Accuracy Validation

### What Is Ground Truth?

Ground truth is our "answer key" — we know exactly which transactions are attacks because we created them. This allows us to measure tool accuracy objectively.

### Ground Truth File: `raw/ground_truth/attack_markers.json`

```json
{
  "suspiciousMintTxHash": "0x...",
  "stagingTransferTxHash": "0x...",
  "exitTransferTxHash": "0x...",
  "attackCycles": [...],
  "privilegedActorAddress": "0xf39F...",
  "stagingWalletAddress": "0x90F7...",
  "exitWalletAddress": "0x15d3...",
  "baselineThreshold": "..."
}
```

### How Validation Works

The decoded forensic report compares:
```
For each ground truth attack tx:
  → Was it classified as suspicious? (detection)
  → Did the correct heuristics fire? (quality)
  → Was the signal confidence correct? (calibration)
  → Were there any false alarms? (precision)
```

### Expected Results

| Metric | Expected | Meaning |
|--------|----------|---------|
| Detection Rate (Recall) | 100% | All attacks found |
| Precision | 100% | No false alarms |
| False Positive Rate | 0% | Normal txs not flagged |
| Ground Truth Match | ✅ | Signal links to attack marker |

---

*This document is part of the AdminAttackSim Forensics MVP.*
