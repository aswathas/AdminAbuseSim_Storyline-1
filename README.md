# AdminAttackSim — Blockchain Forensics MVP

> A local, deterministic blockchain forensics tool that simulates and detects **privileged mint and rapid extraction** attacks on EVM chains.

## 🎯 What Does This Do?

1. **Simulates** an insider attack on a local Ethereum chain
2. **Collects** complete raw evidence (transactions, traces, state diffs, ABI)
3. **Analyzes** the evidence through a multi-stage forensic pipeline
4. **Detects** the attack using deterministic heuristic rules
5. **Generates** two detailed forensic reports per analysis mode

📖 **Full detailed explanation**: See [SIMULATION_REPORT.md](SIMULATION_REPORT.md) for complete documentation of the attack, detection methodology, and pipeline architecture.

---

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Installation (New Laptop Setup)](#-installation-new-laptop-setup)
- [Quick Start](#-quick-start)
- [Configurable Simulation](#-configurable-simulation)
- [Understanding The Output](#-understanding-the-output)
- [Project Structure](#-project-structure)
- [Two Analysis Modes](#-two-analysis-modes)
- [Stress Testing](#-stress-testing)
- [Troubleshooting](#-troubleshooting)

---

## 🔧 Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **Node.js** | ≥ 18.x | Forensic pipeline runtime |
| **Foundry** (forge, anvil, cast) | Latest | Smart contract compilation + local EVM chain |
| **Ollama** | Latest (optional) | LLM narrative report generation |
| **Git** | Any | Version control |

---

## 🚀 Installation (New Laptop Setup)

### Step 1: Install Node.js

**Windows** (recommended):
```powershell
# Download and install from https://nodejs.org/ (LTS version)
# Or via winget:
winget install OpenJS.NodeJS.LTS

# Verify:
node --version    # Should show v18.x or higher
npm --version
```

**macOS**:
```bash
brew install node
```

**Linux**:
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Step 2: Install Foundry (Forge, Anvil, Cast)

**Windows (PowerShell)**:
```powershell
# Install foundryup
curl -L https://foundry.paradigm.xyz | bash

# Then run foundryup (may need to restart terminal)
foundryup

# Verify:
forge --version
anvil --version
cast --version
```

**macOS / Linux**:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

> **Note**: On Windows, Foundry installs to `%USERPROFILE%\.foundry\bin`. You may need to add this to your PATH or restart your terminal.

### Step 3: Install Ollama (Optional — for LLM reports)

**Windows**: Download from [https://ollama.ai](https://ollama.ai)

**macOS**:
```bash
brew install ollama
```

**Linux**:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

After installing:
```bash
# Start Ollama service
ollama serve

# Pull the model (in a separate terminal)
ollama pull gemma3:1b
```

### Step 4: Clone & Setup The Project

```bash
# Clone the repository
git clone <your-repo-url>
cd AdminAttackSim/forensics-mvp

# Install Foundry dependencies
forge install foundry-rs/forge-std --no-git

# Install Node.js dependencies
npm install

# Build the smart contracts
forge build

# copy environment file
cp .env.example .env
```

### Step 5: Verify Everything Works

```bash
# Check all tools are available:
node --version       # ≥ 18.x
forge --version      # Should show foundry version
anvil --version      # Should show anvil version

# Quick test — start Anvil (should print account info):
anvil --host 127.0.0.1 --port 8545 --block-time 1
# Press Ctrl+C to stop after verifying it works
```

---

## ⚡ Quick Start

### Option A: Automated (Recommended)

```bash
# Terminal 1: Start the local EVM chain
anvil --host 127.0.0.1 --port 8545 --block-time 1

# Terminal 2: Run simulation + analysis
cd forensics-mvp

# Simulate attack (1 attack, auto-baseline)
node detector/simulate.js --attacks 1

# Run full forensic pipeline
node detector/runPipeline.js all
```

### Option B: Using Foundry Scripts (Original Method)

```bash
# Terminal 1: Anvil
anvil --host 127.0.0.1 --port 8545 --block-time 1

# Terminal 2: Deploy + Simulate + Analyze
cd forensics-mvp
forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
forge script script/SimulateAttack.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
node detector/exportRaw.js
node detector/runPipeline.js all
```

### What Happens

1. Anvil starts a local blockchain with 10 pre-funded accounts
2. `simulate.js` deploys DemoToken, generates baseline noise, runs attack cycles
3. `exportRaw.js` is auto-called to collect all evidence from the chain
4. `runPipeline.js` runs normalization → decoding → derivation → heuristics → signals → reports → graphs
5. All outputs are saved to `runs/<timestamp>/`

---

## 🎛️ Configurable Simulation

The Node.js simulator accepts CLI arguments for flexible testing:

```bash
# Default: 1 attack, 5 baseline transactions
node detector/simulate.js

# Custom attacks and baseline
node detector/simulate.js --attacks 5 --baseline 20

# Just set attacks (baseline auto-scales to 3× attacks)
node detector/simulate.js --attacks 10

# Stress tests
node detector/simulate.js --attacks 100 --baseline 200
node detector/simulate.js --attacks 1000 --baseline 2000
```

### npm shortcuts

```bash
npm run sim                  # Default: 1 attack
npm run sim:stress           # 100 attacks + 200 baseline
npm run sim -- --attacks 50  # Custom via npm
```

### Transaction Count

```
Total = 1 (deploy) + baseline + (attacks × 3)

1 attack, 5 baseline   →  9 transactions
5 attacks, 20 baseline  →  36 transactions
100 attacks, 200 base   →  501 transactions
```

---

## 📊 Understanding The Output

### Runs Folder

Every pipeline run creates a timestamped folder:

```
runs/
└── 2026-03-17_01-06-13/
    ├── run_manifest.json           ← Run metadata
    ├── raw_snapshot/               ← Evidence snapshot
    ├── normalized/                 ← Structured records
    ├── decoded/
    │   ├── without_abi/            ← Generic decoded views
    │   └── with_abi/               ← ABI-decoded views
    ├── derived/
    │   ├── without_abi/            ← Forensic facts + heuristics
    │   └── with_abi/
    ├── signals/
    │   ├── without_abi/            ← Suspicious findings
    │   └── with_abi/
    ├── reports/
    │   ├── decoded_forensic_report_without_abi.md    ← Tool accuracy report
    │   ├── decoded_forensic_report_with_abi.md       ← Tool accuracy report
    │   ├── narrative_forensic_report_without_abi.md  ← Ollama LLM report
    │   └── narrative_forensic_report_with_abi.md     ← Ollama LLM report
    └── graphs/
        ├── trace_graph_*.json / *.mmd               ← Value flow
        └── incident_timeline_*.json / *.mmd          ← Event sequence
```

### Key Files To Check

```bash
# Signal summary — quick yes/no on detection
cat runs/*/signals/with_abi/signal_summary.json

# Decoded forensic report — full accuracy scorecard
cat runs/*/reports/decoded_forensic_report_with_abi.md

# Narrative report — LLM explanation
cat runs/*/reports/narrative_forensic_report_with_abi.md

# Trace graph — visual fund flow (open in Mermaid viewer)
cat runs/*/graphs/trace_graph_with_abi.mmd
```

---

## 📁 Project Structure

```
forensics-mvp/
├── src/
│   └── DemoToken.sol                 # Minimal ERC20 with owner-only mint
├── script/
│   ├── Deploy.s.sol                  # Foundry deployment script
│   └── SimulateAttack.s.sol          # Legacy Foundry simulation (1 attack)
├── detector/
│   ├── config.js                     # Central config (accounts, paths, thresholds)
│   ├── simulate.js                   # ⭐ Configurable Node.js simulator
│   ├── exportRaw.js                  # Raw evidence collection
│   ├── normalize.js                  # Raw → structured records
│   ├── decode.js                     # Decoded views (ABI / non-ABI)
│   ├── derive.js                     # Forensic facts schema
│   ├── heuristics.js                 # H1, H2, H3 detection rules
│   ├── signals.js                    # Final suspicious findings
│   ├── reportOllama.js               # ⭐ Two-report generator
│   ├── graphs.js                     # Trace + timeline graphs
│   └── runPipeline.js                # Pipeline orchestrator (runs/ system)
├── runs/                             # ⭐ Per-run output (git-ignored)
├── raw/                              # Raw evidence (git-ignored)
├── SIMULATION_REPORT.md              # ⭐ Full attack & detection docs
├── README.md                         # This file
├── package.json
├── foundry.toml
├── .env.example
└── .gitignore
```

---

## 🔬 Two Analysis Modes

| Aspect | Without ABI | With ABI |
|--------|-------------|----------|
| Function labels | `unknown_sensitive_like_call` | `mint` |
| Event labels | `Transfer (standard ERC20 pattern)` | `Transfer` |
| Confidence | Low–Medium | High |
| Signal name | Possible Privileged Asset Extraction | Abnormal Privileged Mint and Extraction |
| **Detection result** | **✅ HIGH** | **✅ HIGH** |

> ABI is enrichment, not the foundation.

---

## 🏋️ Stress Testing

```bash
# Anvil (Terminal 1)
anvil --host 127.0.0.1 --port 8545 --block-time 1

# Stress test (Terminal 2)
node detector/simulate.js --attacks 100 --baseline 200
node detector/runPipeline.js all

# Check accuracy
cat runs/*/reports/decoded_forensic_report_with_abi.md | head -50
```

Expected at any scale: **100% recall, 100% precision, 0% false positives**.

---

## 🔧 Troubleshooting

### "forge not found"
```bash
# Add Foundry to PATH (Windows):
$env:PATH = "$env:USERPROFILE\.foundry\bin;$env:PATH"

# Or run foundryup again:
foundryup
```

### "Connection refused" on exportRaw.js
```bash
# Make sure Anvil is running:
anvil --host 127.0.0.1 --port 8545 --block-time 1
```

### "Ollama unavailable" in reports
```bash
# Start Ollama first:
ollama serve
ollama pull gemma3:1b

# The decoded forensic report works without Ollama
# Only the narrative report needs it
```

### "Contract artifact not found"
```bash
# Build contracts first:
forge build
```

### Empty runs/ folder
```bash
# Make sure you ran the simulation + export before pipeline:
node detector/simulate.js --attacks 1
node detector/runPipeline.js all
```

---

## 📝 Design Principles

1. **ABI is enrichment, not the foundation** — Detection works without ABI
2. **Same derived schema** in both modes — Only decode richness differs
3. **Raw evidence is preserved** — Decoded views never overwrite raw
4. **Ground-truth validation** — Every run can be validated against markers
5. **File-based, deterministic** — Each run is self-contained in runs/
6. **Ollama explains, rules detect** — LLM narrates, heuristics decide
7. **Configurable** — Scale from 1 to 1000+ attacks

---

## 📝 License

MIT
