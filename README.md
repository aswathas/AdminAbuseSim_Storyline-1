# Blockchain Forensics MVP — Privileged Mint & Extraction

> A local, file-based, deterministic blockchain forensics MVP that detects and analyzes a simulated **privileged mint and rapid extraction** attack.

## 🎯 Attack Story

A privileged actor (contract owner) abuses their `mint` function to create abnormally large tokens, then rapidly extracts them through a staging wallet to an exit wallet:

```
Owner (privileged) ──mint 1M tokens──▶ Self
                    ──transfer──▶ Staging Wallet
                                 ──transfer──▶ Exit Wallet
```

## 🔬 Two Analysis Modes

This MVP runs the **exact same forensic pipeline** in two modes to demonstrate a core principle:

> **ABI is enrichment, not the foundation of detection.**

| Aspect | Without ABI | With ABI |
|--------|-------------|----------|
| Function names | `unknown_sensitive_like_call` | `mint` |
| Event names | `Transfer (standard ERC20 pattern)` | `Transfer` |
| Decode confidence | low–medium | high |
| Signal name | Possible Privileged Asset Extraction | Abnormal Privileged Mint and Extraction |
| **Detection result** | **Same — HIGH confidence** | **Same — HIGH confidence** |

Both modes use the **same derived schema**, the **same heuristics** (H1+H2+H3), and produce the **same signal**.

## 📁 Folder Structure

```
forensics-mvp/
├── src/DemoToken.sol              # Minimal ERC20-like token with owner-restricted mint
├── script/
│   ├── Deploy.s.sol               # Foundry deployment script
│   └── SimulateAttack.s.sol       # Full attack simulation (baseline + suspicious)
├── detector/
│   ├── config.js                  # Central configuration (accounts, selectors, paths)
│   ├── exportRaw.js               # A. Raw evidence collection from Anvil
│   ├── normalize.js               # B. Convert raw → clean structured records
│   ├── decode.js                  # C. Human-readable decoded views (ABI / non-ABI)
│   ├── derive.js                  # D. Generalized derived forensic schema
│   ├── heuristics.js              # E. Rule-based detection (H1, H2, H3)
│   ├── signals.js                 # F. Final analyst-facing suspicious findings
│   ├── reportOllama.js            # G. Ollama narrative report generation
│   ├── graphs.js                  # H. Trace graph + incident timeline
│   └── runPipeline.js             # Full pipeline orchestrator
├── raw/                           # Exact blockchain evidence
│   ├── transactions/              # Raw transaction data
│   ├── receipts/                  # Raw receipt + log data
│   ├── blocks/                    # Raw block data
│   ├── traces/                    # debug_traceTransaction (callTracer)
│   ├── state_diffs/               # prestateTracer with diffMode
│   ├── abi/                       # ABI JSON + contract metadata
│   ├── contracts/                 # Deployed contract info
│   ├── ground_truth/              # Attack markers for validation
│   └── event_signatures/          # Known topic/selector reference
├── normalized/                    # Clean structured records
├── decoded/                       # Human-readable decoded views
│   ├── without_abi/
│   └── with_abi/
├── derived/                       # Generalized forensic facts
│   ├── without_abi/
│   └── with_abi/
├── signals/                       # Final suspicious findings
│   ├── without_abi/
│   └── with_abi/
├── reports/                       # Ollama narrative reports
├── graphs/                        # Trace graph + timeline (JSON + Mermaid)
├── package.json
├── foundry.toml
└── .env.example
```

## 🔧 Prerequisites

- **Foundry** (forge, anvil, cast) — [Install](https://book.getfoundry.sh/getting-started/installation)
- **Node.js** ≥ 18
- **Ollama** (optional, for narrative reports) — [Install](https://ollama.ai)

## 🚀 Quick Start — End-to-End

```bash
# 1. Install Node.js dependencies
cd forensics-mvp
npm install

# 2. Start Anvil (local EVM chain) — keep this running in a separate terminal
anvil --host 127.0.0.1 --port 8545 --block-time 1

# 3. Deploy DemoToken contract
forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast

# 4. Run attack simulation (baseline activity + suspicious incident)
forge script script/SimulateAttack.s.sol --rpc-url http://127.0.0.1:8545 --broadcast

# 5. Export raw evidence from Anvil
node detector/exportRaw.js

# 6. Run full forensic pipeline (both modes)
node detector/runPipeline.js all

# 7. (Optional) Generate Ollama reports if Ollama is running
#    ollama pull llama3.2
node detector/reportOllama.js all
```

## 📊 Inspect Results

### Raw Evidence
```bash
# Raw transactions and receipts
cat raw/transactions/_all_transactions.json
cat raw/receipts/_all_receipts.json

# Raw ABI (enrichment only)
cat raw/abi/DemoToken.abi.json
cat raw/abi/DemoToken.metadata.json

# Raw traces and state diffs
ls raw/traces/
ls raw/state_diffs/

# Ground-truth attack markers
cat raw/ground_truth/attack_markers.json
```

### Decoded Views
```bash
# Without ABI — generic decoding
cat decoded/without_abi/decoded_summary.json

# With ABI — precise function/event names
cat decoded/with_abi/decoded_summary.json
```

### Derived Facts
```bash
cat derived/without_abi/derived_facts.json
cat derived/with_abi/derived_facts.json
```

### Heuristics & Signals
```bash
cat derived/without_abi/heuristic_results.json
cat signals/without_abi/signal_summary.json
cat signals/with_abi/signal_summary.json
```

### Graphs
```bash
# Trace graph (value flow) — JSON + Mermaid
cat graphs/trace_graph_without_abi.json
cat graphs/trace_graph_without_abi.mmd

# Incident timeline — JSON + Mermaid
cat graphs/incident_timeline_without_abi.json
cat graphs/incident_timeline_without_abi.mmd
```

### Ground-Truth Validation
Compare the ground-truth markers with the pipeline outputs:
```bash
# Ground truth
cat raw/ground_truth/attack_markers.json

# Signal output — should match the same suspicious tx hashes
cat signals/without_abi/signals.json
cat signals/with_abi/signals.json
```

## 🧠 Pipeline Architecture

```
Raw Evidence → Normalization → Decoded View → Derived Facts → Heuristics → Signal → Ollama Report
                                                                                  → Graph Views
```

### Heuristics
| ID | Name | Logic |
|----|------|-------|
| H1 | Sensitive Action With Large Movement | Sensitive/mint-like action with token movement > 10× baseline |
| H2 | Rapid Follow-Up Extraction | Tokens move to staging/exit within 5 blocks |
| H3 | Deviation From Baseline | Suspicious amount > 100× normal baseline activity |

### Signal Firing
- **Medium** → H1 only
- **High** → H1 + H2
- **High (strongest)** → H1 + H2 + H3

## 🏗️ Design Principles

1. **ABI is enrichment, not the foundation** — Detection works without ABI
2. **Same derived schema** in both modes — Only decoding richness differs
3. **Raw evidence is preserved** — Decoded interpretation never overwrites raw
4. **Ground-truth validation** — Explicit markers enable accuracy verification
5. **File-based, deterministic** — Easy to rerun and inspect manually
6. **Ollama explains, rules detect** — LLM is the narrator, not the detector

## 📝 License

MIT
