/**
 * graphs.js — Forensic graph generation.
 *
 * Graph 1: Trace Graph (value flow path)
 * Graph 2: Incident Timeline (event order)
 *
 * Outputs: JSON + Mermaid (.mmd)
 *
 * Usage:  node detector/graphs.js [with_abi|without_abi]
 */
import fs from 'fs';
import path from 'path';
import { PATHS, ACCOUNTS } from './config.js';

function readJSON(fp) { return JSON.parse(fs.readFileSync(fp, 'utf-8')); }
function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

function shortAddr(addr) {
  if (!addr) return 'null';
  return addr.slice(0, 6) + '...' + addr.slice(-4);
}

function formatAmount(wei) {
  if (!wei || wei === '0') return '0';
  try {
    const val = BigInt(wei);
    const eth = val / (10n ** 18n);
    const remainder = val % (10n ** 18n);
    if (remainder === 0n) return eth.toString();
    return `${eth}.${remainder.toString().padStart(18, '0').replace(/0+$/, '')}`;
  } catch {
    return wei;
  }
}

export function generateGraphs(mode = 'without_abi') {
  console.log(`📊 Generating graphs (${mode})...`);
  ensureDir(PATHS.graphs);

  const normalized   = readJSON(path.join(PATHS.normalized, 'normalized_records.json'));
  const derivedFacts = readJSON(path.join(PATHS.derived, mode, 'derived_facts.json'));
  const signals      = readJSON(path.join(PATHS.signals, mode, 'signals.json'));
  const groundTruth  = readJSON(path.join(PATHS.rawGroundTruth, 'attack_markers.json'));
  const contracts    = readJSON(path.join(PATHS.rawContracts, 'deployed_contracts.json'));

  const tokenAddress = contracts.DemoToken.address;

  // Build derived facts map
  const factMap = {};
  for (const f of derivedFacts) factMap[f.txHash] = f;

  // ═══════════════════════════════════════════════════════════
  // GRAPH 1: TRACE GRAPH (value flow)
  // ═══════════════════════════════════════════════════════════

  // Build nodes from all relevant addresses
  const addressRoles = {
    [tokenAddress.toLowerCase()]:        { label: 'DemoToken Contract', role: 'contract' },
    [ACCOUNTS.owner.toLowerCase()]:      { label: 'Owner/Privileged Actor', role: 'privileged_actor' },
    [ACCOUNTS.user1.toLowerCase()]:      { label: 'User 1', role: 'user' },
    [ACCOUNTS.user2.toLowerCase()]:      { label: 'User 2', role: 'user' },
    [ACCOUNTS.staging.toLowerCase()]:    { label: 'Staging Wallet', role: 'staging' },
    [ACCOUNTS.exit.toLowerCase()]:       { label: 'Exit Wallet', role: 'exit' },
  };

  const nodes = [];
  const seenAddresses = new Set();

  for (const record of normalized) {
    for (const addr of [record.actorAddress, record.targetAddress, record.primaryTransferFrom, record.primaryTransferTo]) {
      if (addr && !seenAddresses.has(addr.toLowerCase())) {
        seenAddresses.add(addr.toLowerCase());
        const info = addressRoles[addr.toLowerCase()] || { label: shortAddr(addr), role: 'unknown' };
        const isSuspicious = addr.toLowerCase() === ACCOUNTS.owner.toLowerCase() ||
                            addr.toLowerCase() === ACCOUNTS.staging.toLowerCase() ||
                            addr.toLowerCase() === ACCOUNTS.exit.toLowerCase();

        nodes.push({
          address:       addr,
          label:         info.label,
          role:          info.role,
          suspicious:    isSuspicious && record.isSuspicious,
          attack_linked: record.groundTruthLinked,
        });
      }
    }
  }

  // Build edges from token transfer events
  const edges = [];
  for (const record of normalized) {
    if (!record.hasTokenTransfer) continue;
    for (const transfer of record.tokenTransfers) {
      const fact = factMap[record.txHash];
      const isSuspicious = record.isSuspicious;

      let actionType = 'transfer';
      if (record.classification === 'suspicious_mint' || record.classification === 'baseline_mint') {
        actionType = 'mint';
      }

      edges.push({
        source:                      transfer.from,
        destination:                 transfer.to,
        amount:                      transfer.amount,
        amountFormatted:             formatAmount(transfer.amount),
        txHash:                      record.txHash,
        blockNumber:                 record.blockNumber,
        actionType,
        suspicious:                  isSuspicious,
        ground_truth_attack_linked:  record.groundTruthLinked,
        classification:              record.classification,
      });
    }
  }

  const traceGraph = { nodes, edges };
  fs.writeFileSync(
    path.join(PATHS.graphs, `trace_graph_${mode}.json`),
    JSON.stringify(traceGraph, null, 2)
  );

  // Generate Mermaid for trace graph
  const mermaidTrace = generateTraceMermaid(traceGraph, tokenAddress);
  fs.writeFileSync(path.join(PATHS.graphs, `trace_graph_${mode}.mmd`), mermaidTrace);

  console.log(`✅ Trace graph: ${edges.length} edges, ${nodes.length} nodes`);

  // ═══════════════════════════════════════════════════════════
  // GRAPH 2: INCIDENT TIMELINE
  // ═══════════════════════════════════════════════════════════

  const timeline = [];

  for (const record of normalized) {
    const fact = factMap[record.txHash];
    let eventLabel;

    switch (record.classification) {
      case 'contract_deployment':
        eventLabel = 'Contract Deployed';
        break;
      case 'baseline_mint':
        eventLabel = `Baseline Mint (${formatAmount(record.primaryTransferAmount)} DEMO)`;
        break;
      case 'baseline_transfer':
        eventLabel = `Normal Transfer (${formatAmount(record.primaryTransferAmount)} DEMO)`;
        break;
      case 'suspicious_mint':
        eventLabel = `⚠️ SUSPICIOUS MINT (${formatAmount(record.primaryTransferAmount)} DEMO)`;
        break;
      case 'suspicious_staging_transfer':
        eventLabel = `⚠️ Staging Transfer (${formatAmount(record.primaryTransferAmount)} DEMO)`;
        break;
      case 'suspicious_exit_transfer':
        eventLabel = `⚠️ Exit Transfer (${formatAmount(record.primaryTransferAmount)} DEMO)`;
        break;
      default:
        eventLabel = record.classification || 'Unknown Event';
    }

    timeline.push({
      order:          timeline.length + 1,
      blockNumber:    record.blockNumber,
      timestamp:      record.timestamp,
      txHash:         record.txHash,
      classification: record.classification,
      eventLabel,
      actor:          record.actorAddress,
      suspicious:     record.isSuspicious,
      attackLinked:   record.groundTruthLinked,
    });
  }

  // Add signal-fired event
  if (signals.length > 0) {
    timeline.push({
      order:          timeline.length + 1,
      blockNumber:    signals[0].blockNumber,
      timestamp:      null,
      txHash:         null,
      classification: 'signal_fired',
      eventLabel:     `🚨 SIGNAL: ${signals[0].signalName} [${signals[0].confidence}]`,
      actor:          null,
      suspicious:     true,
      attackLinked:   true,
    });
  }

  const timelineGraph = { timeline };
  fs.writeFileSync(
    path.join(PATHS.graphs, `incident_timeline_${mode}.json`),
    JSON.stringify(timelineGraph, null, 2)
  );

  // Generate Mermaid for timeline
  const mermaidTimeline = generateTimelineMermaid(timeline);
  fs.writeFileSync(path.join(PATHS.graphs, `incident_timeline_${mode}.mmd`), mermaidTimeline);

  console.log(`✅ Timeline: ${timeline.length} events`);
  console.log(`✅ Graphs written → ${PATHS.graphs}`);
}

// ─── Mermaid generators ─────────────────────────────────────

function generateTraceMermaid(graph, tokenAddress) {
  let mmd = 'graph LR\n';

  // Define nodes with styles
  const nodeIds = {};
  let counter = 0;

  for (const node of graph.nodes) {
    const id = `N${counter++}`;
    nodeIds[node.address.toLowerCase()] = id;
    const label = `${node.label}\\n${shortAddr(node.address)}`;
    if (node.role === 'contract') {
      mmd += `    ${id}[["${label}"]]\n`;
    } else if (node.role === 'privileged_actor') {
      mmd += `    ${id}(("${label}"))\n`;
    } else {
      mmd += `    ${id}["${label}"]\n`;
    }
  }

  // Add zero-address for mint source
  nodeIds['0x0000000000000000000000000000000000000000'] = 'ZERO';
  mmd += `    ZERO(("Zero Address\\n(Mint Source)"))\n`;

  mmd += '\n';

  // Define edges
  for (const edge of graph.edges) {
    const srcId  = nodeIds[edge.source.toLowerCase()] || 'UNKNOWN';
    const dstId  = nodeIds[edge.destination.toLowerCase()] || 'UNKNOWN';
    const label  = `${edge.amountFormatted} DEMO\\n${edge.actionType}`;

    if (edge.suspicious) {
      mmd += `    ${srcId} ==>|"${label}"| ${dstId}\n`;
    } else {
      mmd += `    ${srcId} -->|"${label}"| ${dstId}\n`;
    }
  }

  // Styles
  mmd += '\n';
  mmd += '    style ZERO fill:#666,stroke:#333,color:#fff\n';
  for (const node of graph.nodes) {
    const id = nodeIds[node.address.toLowerCase()];
    if (node.role === 'privileged_actor') {
      mmd += `    style ${id} fill:#e74c3c,stroke:#c0392b,color:#fff\n`;
    } else if (node.role === 'staging') {
      mmd += `    style ${id} fill:#e67e22,stroke:#d35400,color:#fff\n`;
    } else if (node.role === 'exit') {
      mmd += `    style ${id} fill:#c0392b,stroke:#922b21,color:#fff\n`;
    } else if (node.role === 'contract') {
      mmd += `    style ${id} fill:#3498db,stroke:#2980b9,color:#fff\n`;
    }
  }

  return mmd;
}

function generateTimelineMermaid(timeline) {
  let mmd = 'gantt\n';
  mmd += '    title Incident Timeline\n';
  mmd += '    dateFormat X\n';
  mmd += '    axisFormat %s\n\n';

  mmd += '    section Baseline Activity\n';
  for (const event of timeline) {
    if (!event.suspicious && event.classification !== 'signal_fired') {
      const safeLabel = event.eventLabel.replace(/"/g, "'");
      mmd += `    ${safeLabel} :${event.order}, ${event.order}\n`;
    }
  }

  mmd += '\n    section Suspicious Activity\n';
  for (const event of timeline) {
    if (event.suspicious && event.classification !== 'signal_fired') {
      const safeLabel = event.eventLabel.replace(/"/g, "'");
      mmd += `    ${safeLabel} :crit, ${event.order}, ${event.order}\n`;
    }
  }

  mmd += '\n    section Signal\n';
  for (const event of timeline) {
    if (event.classification === 'signal_fired') {
      const safeLabel = event.eventLabel.replace(/"/g, "'");
      mmd += `    ${safeLabel} :crit, ${event.order}, ${event.order}\n`;
    }
  }

  return mmd;
}

// Run directly
if (process.argv[1] && process.argv[1].includes('graphs')) {
  const mode = process.argv[2] || 'without_abi';
  if (mode === 'all') {
    generateGraphs('without_abi');
    generateGraphs('with_abi');
  } else {
    generateGraphs(mode);
  }
}
