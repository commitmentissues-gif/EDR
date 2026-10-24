import { initDatabase, query } from '../backend/db/index.js';
import { 
  recordProcessEvent, 
  recordProcessTermination,
  getProcesses, 
  getProcessByPid, 
  getProcessTree, 
  getProcessLineage,
  getProcessTreeStats,
  seedBaselineProcesses, 
  hashSignatureCache, 
  getOrComputeExecutableHash,
  calculateProcessRisk 
} from '../backend/process/index.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  \x1b[32m✔\x1b[0m ${testName}`);
    passed++;
  } else {
    console.error(`  \x1b[31m✖\x1b[0m ${testName}${detail ? ` (${detail})` : ''}`);
    failed++;
  }
}

async function runProcessMonitoringTests() {
  console.log('\n\x1b[1m=== Running LocalEDR Process Tree & Telemetry Test Suite ===\x1b[0m\n');

  // 1. Initialize SQLite Database
  console.log('\x1b[36m[Stage 1: SQLite Schema & Indexes Verification]\x1b[0m');
  await initDatabase();

  const tables = query<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table'");
  const tableNames = tables.map(t => t.name);
  assert(tableNames.includes('process_events'), 'Table process_events exists in SQLite');

  const indexes = query<{ name: string }>("SELECT name FROM sqlite_master WHERE type='index'");
  const indexNames = indexes.map(i => i.name);
  assert(indexNames.includes('idx_process_events_pid'), 'Index on pid exists');
  assert(indexNames.includes('idx_process_events_ppid'), 'Index on parent_pid exists');
  assert(indexNames.includes('idx_process_events_name'), 'Index on process_name exists');
  assert(indexNames.includes('idx_process_events_timestamp'), 'Index on creation_timestamp exists');
  assert(indexNames.includes('idx_process_events_sha256'), 'Index on sha256 exists');
  assert(indexNames.includes('idx_process_events_exe'), 'Index on executable_path exists');

  // 2. Normal Windows Applications Baseline Seeding
  console.log('\n\x1b[36m[Stage 2: Normal Windows Applications Baseline Seeding]\x1b[0m');
  seedBaselineProcesses();

  const initialList = getProcesses({ limit: 50 });
  assert(initialList.total >= 10, `Baseline processes populated (${initialList.total} total)`);

  const procNames = initialList.processes.map(p => p.process_name.toLowerCase());
  assert(procNames.includes('system'), 'Contains System process');
  assert(procNames.includes('smss.exe'), 'Contains smss.exe');
  assert(procNames.includes('services.exe'), 'Contains services.exe');
  assert(procNames.includes('svchost.exe'), 'Contains svchost.exe');
  assert(procNames.includes('explorer.exe'), 'Contains explorer.exe');
  assert(procNames.includes('notepad.exe'), 'Contains notepad.exe');
  assert(procNames.includes('cmd.exe'), 'Contains cmd.exe');
  assert(procNames.includes('powershell.exe'), 'Contains powershell.exe');

  // 3. Process Event Model Fields Verification
  console.log('\n\x1b[36m[Stage 3: Process Event Model Fields]\x1b[0m');
  const explorerProc = initialList.processes.find(p => p.process_name.toLowerCase() === 'explorer.exe');
  assert(explorerProc !== undefined, 'explorer.exe record found');
  if (explorerProc) {
    assert(explorerProc.pid === 1120, 'PID captured correctly (1120)');
    assert(explorerProc.parent_pid === 740, 'Parent PID captured correctly (740)');
    assert(explorerProc.executable_path.includes('explorer.exe'), 'Executable path is correct');
    assert(explorerProc.username.includes('User'), 'Username is correct');
    assert(explorerProc.integrity_level === 'Medium', 'Integrity level is Medium');
    assert(explorerProc.signature_status === 'Valid', 'Signature status is Valid');
    assert(explorerProc.publisher.includes('Microsoft'), 'Publisher is Microsoft Windows Publisher');
    assert(explorerProc.sha256.length === 64, 'SHA-256 hash length is 64 characters');
    assert(typeof explorerProc.risk_score === 'number', 'Risk score is a number');
    assert(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(explorerProc.risk_level), 'Risk level is valid enum');
  }

  // 4. Querying and Filtering
  console.log('\n\x1b[36m[Stage 4: Querying & Filtering]\x1b[0m');
  const systemProcs = getProcesses({ integrity_level: 'System' });
  assert(systemProcs.processes.length > 0, `Filtered System integrity processes (${systemProcs.processes.length})`);
  assert(systemProcs.processes.every(p => p.integrity_level === 'System'), 'All filtered processes have System integrity');

  const searchResults = getProcesses({ search: 'notepad' });
  assert(searchResults.processes.length >= 1, 'Search by name "notepad" returns matching process');

  // 5. Real Process-Tree Reconstruction Engine
  console.log('\n\x1b[36m[Stage 5: Real Process-Tree Reconstruction Engine]\x1b[0m');
  const tree = getProcessTree();
  assert(tree.length > 0, `Process execution tree constructed with ${tree.length} root branches`);

  // Verify explorer.exe tree reconstruction:
  // explorer.exe
  // └── chrome.exe
  // └── powershell.exe
  // └── cmd.exe
  const explorerNode = tree.find(t => t.pid === 1120);
  assert(explorerNode !== undefined, 'explorer.exe (PID 1120) found in tree');
  if (explorerNode) {
    const childNames = explorerNode.children.map(c => c.process_name.toLowerCase());
    assert(childNames.includes('chrome.exe'), 'explorer.exe has direct child chrome.exe');
    assert(childNames.includes('powershell.exe'), 'explorer.exe has direct child powershell.exe');
    assert(childNames.includes('cmd.exe'), 'explorer.exe has direct child cmd.exe');

    // Verify powershell.exe has child conhost.exe
    const psNode = explorerNode.children.find(c => c.process_name.toLowerCase() === 'powershell.exe');
    assert(psNode !== undefined, 'powershell.exe found under explorer.exe');
    if (psNode) {
      const psChildren = psNode.children.map(c => c.process_name.toLowerCase());
      assert(psChildren.includes('conhost.exe'), 'powershell.exe has child conhost.exe');
    }
  }

  // 6. Handling Processes Whose Parent Process Has Already Terminated
  console.log('\n\x1b[36m[Stage 6: Terminated Parent Handling]\x1b[0m');
  // Scenario A: Historical parent in DB terminated (updater_setup.exe PID 5520 -> bg_sync_service.exe PID 5530)
  const allTreeNodes = getProcessTree({ rootPid: 1120 });
  const findNode = (nodes: any[], pid: number): any => {
    for (const n of nodes) {
      if (n.pid === pid) return n;
      const found = findNode(n.children || [], pid);
      if (found) return found;
    }
    return null;
  };

  const terminatedParent = findNode(allTreeNodes, 5520);
  assert(terminatedParent !== null, 'Terminated parent updater_setup.exe (5520) retained in tree');
  if (terminatedParent) {
    assert(terminatedParent.is_terminated === true, 'Parent marked as terminated (is_terminated: true)');
    assert(terminatedParent.status === 'terminated', 'Parent status is "terminated"');
    const childWorker = terminatedParent.children.find((c: any) => c.pid === 5530);
    assert(childWorker !== undefined, 'Child bg_sync_service.exe (5530) remains attached to terminated parent');
    assert(childWorker?.is_terminated === false, 'Child process is still running');
  }

  // Scenario B: Live termination event
  const termRes = recordProcessTermination(3420); // terminate notepad.exe
  assert(termRes !== null, 'Recorded process termination for notepad.exe (3420)');
  assert(termRes?.is_terminated === true, 'notepad.exe marked terminated');
  const reloadedTree = getProcessTree();
  const reloadedExplorer = reloadedTree.find(t => t.pid === 1120);
  const reloadedNotepad = reloadedExplorer?.children.find(c => c.pid === 3420);
  assert(reloadedNotepad?.is_terminated === true, 'notepad.exe is marked terminated in tree while maintaining parent relationship');

  // 7. Process-Tree APIs
  console.log('\n\x1b[36m[Stage 7: Process-Tree APIs]\x1b[0m');
  // Subtree API
  const chromeSubtree = getProcessTree({ rootPid: 2840 });
  assert(chromeSubtree.length === 1 && chromeSubtree[0].pid === 2840, 'getProcessTree({ rootPid }) returns isolated subtree');

  // Lineage API
  const lineageCmd = getProcessLineage(4912); // conhost.exe
  assert(lineageCmd.target !== null, 'Found target node for lineage PID 4912');
  assert(lineageCmd.ancestors.length >= 2, 'Lineage includes ancestors (explorer.exe -> powershell.exe)');
  assert(lineageCmd.ancestors.some(a => a.pid === 1120), 'Ancestor path includes explorer.exe');
  assert(lineageCmd.ancestors.some(a => a.pid === 4820), 'Ancestor path includes powershell.exe');

  // Stats API
  const stats = getProcessTreeStats();
  assert(stats.totalProcesses >= 10, `Total processes in stats (${stats.totalProcesses})`);
  assert(stats.terminatedProcesses >= 1, `Terminated processes counted (${stats.terminatedProcesses})`);
  assert(stats.rootTreesCount >= 2, `Root trees counted (${stats.rootTreesCount})`);
  assert(stats.maxTreeDepth >= 3, `Tree depth measured (${stats.maxTreeDepth})`);

  // 8. Process Risk Assessment Heuristics
  console.log('\n\x1b[36m[Stage 8: Risk Assessment Engine]\x1b[0m');
  const lowRisk = calculateProcessRisk({
    process_name: 'notepad.exe',
    executable_path: 'C:\\Windows\\System32\\notepad.exe',
    command_line: 'notepad.exe',
    signature_status: 'Valid'
  });
  assert(lowRisk.risk_score <= 15, `Benign signed notepad has low risk score (${lowRisk.risk_score})`);
  assert(lowRisk.risk_level === 'LOW', 'Benign notepad risk level is LOW');

  const highRisk = calculateProcessRisk({
    process_name: 'powershell.exe',
    executable_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    command_line: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SQBFAFgA',
    signature_status: 'Valid'
  });
  assert(highRisk.risk_score >= 60, `PowerShell with bypass and encoded command has high risk score (${highRisk.risk_score})`);
  assert(highRisk.risk_factors.some(f => f.includes('ExecutionPolicy') || f.includes('Obfuscated')), 'Risk factors include execution policy or obfuscation flags');

  const unsignedRisk = calculateProcessRisk({
    process_name: 'unknown_tool.exe',
    executable_path: 'C:\\Windows\\Temp\\unknown_tool.exe',
    command_line: 'unknown_tool.exe',
    signature_status: 'Unsigned'
  });
  assert(unsignedRisk.risk_score >= 25, `Unsigned binary in Temp has elevated risk score (${unsignedRisk.risk_score})`);

  // 9. Node Visual Requirements Verification
  console.log('\n\x1b[36m[Stage 9: Node Required Fields Verification]\x1b[0m');
  const sampleNode = tree[0];
  assert(typeof sampleNode.process_name === 'string' && sampleNode.process_name.length > 0, 'Node has process_name');
  assert(typeof sampleNode.pid === 'number', 'Node has PID');
  assert(typeof sampleNode.parent_pid === 'number', 'Node has parent_pid');
  assert(typeof sampleNode.username === 'string', 'Node has user');
  assert(typeof sampleNode.command_line === 'string', 'Node has command line');
  assert(typeof sampleNode.sha256 === 'string', 'Node has SHA-256');
  assert(typeof sampleNode.signature_status === 'string', 'Node has signature status');
  assert(typeof sampleNode.risk_score === 'number', 'Node has risk score');

  // 10. Hash Caching Verification
  console.log('\n\x1b[36m[Stage 10: In-Memory Caching Verification]\x1b[0m');
  const testExePath = 'C:\\Windows\\System32\\testapp.exe';
  hashSignatureCache.set(testExePath, {
    sha256: 'deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678',
    signature_status: 'Valid',
    publisher: 'Contoso Software Ltd'
  });

  const cacheHit = getOrComputeExecutableHash(testExePath);
  assert(cacheHit.sha256 === 'deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678', 'Cache hit returns cached SHA-256 without disk access');
  assert(cacheHit.publisher === 'Contoso Software Ltd', 'Cache hit returns cached publisher');

  // 11. Live Endpoint Event Ingestion, Deduplication & Provenance Verification
  console.log('\n\x1b[36m[Stage 11: Live Endpoint Event Ingestion & Provenance]\x1b[0m');
  const liveGuid = '{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}';
  const liveTimestamp = new Date().toISOString();
  
  // Test live event recording
  const liveEvent = recordProcessEvent({
    guid: liveGuid,
    pid: 9912,
    parent_pid: 1120,
    process_name: 'test_live_tool.exe',
    executable_path: 'C:\\Tools\\test_live_tool.exe',
    command_line: 'test_live_tool.exe --verbose',
    username: 'CORP\\JohnDoe',
    creation_timestamp: liveTimestamp,
    source: 'sysmon_live'
  });

  assert(liveEvent.source === 'sysmon_live', 'Recorded event carries sysmon_live source');
  assert(liveEvent.pid === 9912, 'Recorded event has correct PID');

  // Test deduplication by GUID
  const duplicateGuidEvent = recordProcessEvent({
    guid: liveGuid,
    pid: 9912,
    parent_pid: 1120,
    process_name: 'test_live_tool.exe',
    source: 'sysmon_live'
  });
  assert(duplicateGuidEvent.id === liveEvent.id, 'Duplicate GUID event is cleanly deduplicated without re-insertion');

  // Test deduplication by PID + creation_timestamp
  const duplicateTimestampEvent = recordProcessEvent({
    pid: 9912,
    creation_timestamp: liveTimestamp,
    process_name: 'test_live_tool.exe',
    source: 'sysmon_live'
  });
  assert(duplicateTimestampEvent.id === liveEvent.id, 'Duplicate PID + timestamp event is cleanly deduplicated');

  // Test input validation
  let caughtInvalidPid = false;
  try {
    recordProcessEvent({ pid: -5, process_name: 'bad.exe' });
  } catch {
    caughtInvalidPid = true;
  }
  assert(caughtInvalidPid, 'Rejects invalid PID <= 0 with validation error');

  let caughtEmptyName = false;
  try {
    recordProcessEvent({ pid: 1234, process_name: '' });
  } catch {
    caughtEmptyName = true;
  }
  assert(caughtEmptyName, 'Rejects empty process_name with validation error');

  // Test source filtering in getProcesses
  const liveFiltered = getProcesses({ source: 'live' });
  assert(liveFiltered.processes.some(p => p.pid === 9912 && p.source === 'sysmon_live'), 'getProcesses with source="live" returns genuine live events');

  const baselineFiltered = getProcesses({ source: 'baseline' });
  assert(baselineFiltered.processes.every(p => p.source === 'baseline_seed'), 'getProcesses with source="baseline" returns only baseline events');

  console.log(`\n\x1b[1m=== Process Tree & Monitoring Tests Complete: ${passed} passed, ${failed} failed ===\x1b[0m\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runProcessMonitoringTests().catch(err => {
  console.error('Fatal error in process monitoring test runner:', err);
  process.exit(1);
});
