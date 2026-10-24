import { 
  lolbinDetector, 
  lolbinManager,
  MONITORED_BINARIES,
  CONTEXTUAL_BEHAVIORS,
  DEFAULT_LOLBIN_CONFIG,
  SAFE_SIMULATIONS,
  type MonitoredBinaryName
} from '../backend/detection/lolbins/index.js';
import { ingestAndDetect, syncDefaultRules } from '../backend/detection/engine.js';
import { initDatabase } from '../backend/db/index.js';
import { mitreService } from '../backend/mitre/index.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string) {
  if (condition) {
    console.log(`  \x1b[32m✔\x1b[0m ${testName}`);
    passed++;
  } else {
    console.error(`  \x1b[31m✖\x1b[0m ${testName}`);
    failed++;
  }
}

export async function runLolbinTests(): Promise<{ passed: number; failed: number }> {
  console.log('\n\x1b[1m=== Running Specialized PowerShell & LOLBin Detection Tests ===\x1b[0m\n');

  await initDatabase();
  syncDefaultRules();
  lolbinManager.initDatabase();

  // Test Suite 1: Verification of Monitored Binaries (All 13 Required)
  console.log('\x1b[36m[Test Suite 1: Monitored Binaries Catalog (13 Windows Binaries)]\x1b[0m');
  const requiredBinaries: MonitoredBinaryName[] = [
    'powershell.exe',
    'cmd.exe',
    'rundll32.exe',
    'regsvr32.exe',
    'mshta.exe',
    'certutil.exe',
    'bitsadmin.exe',
    'wmic.exe',
    'cscript.exe',
    'wscript.exe',
    'msiexec.exe',
    'schtasks.exe',
    'reg.exe'
  ];

  const monitored = lolbinManager.getMonitoredBinaries();
  assert(monitored.length === 13, `All 13 specified LOLBins are registered (found ${monitored.length})`);

  for (const binName of requiredBinaries) {
    const item = monitored.find(m => m.name === binName);
    assert(item !== undefined, `Binary '${binName}' is monitored`);
    assert(item?.enabled === true, `Binary '${binName}' is enabled by default`);
    assert(Array.isArray(item?.mitreTechniques) && item.mitreTechniques.length > 0, `Binary '${binName}' mapped to MITRE ATT&CK techniques`);
    assert(typeof item?.legitimateUse === 'string' && item.legitimateUse.length > 0, `Binary '${binName}' documents legitimate use`);
    assert(typeof item?.commonAbuse === 'string' && item.commonAbuse.length > 0, `Binary '${binName}' documents attack abuse`);
  }

  // Test Suite 2: Contextual Behaviors Catalog (All 9 Required Behaviors)
  console.log('\n\x1b[36m[Test Suite 2: Contextual Detection Behaviors (All 9 Specific Behaviors)]\x1b[0m');
  const behaviors = lolbinManager.getBehaviors();
  assert(behaviors.length === 9, `All 9 contextual behaviors defined (found ${behaviors.length})`);

  const behaviorKeys = [
    'encoded_powershell',
    'suspicious_download',
    'hidden_execution',
    'unusual_parent',
    'office_to_powershell',
    'browser_to_powershell',
    'powershell_to_lolbin',
    'lolbin_to_executable',
    'temp_location_execution'
  ];

  for (const bKey of behaviorKeys) {
    const b = behaviors.find(item => item.id === bKey);
    assert(b !== undefined, `Behavior '${bKey}' is configured`);
    assert(b?.primaryMitre?.technique_id !== undefined, `Behavior '${bKey}' has MITRE technique ${b?.primaryMitre?.technique_id}`);
  }

  // Test Suite 3: Negative Testing - Contextual False Positive Suppression (Do NOT flag benign commands)
  console.log('\n\x1b[36m[Test Suite 3: Low False Positive Guarantee - Benign Commands Must NOT Trigger Alerts]\x1b[0m');

  // Benign 1: cmd.exe /c echo
  const benignCmd = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'cmd.exe',
    command_line: 'cmd.exe /c echo LocalEDR Benign Test',
    parent_process_name: 'explorer.exe'
  });
  assert(benignCmd.alertsGenerated.length === 0, 'Benign: cmd.exe /c echo does NOT trigger alert');

  // Benign 2: powershell.exe -Command "Get-Date"
  const benignPs = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -NoProfile -Command "Get-Date"',
    parent_process_name: 'explorer.exe'
  });
  assert(benignPs.alertsGenerated.length === 0, 'Benign: powershell.exe Get-Date does NOT trigger alert');

  // Benign 3: certutil.exe -hashfile
  const benignCertutil = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'certutil.exe',
    command_line: 'certutil.exe -hashfile C:\\Windows\\System32\\notepad.exe SHA256',
    parent_process_name: 'cmd.exe'
  });
  assert(benignCertutil.alertsGenerated.length === 0, 'Benign: certutil.exe -hashfile does NOT trigger alert');

  // Benign 4: bitsadmin.exe /list
  const benignBits = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'bitsadmin.exe',
    command_line: 'bitsadmin.exe /list /allusers',
    parent_process_name: 'cmd.exe'
  });
  assert(benignBits.alertsGenerated.length === 0, 'Benign: bitsadmin.exe /list does NOT trigger alert');

  // Benign 5: schtasks.exe /query
  const benignSchtasks = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'schtasks.exe',
    command_line: 'schtasks.exe /query /fo TABLE',
    parent_process_name: 'cmd.exe'
  });
  assert(benignSchtasks.alertsGenerated.length === 0, 'Benign: schtasks.exe /query does NOT trigger alert');

  // Benign 6: reg.exe query
  const benignReg = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'reg.exe',
    command_line: 'reg.exe query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion"',
    parent_process_name: 'cmd.exe'
  });
  assert(benignReg.alertsGenerated.length === 0, 'Benign: reg.exe query does NOT trigger alert');

  // Benign 7: wmic.exe os get caption
  const benignWmic = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'wmic.exe',
    command_line: 'wmic.exe os get caption,version',
    parent_process_name: 'cmd.exe'
  });
  assert(benignWmic.alertsGenerated.length === 0, 'Benign: wmic.exe os get caption does NOT trigger alert');

  // Test Suite 4: Contextual Suspicious Detections & MITRE ATT&CK Mapping
  console.log('\n\x1b[36m[Test Suite 4: Contextual Detections & MITRE ATT&CK Verification]\x1b[0m');

  // 1. Encoded PowerShell (T1059.001)
  const encPsDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=',
    parent_process_name: 'cmd.exe'
  });
  assert(encPsDetection.alertsGenerated.length > 0, 'Contextual Detection: Encoded PowerShell detected');
  const encAlert = encPsDetection.alertsGenerated.find(a => a.rule_id.includes('POWERSHELL-ENCODED'));
  assert(encAlert !== undefined, 'Encoded PowerShell triggered EDR rule EDR-007');
  assert(encAlert?.mitre_technique_id === 'T1059.001', 'Encoded PowerShell mapped to MITRE T1059.001');

  // 2. Suspicious Download Cradle (T1105 / T1059.001)
  const dlDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -Command "(New-Object Net.WebClient).DownloadString(\'http://127.0.0.1/safe.ps1\')"',
    parent_process_name: 'cmd.exe'
  });
  assert(dlDetection.alertsGenerated.length > 0, 'Contextual Detection: PowerShell Download Cradle detected');
  const dlAlert = dlDetection.alertsGenerated.find(a => a.rule_id.includes('DOWNLOAD-CRADLE') || a.rule_id.includes('INGRESS'));
  assert(dlAlert !== undefined, 'Download Cradle matched dedicated download rule');
  assert(dlAlert?.mitre_technique_id === 'T1105', 'Download Cradle mapped to MITRE T1105');

  // 3. Hidden Execution (T1564.003)
  const hiddenDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -WindowStyle Hidden -Command "Write-Host Safe"',
    parent_process_name: 'explorer.exe'
  });
  assert(hiddenDetection.alertsGenerated.length > 0, 'Contextual Detection: Hidden Window execution detected');
  const hiddenAlert = hiddenDetection.alertsGenerated.find(a => a.rule_id.includes('HIDDEN-EXEC'));
  assert(hiddenAlert !== undefined, 'Hidden window triggered EDR-026');
  assert(hiddenAlert?.mitre_technique_id === 'T1564.003', 'Hidden execution mapped to MITRE T1564.003');

  // 4. Unusual Parent Process (svchost -> cmd.exe) (T1059.003)
  const unusualParentDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'cmd.exe',
    command_line: 'cmd.exe /c whoami',
    parent_process_name: 'svchost.exe'
  });
  assert(unusualParentDetection.alertsGenerated.length > 0, 'Contextual Detection: Unusual Parent (svchost -> cmd) detected');
  const parentAlert = unusualParentDetection.alertsGenerated.find(a => a.rule_id.includes('CMD-UNUSUAL-PARENT'));
  assert(parentAlert !== undefined, 'Unusual parent triggered EDR-002');
  assert(parentAlert?.mitre_technique_id === 'T1059.003', 'Unusual parent mapped to MITRE T1059.003');

  // 5. Office → PowerShell (T1059.001)
  const officeDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -ExecutionPolicy Bypass -Command "Write-Host macro"',
    parent_process_name: 'winword.exe'
  });
  assert(officeDetection.alertsGenerated.length > 0, 'Contextual Detection: Office (Word) -> PowerShell detected');
  const officeAlert = officeDetection.alertsGenerated.find(a => a.rule_id.includes('OFFICE-POWERSHELL'));
  assert(officeAlert !== undefined, 'Office -> PowerShell triggered EDR-001');
  assert(officeAlert?.severity === 'CRITICAL', 'Office -> PowerShell classified as CRITICAL severity');

  // 6. Browser → PowerShell (T1189)
  const browserDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'powershell.exe',
    command_line: 'powershell.exe -Command "Write-Host browser_compromise"',
    parent_process_name: 'chrome.exe'
  });
  assert(browserDetection.alertsGenerated.length > 0, 'Contextual Detection: Browser (Chrome) -> PowerShell detected');
  const browserAlert = browserDetection.alertsGenerated.find(a => a.rule_id.includes('BROWSER-POWERSHELL'));
  assert(browserAlert !== undefined, 'Browser -> PowerShell triggered EDR-027');
  assert(browserAlert?.mitre_technique_id === 'T1189', 'Browser -> PowerShell mapped to MITRE T1189');

  // 7. PowerShell → LOLBin (certutil) (T1218 / T1059.001)
  const psLolbinDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'certutil.exe',
    command_line: 'certutil.exe -urlcache -split -f http://127.0.0.1/tool.bin tool.exe',
    parent_process_name: 'powershell.exe'
  });
  assert(psLolbinDetection.alertsGenerated.length > 0, 'Contextual Detection: PowerShell -> LOLBin (certutil) detected');
  const psLolbinAlert = psLolbinDetection.alertsGenerated.find(a => a.rule_id.includes('POWERSHELL-TO-LOLBIN') || a.rule_id.includes('SUSPICIOUS-LOLBIN-EXEC'));
  assert(psLolbinAlert !== undefined, 'PowerShell -> LOLBin triggered detection');
  assert(psLolbinAlert?.mitre_technique_id === 'T1218' || psLolbinAlert?.mitre_technique_id === 'T1105', 'PowerShell -> LOLBin mapped to MITRE T1218 / T1105');

  // 8. LOLBin → Executable (rundll32 -> payload.exe) (T1218)
  const lolbinExeDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'agent_runner.exe',
    command_line: 'C:\\Users\\Public\\agent_runner.exe --start',
    parent_process_name: 'rundll32.exe'
  });
  assert(lolbinExeDetection.alertsGenerated.length > 0, 'Contextual Detection: LOLBin -> Executable detected');
  const lolbinExeAlert = lolbinExeDetection.alertsGenerated.find(a => a.rule_id.includes('LOLBIN-TO-EXECUTABLE'));
  assert(lolbinExeAlert !== undefined, 'LOLBin -> Executable triggered EDR-029');
  assert(lolbinExeAlert?.mitre_technique_id === 'T1218', 'LOLBin -> Executable mapped to MITRE T1218');

  // 9. Temporary Location Execution (T1027)
  const tempDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'powershell.exe',
    image_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\staged_dropper.exe',
    command_line: 'C:\\Users\\User\\AppData\\Local\\Temp\\staged_dropper.exe -run',
    parent_process_name: 'explorer.exe'
  });
  assert(tempDetection.alertsGenerated.length > 0, 'Contextual Detection: Execution from Temporary Location detected');
  const tempAlert = tempDetection.alertsGenerated.find(a => a.rule_id.includes('TEMP-DIR') || a.rule_id.includes('TEMP-LOCATION'));
  assert(tempAlert !== undefined, 'Temp execution matched temp directory rule');
  assert(tempAlert?.mitre_technique_id === 'T1027', 'Temp location execution mapped to MITRE T1027');

  // Test Suite 5: Additional Monitored LOLBins (WMIC, Regsvr32, Msiexec)
  console.log('\n\x1b[36m[Test Suite 5: Additional Monitored LOLBins Verification]\x1b[0m');

  // WMIC Process Call Create (T1047)
  const wmicDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'wmic.exe',
    command_line: 'wmic.exe process call create "calc.exe"',
    parent_process_name: 'cmd.exe'
  });
  assert(wmicDetection.alertsGenerated.length > 0, 'WMIC Process Call Create detected');
  const wmicAlert = wmicDetection.alertsGenerated.find(a => a.rule_id.includes('WMIC-PROCESS-CREATION'));
  assert(wmicAlert !== undefined, 'WMIC triggered EDR-032');
  assert(wmicAlert?.mitre_technique_id === 'T1047', 'WMIC mapped to MITRE T1047');

  // Regsvr32 Squiblydoo (T1218.010)
  const regsvrDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'regsvr32.exe',
    command_line: 'regsvr32.exe /s /u /i:http://127.0.0.1/payload.sct scrobj.dll',
    parent_process_name: 'cmd.exe'
  });
  assert(regsvrDetection.alertsGenerated.length > 0, 'Regsvr32 Squiblydoo detected');
  const regsvrAlert = regsvrDetection.alertsGenerated.find(a => a.rule_id.includes('REGSVR32-SQUIBLYDOO') || a.rule_id.includes('SUSPICIOUS-LOLBIN-EXEC'));
  assert(regsvrAlert !== undefined, 'Regsvr32 triggered Squiblydoo rule');

  // Msiexec Remote Install (T1218.007)
  const msiDetection = ingestAndDetect({
    event_type: 'process_creation',
    event_category: 'process',
    process_name: 'msiexec.exe',
    command_line: 'msiexec.exe /q /i http://127.0.0.1/package.msi',
    parent_process_name: 'cmd.exe'
  });
  assert(msiDetection.alertsGenerated.length > 0, 'Msiexec Remote Install detected');
  const msiAlert = msiDetection.alertsGenerated.find(a => a.rule_id.includes('MSIEXEC-REMOTE-INSTALL'));
  assert(msiAlert !== undefined, 'Msiexec triggered EDR-033');

  // Test Suite 6: Configurable LOLBin Rules & In-Memory / SQLite Persistence
  console.log('\n\x1b[36m[Test Suite 6: Configurable LOLBin Rules & Manager]\x1b[0m');

  const initialStatus = lolbinDetector.isBinaryEnabled('bitsadmin.exe');
  assert(initialStatus === true, 'bitsadmin.exe is initially enabled in detector');

  // Disable bitsadmin.exe
  const updated = lolbinManager.updateBinaryConfig('bitsadmin.exe', { enabled: false, riskWeight: 40 });
  assert(updated === true, 'LOLBin manager updated bitsadmin.exe config');
  assert(lolbinDetector.isBinaryEnabled('bitsadmin.exe') === false, 'Detector reflects bitsadmin.exe disabled');

  // Restore bitsadmin.exe
  lolbinManager.updateBinaryConfig('bitsadmin.exe', { enabled: true, riskWeight: 75 });
  assert(lolbinDetector.isBinaryEnabled('bitsadmin.exe') === true, 'Detector reflects bitsadmin.exe restored to enabled');

  // Global Config Update
  const globalCfg = lolbinManager.getGlobalConfig();
  assert(Array.isArray(globalCfg.monitoredOfficeParents), 'Global config contains monitored Office parents');
  assert(globalCfg.monitoredOfficeParents.includes('winword.exe'), 'winword.exe is in monitored Office parents');

  // Safe Simulations Test
  console.log('\n\x1b[36m[Test Suite 7: Safe Simulations Runner (Benign & Detection)]\x1b[0m');
  const sims = lolbinManager.getSimulations();
  assert(sims.length >= 10, `At least 10 safe simulation scenarios available (found ${sims.length})`);

  // Run a benign simulation (SIM-BENIGN-CMD-ECHO)
  const benignSimResult = lolbinManager.runSimulation('SIM-BENIGN-CMD-ECHO');
  assert(benignSimResult.isSuccess === true, 'Benign simulation SIM-BENIGN-CMD-ECHO ran successfully without alert');
  assert(benignSimResult.alertsGenerated.length === 0, 'Benign simulation produced 0 alerts');

  // Run a detection simulation (SIM-ALERT-OFFICE-POWERSHELL)
  const detectSimResult = lolbinManager.runSimulation('SIM-ALERT-OFFICE-POWERSHELL');
  assert(detectSimResult.isSuccess === true, 'Detection simulation SIM-ALERT-OFFICE-POWERSHELL flagged alert');
  assert(detectSimResult.detectionResult.isSuspicious === true, 'Detector marked simulation as suspicious');

  console.log(`\n\x1b[1m=== LOLBin Test Results: ${passed} passed, ${failed} failed ===\x1b[0m\n`);
  return { passed, failed };
}

if (process.argv[1]?.endsWith('lolbin-detection.test.ts')) {
  runLolbinTests().then(res => {
    if (res.failed > 0) process.exit(1);
  });
}
