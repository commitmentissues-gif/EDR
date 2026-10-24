import { 
  MonitoredLolbinName, 
  LolbinEvaluationResult, 
  LolbinBehaviorCategory 
} from './types.js';
import { MONITORED_LOLBINS_LIST, LOLBIN_PROFILES } from './profiles.js';
import { getLolbinRules } from './config.js';
import { TelemetryEvent } from '../detection/types.js';
import { NormalizedEvent } from '../events/types.js';

function normalize(s?: string | null): string {
  return (s || '').trim().toLowerCase();
}

/**
 * Checks whether an event matches a known benign, non-malicious command pattern.
 * Crucial requirement: Do not flag every use of these tools. Use contextual detection.
 */
export function isBenignLolbinUsage(
  processName: string,
  commandLine: string,
  parentName: string
): { isBenign: boolean; reason?: string } {
  const normProc = normalize(processName);
  const normCmd = normalize(commandLine);
  const normParent = normalize(parentName);

  // If parent is Office or Web Browser, it is NEVER considered benign!
  const highRiskParents = [
    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe'
  ];
  if (highRiskParents.includes(normParent)) {
    return { isBenign: false };
  }

  // 1. certutil.exe - Benign cryptographic hashing and certificate viewing
  if (normProc === 'certutil.exe') {
    if (normCmd.includes('-hashfile') && !normCmd.includes('http') && !normCmd.includes('-urlcache')) {
      return { isBenign: true, reason: 'Certutil standard cryptographic hash calculation (-hashfile)' };
    }
    if (normCmd.includes('-dump') || normCmd.includes('-v -store')) {
      return { isBenign: true, reason: 'Certutil certificate inspection or store query' };
    }
  }

  // 2. schtasks.exe - Benign query operations
  if (normProc === 'schtasks.exe') {
    if (normCmd.includes('/query') && !normCmd.includes('/create') && !normCmd.includes('/change')) {
      return { isBenign: true, reason: 'Schtasks read-only task query (/query)' };
    }
    if (normCmd.includes('/?') || normCmd.endsWith('schtasks.exe')) {
      return { isBenign: true, reason: 'Schtasks help syntax invocation' };
    }
  }

  // 3. reg.exe - Benign query operations
  if (normProc === 'reg.exe') {
    if (normCmd.includes('query') && !normCmd.includes('add') && !normCmd.includes('delete')) {
      return { isBenign: true, reason: 'Reg read-only key query (reg query)' };
    }
    if (normCmd.includes('/?') || normCmd.endsWith('reg.exe')) {
      return { isBenign: true, reason: 'Reg help syntax invocation' };
    }
  }

  // 4. wmic.exe - Benign system information gathering
  if (normProc === 'wmic.exe') {
    const isBenignQuery = normCmd.includes('os get') || 
                          normCmd.includes('cpu get') || 
                          normCmd.includes('logicaldisk get') || 
                          normCmd.includes('bios get') ||
                          normCmd.includes('computersystem get');
    if (isBenignQuery && !normCmd.includes('call create') && !normCmd.includes('delete') && !normCmd.includes('shadowcopy')) {
      return { isBenign: true, reason: 'WMIC read-only system hardware or OS property query' };
    }
  }

  // 5. bitsadmin.exe - Benign list / reset
  if (normProc === 'bitsadmin.exe') {
    if ((normCmd.includes('/list') || normCmd.includes('/reset')) && !normCmd.includes('/transfer') && !normCmd.includes('/addfile')) {
      return { isBenign: true, reason: 'Bitsadmin read-only queue query or reset' };
    }
  }

  // 6. msiexec.exe - Standard help flag
  if (normProc === 'msiexec.exe') {
    if (normCmd.includes('/?') || normCmd.endsWith('msiexec.exe') || normCmd.endsWith('msiexec')) {
      return { isBenign: true, reason: 'Msiexec help flag' };
    }
  }

  // 7. powershell.exe - Benign simple non-encoded non-download commands from standard shells
  if (normProc === 'powershell.exe') {
    const hasSuspiciousFlag = normCmd.includes('-enc') || 
                              normCmd.includes('download') || 
                              normCmd.includes('bypass') || 
                              normCmd.includes('-w hidden') || 
                              normCmd.includes('iex') ||
                              normCmd.includes('invoke-expression') ||
                              normCmd.includes('webclient');
    const isStandardParent = normParent === 'explorer.exe' || normParent === 'cmd.exe' || normParent === 'devenv.exe';
    if (!hasSuspiciousFlag && isStandardParent && (normCmd.includes('get-process') || normCmd.includes('get-date') || normCmd.includes('$psversiontable') || normCmd.includes('get-service'))) {
      return { isBenign: true, reason: 'PowerShell benign standard diagnostic cmdlet invocation' };
    }
  }

  // 8. cmd.exe - Standard echo, dir, ver from explorer
  if (normProc === 'cmd.exe') {
    const hasSuspiciousArg = normCmd.includes('powershell') || 
                             normCmd.includes('certutil') || 
                             normCmd.includes('mshta') || 
                             normCmd.includes('bitsadmin') || 
                             normCmd.includes('delete shadows') ||
                             normCmd.includes('vssadmin') ||
                             normCmd.includes('regsvr32') ||
                             normCmd.includes('rundll32');
    if (!hasSuspiciousArg && (normCmd.includes('/c echo') || normCmd.includes('/c dir') || normCmd.includes('/c ver') || normCmd.includes('/c date'))) {
      return { isBenign: true, reason: 'Cmd.exe standard non-threatening command' };
    }
  }

  return { isBenign: false };
}

/**
 * Evaluates an incoming process execution event specifically against LOLBin contextual detection rules.
 */
export function evaluateLolbinContext(
  event: TelemetryEvent | NormalizedEvent
): LolbinEvaluationResult | null {
  const procName = normalize(event.process_name || (event.image_path ? event.image_path.split('\\').pop() : ''));
  const parentName = normalize(event.parent_process_name || '');
  const cmdLine = normalize(event.command_line || '');
  const imagePath = normalize(event.image_path || event.process_path || '');

  // 1. Check if the process or parent is in the monitored LOLBins list
  const isTargetLolbin = MONITORED_LOLBINS_LIST.includes(procName as MonitoredLolbinName);
  const isParentLolbin = MONITORED_LOLBINS_LIST.includes(parentName as MonitoredLolbinName);

  if (!isTargetLolbin && !isParentLolbin) {
    return null;
  }

  // 2. Benign filter check: Avoid false positives on standard administrative usage
  const benignCheck = isBenignLolbinUsage(procName, cmdLine, parentName);
  if (benignCheck.isBenign) {
    return {
      matched: false,
      isBenign: true,
      benignReason: benignCheck.reason,
      matchedCriteria: [],
      evidence: {}
    };
  }

  const activeRules = getLolbinRules().filter(r => r.enabled);
  const matchedRules: { rule: typeof activeRules[0]; criteria: string[] }[] = [];

  const tempDirs = ['\\appdata\\local\\temp', '\\users\\public', '\\windows\\temp', '\\temp\\'];
  const officeApps = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'];
  const webBrowsers = ['chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe'];
  const executionProxies = ['mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'wscript.exe', 'cscript.exe'];

  // Behavior 1: Office -> PowerShell / cmd
  if (officeApps.includes(parentName) && (procName === 'powershell.exe' || procName === 'cmd.exe')) {
    const r = activeRules.find(r => r.behavior === 'office_to_powershell');
    if (r) {
      matchedRules.push({
        rule: r,
        criteria: [`Office application '${parentName}' directly spawned scripting shell '${procName}'`]
      });
    }
  }

  // Behavior 2: Web Browser -> PowerShell / cmd
  if (webBrowsers.includes(parentName) && (procName === 'powershell.exe' || procName === 'cmd.exe')) {
    const r = activeRules.find(r => r.behavior === 'browser_to_powershell');
    if (r) {
      matchedRules.push({
        rule: r,
        criteria: [`Web browser '${parentName}' spawned interactive shell '${procName}'`]
      });
    }
  }

  // Behavior 3: PowerShell -> Secondary LOLBin
  if (parentName === 'powershell.exe' && ['certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'bitsadmin.exe', 'wmic.exe'].includes(procName)) {
    const r = activeRules.find(r => r.behavior === 'powershell_to_lolbin');
    if (r) {
      matchedRules.push({
        rule: r,
        criteria: [`PowerShell process spawned secondary Living-off-the-Land binary '${procName}'`]
      });
    }
  }

  // Behavior 4: LOLBin -> Executable (Proxy detonation)
  if (executionProxies.includes(parentName) && (procName === 'cmd.exe' || procName === 'powershell.exe' || !MONITORED_LOLBINS_LIST.includes(procName as any))) {
    const r = activeRules.find(r => r.behavior === 'lolbin_to_executable');
    if (r) {
      matchedRules.push({
        rule: r,
        criteria: [`Execution proxy LOLBin '${parentName}' spawned child executable '${procName}'`]
      });
    }
  }

  // Behavior 5: Encoded PowerShell
  if (procName === 'powershell.exe') {
    const encodedFlags = ['-enc ', '-encodedcommand ', '-e ', '-enc\t', '-encodedcommand\t'];
    const hasEncodedFlag = encodedFlags.some(f => cmdLine.includes(f));
    const hasBase64Method = cmdLine.includes('frombase64string') || cmdLine.includes('::frombase64');
    if (hasEncodedFlag || hasBase64Method) {
      const r = activeRules.find(r => r.behavior === 'encoded_powershell');
      if (r) {
        matchedRules.push({
          rule: r,
          criteria: [`PowerShell executed with obfuscated base64 payload parameter`]
        });
      }
    }
  }

  // Behavior 6: Suspicious Download Commands
  if (isTargetLolbin) {
    const isDownload = 
      (procName === 'certutil.exe' && (cmdLine.includes('-urlcache') || (cmdLine.includes('-split') && cmdLine.includes('-f')) || cmdLine.includes('http://') || cmdLine.includes('https://'))) ||
      (procName === 'bitsadmin.exe' && (cmdLine.includes('/transfer') || cmdLine.includes('/addfile') || cmdLine.includes('/download'))) ||
      (procName === 'powershell.exe' && (cmdLine.includes('downloadstring') || cmdLine.includes('downloadfile') || cmdLine.includes('invoke-webrequest') || cmdLine.includes('iwr ') || cmdLine.includes('system.net.webclient'))) ||
      (procName === 'msiexec.exe' && (cmdLine.includes('/q') || cmdLine.includes('/qn')) && (cmdLine.includes('http://') || cmdLine.includes('https://')));

    if (isDownload) {
      const r = activeRules.find(r => r.behavior === 'suspicious_download');
      if (r) {
        matchedRules.push({
          rule: r,
          criteria: [`LOLBin '${procName}' invoked with remote download parameters in command line`]
        });
      }
    }
  }

  // Behavior 7: Hidden Execution
  if (isTargetLolbin) {
    const isHidden = 
      (procName === 'powershell.exe' && (cmdLine.includes('-w hidden') || cmdLine.includes('-windowstyle hidden') || cmdLine.includes('-w 1'))) ||
      (procName === 'wscript.exe' && cmdLine.includes('//b')) ||
      (procName === 'cscript.exe' && (cmdLine.includes('//b') || cmdLine.includes('//nologo'))) ||
      (procName === 'mshta.exe' && (cmdLine.includes('javascript:') || cmdLine.includes('vbscript:')) && (cmdLine.includes('close()') || cmdLine.includes('wscript.shell')));

    if (isHidden) {
      const r = activeRules.find(r => r.behavior === 'hidden_execution');
      if (r) {
        matchedRules.push({
          rule: r,
          criteria: [`LOLBin '${procName}' executed with window-suppression parameters`]
        });
      }
    }
  }

  // Behavior 8: Execution from Temporary Locations
  if (isTargetLolbin) {
    const isTempPath = tempDirs.some(t => imagePath.includes(t) || cmdLine.includes(t));
    if (isTempPath) {
      const r = activeRules.find(r => r.behavior === 'temp_location_execution');
      if (r) {
        matchedRules.push({
          rule: r,
          criteria: [`LOLBin '${procName}' invoked binary or script from user-writable temporary directory`]
        });
      }
    }
  }

  if (matchedRules.length === 0) {
    return null;
  }

  // Pick highest priority matched rule
  const primaryMatch = matchedRules.sort((a, b) => b.rule.score - a.rule.score)[0];
  const allCriteria = matchedRules.flatMap(m => m.criteria);

  return {
    matched: true,
    ruleId: primaryMatch.rule.id,
    ruleName: primaryMatch.rule.name,
    behavior: primaryMatch.rule.behavior,
    severity: primaryMatch.rule.severity,
    score: primaryMatch.rule.score,
    mitre: primaryMatch.rule.mitre,
    matchedCriteria: allCriteria,
    evidence: {
      process_name: event.process_name,
      parent_process_name: event.parent_process_name,
      command_line: event.command_line,
      image_path: event.image_path || event.process_path,
      user: event.user || (event as any).user_name,
      matched_behavior: primaryMatch.rule.behavior,
      criteria: allCriteria
    },
    isBenign: false,
    whyTriggered: `Contextual LOLBin Detection: ${primaryMatch.rule.name} (${primaryMatch.rule.id}). Indicators: ${allCriteria.join('; ')}. MITRE: [${primaryMatch.rule.mitre.tactic} -> ${primaryMatch.rule.mitre.technique_id} ${primaryMatch.rule.mitre.technique_name}].`,
    recommendedAction: primaryMatch.rule.recommendedAction
  };
}
