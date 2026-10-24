import { query } from '../db/index.js';
import { 
  RuleConditions, 
  TelemetryEvent, 
  ConditionEvaluationResult, 
  EvaluationEvidence 
} from './types.js';

/**
 * Normalizes string for case-insensitive matching
 */
function normalize(val?: string | null): string {
  return (val || '').trim().toLowerCase();
}

/**
 * Checks if target string matches any pattern in expected list
 */
function matchesAny(target: string, expected: string | string[], mode: 'exact' | 'contains' | 'endsWith' = 'exact'): boolean {
  const normTarget = normalize(target);
  if (!normTarget) return false;

  const list = Array.isArray(expected) ? expected : [expected];

  return list.some(item => {
    const normItem = normalize(item);
    if (!normItem) return false;

    if (mode === 'contains') {
      return normTarget.includes(normItem);
    } else if (mode === 'endsWith') {
      return normTarget === normItem || normTarget.endsWith('\\' + normItem) || normTarget.endsWith('/' + normItem) || normTarget.endsWith(normItem);
    } else {
      // exact or ends with file name
      return normTarget === normItem || normTarget.endsWith('\\' + normItem) || normTarget.endsWith('/' + normItem);
    }
  });
}

/**
 * Real EDR Condition Evaluator
 * Evaluates telemetry event against configurable rule conditions:
 * - process name
 * - parent process
 * - command line
 * - executable path
 * - hash
 * - username
 * - process relationships
 * 
 * Accurately extracts evidence used for detection.
 */
export function evaluateRuleConditions(
  event: TelemetryEvent,
  conditions: RuleConditions
): ConditionEvaluationResult {
  const evidence: EvaluationEvidence = {
    matched_criteria: []
  };

  const failureResult: ConditionEvaluationResult = {
    matched: false,
    reason: '',
    evidence
  };

  // 1. Event Type Check (if specified)
  if (conditions.event_type) {
    const allowedTypes = Array.isArray(conditions.event_type) ? conditions.event_type : [conditions.event_type];
    if (!allowedTypes.includes(event.event_type)) {
      return failureResult;
    }
  }

  // 2. Condition: Process Name
  if (conditions.process_name) {
    const procName = event.process_name || (event.image_path ? event.image_path.split('\\').pop() : '');
    if (!matchesAny(procName || '', conditions.process_name, 'endsWith')) {
      return failureResult;
    }
    evidence.process_name = procName;
    evidence.matched_criteria.push(`Process Name matches target '${procName}'`);
  }

  // 3. Condition: Parent Process
  const expectedParent = conditions.parent_process || conditions.parent_process_name;
  if (expectedParent) {
    let parentName = event.parent_process_name || '';

    // If parent_process_name not provided directly on event, resolve from process_events if parent_process_id exists
    if (!parentName && event.parent_process_id && event.parent_process_id > 0) {
      try {
        const parentRecords = query<{ process_name: string }>(
          'SELECT process_name FROM process_events WHERE pid = ? ORDER BY id DESC LIMIT 1',
          [event.parent_process_id]
        );
        if (parentRecords[0]) {
          parentName = parentRecords[0].process_name;
        }
      } catch {
        // DB not available or table empty
      }
    }

    if (!matchesAny(parentName || '', expectedParent, 'endsWith')) {
      return failureResult;
    }
    evidence.parent_process = parentName + (event.parent_process_id ? ` (PID ${event.parent_process_id})` : '');
    evidence.matched_criteria.push(`Parent Process matches '${parentName}'`);
  }

  // 3b. Condition: Allowlist Parent (False Positive Exclusion)
  if (conditions.allowlist_parent) {
    const parentName = event.parent_process_name || '';
    if (parentName && matchesAny(parentName, conditions.allowlist_parent, 'endsWith')) {
      return failureResult;
    }
  }

  // 4. Condition: Command Line
  if (conditions.command_line || conditions.command_line_match) {
    const expectedCmds = conditions.command_line || conditions.command_line_match;
    const cmdLine = event.command_line || '';
    if (!cmdLine || !expectedCmds || !matchesAny(cmdLine, expectedCmds, 'contains')) {
      return failureResult;
    }

    // Check allowlists and exclusions to prevent false positives on benign usage
    if (conditions.command_line_not_match && matchesAny(cmdLine, conditions.command_line_not_match, 'contains')) {
      return failureResult;
    }
    if (conditions.allowlist_command_line && matchesAny(cmdLine, conditions.allowlist_command_line, 'contains')) {
      return failureResult;
    }

    // Find the specific matching term
    const terms = Array.isArray(expectedCmds) ? expectedCmds : [expectedCmds];
    const matchedTerm = terms.find(t => normalize(cmdLine).includes(normalize(t)));
    evidence.command_line = cmdLine;
    evidence.matched_criteria.push(`Command line contains suspicious argument '${matchedTerm}'`);
  }

  // 5. Condition: Executable Path
  if (conditions.executable_path) {
    const exePath = event.image_path || (event.process_name ? `C:\\Windows\\System32\\${event.process_name}` : '');
    if (!exePath || !matchesAny(exePath, conditions.executable_path, 'contains')) {
      return failureResult;
    }
    const terms = Array.isArray(conditions.executable_path) ? conditions.executable_path : [conditions.executable_path];
    const matchedPath = terms.find(p => normalize(exePath).includes(normalize(p)));
    evidence.executable_path = exePath;
    evidence.matched_criteria.push(`Executable path is located in suspicious directory '${matchedPath}'`);
  }

  // 6. Condition: Hash (Cryptographic Hash or Threat Intel IoC Match)
  if (conditions.hash) {
    const fileHash = event.file_hash || '';

    if (conditions.hash === 'threat_intel_match') {
      if (!fileHash) {
        return failureResult;
      }
      try {
        const iocMatch = query<{ type: string; value: string; description: string; threat_actor: string }>(
          'SELECT * FROM threat_intel WHERE LOWER(value) = LOWER(?)',
          [fileHash]
        );
        if (iocMatch.length === 0) {
          return failureResult;
        }
        evidence.hash = `${fileHash} [Threat Intel: ${iocMatch[0].threat_actor || 'Malicious'} - ${iocMatch[0].description}]`;
        evidence.matched_criteria.push(`Binary SHA-256 hash matches verified Threat Intel IoC '${fileHash}'`);
      } catch {
        return failureResult;
      }
    } else {
      if (!fileHash || !matchesAny(fileHash, conditions.hash, 'exact')) {
        return failureResult;
      }
      evidence.hash = fileHash;
      evidence.matched_criteria.push(`Binary hash matches rule target '${fileHash}'`);
    }
  }

  // 7. Condition: Username
  if (conditions.username) {
    const user = event.user || '';
    if (!user || !matchesAny(user, conditions.username, 'contains')) {
      return failureResult;
    }
    evidence.username = user;
    evidence.matched_criteria.push(`Security principal matches user '${user}'`);
  }

  // 8. Condition: Process Relationships
  if (conditions.process_relationships) {
    const rel = conditions.process_relationships;
    const relEvidences: string[] = [];

    // Signature relationship: is_unsigned
    if (rel.is_unsigned === true) {
      const sigStatus = normalize(event.signature_status);
      const isUnsigned = sigStatus === 'unsigned' || sigStatus === 'invalid' || sigStatus === 'untrusted';
      if (!isUnsigned) {
        return failureResult;
      }
      relEvidences.push(`Target binary is unsigned / unverified (Authenticode: ${event.signature_status || 'Unsigned'})`);
    }

    // Parent relationship: parent_in
    if (rel.parent_in && rel.parent_in.length > 0) {
      let parentName = event.parent_process_name || '';
      if (!parentName && event.parent_process_id) {
        try {
          const parentRecords = query<{ process_name: string }>(
            'SELECT process_name FROM process_events WHERE pid = ? ORDER BY id DESC LIMIT 1',
            [event.parent_process_id]
          );
          if (parentRecords[0]) {
            parentName = parentRecords[0].process_name;
          }
        } catch {
          // Ignore
        }
      }
      if (!matchesAny(parentName || '', rel.parent_in, 'endsWith')) {
        return failureResult;
      }
      relEvidences.push(`Parent process '${parentName}' belongs to suspicious parent set`);
    }

    // Parent relationship: parent_not_in (unusual parent check)
    if (rel.parent_not_in && rel.parent_not_in.length > 0) {
      let parentName = event.parent_process_name || '';
      if (!parentName && event.parent_process_id) {
        try {
          const parentRecords = query<{ process_name: string }>(
            'SELECT process_name FROM process_events WHERE pid = ? ORDER BY id DESC LIMIT 1',
            [event.parent_process_id]
          );
          if (parentRecords[0]) {
            parentName = parentRecords[0].process_name;
          }
        } catch {
          // Ignore
        }
      }
      if (matchesAny(parentName || '', rel.parent_not_in, 'endsWith')) {
        return failureResult;
      }
      relEvidences.push(`Parent process '${parentName}' is anomalous (not in expected parent set)`);
    }

    // Parent relationship: disallowed_parents / unusual parents
    if (rel.disallowed_parents && rel.disallowed_parents.length > 0) {
      const parentName = event.parent_process_name || '';
      if (!matchesAny(parentName, rel.disallowed_parents, 'endsWith')) {
        return failureResult;
      }
      relEvidences.push(`Parent '${parentName}' is an unusual disallowed parent for this binary`);
    }

    // Integrity Escalation
    if (rel.integrity_escalation === true) {
      const childIntegrity = normalize(event.integrity_level || 'medium');
      const isElevated = childIntegrity === 'high' || childIntegrity === 'system';
      if (!isElevated) {
        return failureResult;
      }
      relEvidences.push(`Integrity level escalated to '${event.integrity_level}'`);
    }

    // Parent is LOLBin check
    if (rel.parent_is_lolbin === true) {
      const parentName = normalize(event.parent_process_name || '');
      const lolbins = [
        'powershell.exe', 'pwsh.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe',
        'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'wmic.exe', 'cscript.exe',
        'wscript.exe', 'msiexec.exe', 'schtasks.exe', 'reg.exe'
      ];
      const isLolbinParent = lolbins.some(l => parentName === l || parentName.endsWith('\\' + l) || parentName.endsWith('/' + l));
      if (!isLolbinParent) {
        return failureResult;
      }
      relEvidences.push(`Parent process '${parentName}' is a monitored Living-off-the-Land Binary (LOLBin)`);
    }

    // Target is Executable (for LOLBin -> executable)
    if (rel.target_is_executable === true) {
      const procName = normalize(event.process_name || '');
      const exeExtensions = ['.exe', '.scr', '.com', '.bat', '.cmd', '.pif'];
      const isExe = exeExtensions.some(ext => procName.endsWith(ext)) || (!procName.includes('.') && procName.length > 0);
      // Exclude harmless conhost.exe
      const isBenignHelper = procName === 'conhost.exe';
      if (!isExe || isBenignHelper) {
        return failureResult;
      }
      relEvidences.push(`Target process '${procName}' is an executable payload spawned by LOLBin`);
    }

    // Temporary location check
    if (rel.is_temp_location === true) {
      const pathToCheck = normalize(event.image_path || event.executable_path || event.process_path || event.command_line || '');
      const tempIndicators = ['\\appdata\\local\\temp\\', '\\windows\\temp\\', '\\users\\public\\', '\\temp\\', '/tmp/', '\\programdata\\'];
      const inTemp = tempIndicators.some(t => pathToCheck.includes(t));
      if (!inTemp) {
        return failureResult;
      }
      relEvidences.push(`Binary execution path is hosted within temporary staging location`);
    }

    // Hidden window execution check
    if (rel.is_hidden === true) {
      const cmd = normalize(event.command_line || '');
      const hiddenFlags = ['-windowstyle hidden', '-w hidden', '-win hidden', '-w 1', '-win 1', 'vbhide', 'start /b'];
      const isHidden = hiddenFlags.some(f => cmd.includes(f));
      if (!isHidden) {
        return failureResult;
      }
      relEvidences.push(`Process invoked with hidden window / stealth execution arguments`);
    }

    // Encoded command execution check
    if (rel.is_encoded === true) {
      const cmd = normalize(event.command_line || '');
      const encFlags = ['-enc', '-encodedcommand', '-encoded', '-e ', '-ec ', '-en '];
      const isEnc = encFlags.some(f => cmd.includes(f));
      if (!isEnc) {
        return failureResult;
      }
      relEvidences.push(`Command line contains obfuscated Base64-encoded script arguments`);
    }

    // Download command check
    if (rel.is_download === true) {
      const cmd = normalize(event.command_line || '');
      const dlFlags = ['downloadstring', 'downloadfile', 'invoke-webrequest', 'iwr ', 'start-bitstransfer', 'net.webclient', '-urlcache', '/transfer', '/download', 'http://', 'https://'];
      const isDl = dlFlags.some(f => cmd.includes(f));
      if (!isDl) {
        return failureResult;
      }
      relEvidences.push(`Command line contains remote download cradle or file transfer parameters`);
    }

    if (relEvidences.length > 0) {
      evidence.process_relationships = relEvidences.join('; ');
      evidence.matched_criteria.push(...relEvidences);
    }
  }

  // 9. Condition: Event Category (process, network, file, registry, windows_event)
  if (conditions.event_category) {
    const allowedCats = Array.isArray(conditions.event_category) ? conditions.event_category : [conditions.event_category];
    if (!allowedCats.includes(event.event_category || 'process')) {
      return failureResult;
    }
    evidence.matched_criteria.push(`Event category matches '${event.event_category}'`);
  }

  // 10. Condition: Windows Event ID (e.g. 4624, 4625, 4720, 4672, 7045, 106, 4104, 1116, 5001)
  if (conditions.windows_event_id) {
    const allowedEids = Array.isArray(conditions.windows_event_id) ? conditions.windows_event_id.map(Number) : [Number(conditions.windows_event_id)];
    if (!event.windows_event_id || !allowedEids.includes(Number(event.windows_event_id))) {
      return failureResult;
    }
    evidence.windows_event_id = event.windows_event_id;
    evidence.matched_criteria.push(`Windows Event ID matches target '${event.windows_event_id}'`);
  }

  // 11. Condition: Channel (Security, System, PowerShell, Windows Defender, Task Scheduler)
  if (conditions.channel) {
    const allowedChans = Array.isArray(conditions.channel) ? conditions.channel : [conditions.channel];
    if (!event.channel || !matchesAny(event.channel, allowedChans, 'exact')) {
      return failureResult;
    }
    evidence.channel = event.channel;
    evidence.matched_criteria.push(`Windows Event Channel matches '${event.channel}'`);
  }

  // 12. Condition: Target User Account
  if (conditions.target_user) {
    const targetUser = event.target_user || '';
    if (!targetUser || !matchesAny(targetUser, conditions.target_user, 'contains')) {
      return failureResult;
    }
    evidence.target_user = targetUser;
    evidence.matched_criteria.push(`Target User Account matches '${targetUser}'`);
  }

  // 13. Condition: Service Name
  if (conditions.service_name) {
    const svcName = event.service_name || '';
    if (!svcName || !matchesAny(svcName, conditions.service_name, 'contains')) {
      return failureResult;
    }
    evidence.service_name = svcName;
    evidence.matched_criteria.push(`Service Name matches target '${svcName}'`);
  }

  // 14. Condition: Task Name
  if (conditions.task_name) {
    const taskName = event.task_name || '';
    if (!taskName || !matchesAny(taskName, conditions.task_name, 'contains')) {
      return failureResult;
    }
    evidence.task_name = taskName;
    evidence.matched_criteria.push(`Scheduled Task Name matches '${taskName}'`);
  }

  // 15. Condition: Script Text (PowerShell ScriptBlock logging)
  if (conditions.script_text) {
    const scriptText = event.script_text || event.command_line || '';
    if (!scriptText || !matchesAny(scriptText, conditions.script_text, 'contains')) {
      return failureResult;
    }
    evidence.script_text = scriptText.substring(0, 100);
    evidence.matched_criteria.push(`Script block contains suspicious expression`);
  }

  // 16. Condition: Network Destination IP or Port
  if (conditions.destination_ip) {
    const destIp = event.destination_ip || '';
    if (!destIp || !matchesAny(destIp, conditions.destination_ip, 'exact')) {
      return failureResult;
    }
    evidence.destination_ip = destIp;
    evidence.matched_criteria.push(`Network destination IP matches '${destIp}'`);
  }

  if (conditions.destination_port) {
    const destPort = event.destination_port;
    const allowedPorts = Array.isArray(conditions.destination_port) ? conditions.destination_port : [conditions.destination_port];
    if (!destPort || !allowedPorts.includes(destPort)) {
      return failureResult;
    }
    evidence.matched_criteria.push(`Network destination port matches '${destPort}'`);
  }

  // 17. Condition: File Path
  if (conditions.file_path) {
    const filePath = event.file_path || event.image_path || '';
    if (!filePath || !matchesAny(filePath, conditions.file_path, 'contains')) {
      return failureResult;
    }
    evidence.matched_criteria.push(`File path matches target '${filePath}'`);
  }

  // 18. Condition: Registry Key
  if (conditions.registry_key) {
    const regKey = event.registry_key || '';
    if (!regKey || !matchesAny(regKey, conditions.registry_key, 'contains')) {
      return failureResult;
    }
    evidence.matched_criteria.push(`Registry key matches target '${regKey}'`);
  }

  // If no conditions were specified or matched criteria is empty, do not alert!
  if (evidence.matched_criteria.length === 0) {
    return failureResult;
  }

  return {
    matched: true,
    reason: evidence.matched_criteria.join(' AND '),
    evidence
  };
}
