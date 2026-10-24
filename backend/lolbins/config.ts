import { LolbinRuleConfig } from './types.js';
import { query, run } from '../db/index.js';
import { logger } from '../logger/index.js';

const log = logger.forComponent('LolbinConfig');

export const DEFAULT_LOLBIN_RULES: LolbinRuleConfig[] = [
  {
    id: 'LOLBIN-001-ENCODED-POWERSHELL',
    name: 'Encoded or Obfuscated PowerShell Command',
    behavior: 'encoded_powershell',
    targetBinaries: ['powershell.exe'],
    enabled: true,
    severity: 'HIGH',
    score: 80,
    mitre: {
      tactic: 'Execution',
      technique_id: 'T1059.001',
      technique_name: 'Command and Scripting Interpreter: PowerShell',
      subtechnique_id: 'T1059.001',
      subtechnique_name: 'PowerShell'
    },
    description: 'Detects PowerShell executed with encoded command flags (-enc, -EncodedCommand, -e) hiding underlying payload instructions.',
    recommendedAction: 'Decode base64 payload parameter, inspect invoked cmdlets, and investigate parent process lineage.'
  },
  {
    id: 'LOLBIN-002-SUSPICIOUS-DOWNLOAD',
    name: 'LOLBin Ingress Tool Transfer (Download Utility)',
    behavior: 'suspicious_download',
    targetBinaries: ['certutil.exe', 'bitsadmin.exe', 'powershell.exe', 'msiexec.exe'],
    enabled: true,
    severity: 'HIGH',
    score: 85,
    mitre: {
      tactic: 'Command and Control',
      technique_id: 'T1105',
      technique_name: 'Ingress Tool Transfer'
    },
    description: 'Detects native Windows system binaries executing remote file download commands (certutil -urlcache, bitsadmin /transfer, WebClient.DownloadFile, msiexec /q /i http).',
    recommendedAction: 'Block remote destination IP at firewall, locate downloaded file, and quarantine payload.'
  },
  {
    id: 'LOLBIN-003-HIDDEN-EXECUTION',
    name: 'Stealthy Hidden Window Execution',
    behavior: 'hidden_execution',
    targetBinaries: ['powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'],
    enabled: true,
    severity: 'MEDIUM',
    score: 65,
    mitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1564.003',
      technique_name: 'Hide Artifacts: Hidden Window',
      subtechnique_id: 'T1564.003',
      subtechnique_name: 'Hidden Window'
    },
    description: 'Detects command interpreters or script hosts executing with parameters explicitly suppressing user GUI windows (-w hidden, -WindowStyle Hidden, //b).',
    recommendedAction: 'Inspect script or command contents. Verify whether execution was initiated by authorized IT management software.'
  },
  {
    id: 'LOLBIN-004-OFFICE-TO-POWERSHELL',
    name: 'Office Application Spawning PowerShell/Command Shell',
    behavior: 'office_to_powershell',
    targetBinaries: ['powershell.exe', 'cmd.exe'],
    enabled: true,
    severity: 'CRITICAL',
    score: 95,
    mitre: {
      tactic: 'Execution',
      technique_id: 'T1204.002',
      technique_name: 'User Execution: Malicious File',
      subtechnique_id: 'T1204.002',
      subtechnique_name: 'Malicious File'
    },
    description: 'Detects Microsoft Office applications (Word, Excel, PowerPoint, Outlook) directly spawning PowerShell or cmd.exe, a classic indicator of macro exploitation.',
    recommendedAction: 'CRITICAL: Terminate child shell immediately, quarantine document attachment, and isolate host.'
  },
  {
    id: 'LOLBIN-005-BROWSER-TO-POWERSHELL',
    name: 'Web Browser Spawning Interactive Shell',
    behavior: 'browser_to_powershell',
    targetBinaries: ['powershell.exe', 'cmd.exe'],
    enabled: true,
    severity: 'CRITICAL',
    score: 90,
    mitre: {
      tactic: 'Execution',
      technique_id: 'T1059.001',
      technique_name: 'Command and Scripting Interpreter: PowerShell',
      subtechnique_id: 'T1059.001',
      subtechnique_name: 'PowerShell'
    },
    description: 'Detects web browsers (Chrome, Edge, Firefox, Brave) spawning shell interpreters directly, indicative of drive-by download or browser exploit.',
    recommendedAction: 'Inspect URL history in browser, quarantine downloaded files, and inspect parent process execution tree.'
  },
  {
    id: 'LOLBIN-006-POWERSHELL-TO-LOLBIN',
    name: 'PowerShell Spawning Secondary LOLBin Proxy',
    behavior: 'powershell_to_lolbin',
    targetBinaries: ['certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'bitsadmin.exe', 'wmic.exe'],
    enabled: true,
    severity: 'HIGH',
    score: 80,
    mitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218',
      technique_name: 'System Binary Proxy Execution'
    },
    description: 'Detects PowerShell spawning secondary proxy binaries (mshta, regsvr32, rundll32, certutil), a standard evasion chain to bypass process restrictions.',
    recommendedAction: 'Inspect full execution lineage, capture arguments passed to the secondary LOLBin, and quarantine referenced artifacts.'
  },
  {
    id: 'LOLBIN-007-LOLBIN-TO-EXECUTABLE',
    name: 'Execution Proxy LOLBin Spawning Child Process',
    behavior: 'lolbin_to_executable',
    targetBinaries: ['mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'wscript.exe', 'cscript.exe'],
    enabled: true,
    severity: 'HIGH',
    score: 85,
    mitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218',
      technique_name: 'System Binary Proxy Execution'
    },
    description: 'Detects proxy execution hosts (mshta, rundll32, regsvr32, cscript, wscript) spawning child shells or executables, indicating successful scriptlet or DLL payload detonation.',
    recommendedAction: 'Inspect script or DLL invoked by parent LOLBin and terminate child process.'
  },
  {
    id: 'LOLBIN-008-TEMP-LOCATION-EXECUTION',
    name: 'LOLBin Launching from Temporary or Staging Directory',
    behavior: 'temp_location_execution',
    targetBinaries: [
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
    ],
    enabled: true,
    severity: 'HIGH',
    score: 80,
    mitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1027',
      technique_name: 'Obfuscated Files or Information'
    },
    description: 'Detects LOLBins executing files from user-writable temporary staging directories (%TEMP%, \\Users\\Public\\, \\Windows\\Temp\\), standard dropper staging locations.',
    recommendedAction: 'Examine temporary directory artifact. Calculate SHA-256 hash and quarantine file.'
  }
];

let activeLolbinRules: LolbinRuleConfig[] = [...DEFAULT_LOLBIN_RULES];

/**
 * Initializes and loads LOLBin configuration from SQLite
 */
export function initLolbinConfig(): void {
  try {
    const rows = query<{ key: string; value: string }>(
      'SELECT key, value FROM system_metadata WHERE key = "lolbin_rules_config"'
    );
    if (rows.length > 0 && rows[0].value) {
      const parsed = JSON.parse(rows[0].value);
      if (Array.isArray(parsed)) {
        activeLolbinRules = parsed;
        log.info(`Loaded ${activeLolbinRules.length} LOLBin rules from database`);
        return;
      }
    }
  } catch (err) {
    log.warn('Could not load custom LOLBin config from database, using defaults:', err);
  }
  activeLolbinRules = [...DEFAULT_LOLBIN_RULES];
}

export function getLolbinRules(): LolbinRuleConfig[] {
  return activeLolbinRules;
}

export function getLolbinRuleById(id: string): LolbinRuleConfig | null {
  return activeLolbinRules.find(r => r.id === id) || null;
}

export function updateLolbinRule(id: string, updates: Partial<LolbinRuleConfig>): LolbinRuleConfig {
  const index = activeLolbinRules.findIndex(r => r.id === id);
  if (index === -1) {
    throw new Error(`LOLBin rule with ID '${id}' not found`);
  }

  const updated: LolbinRuleConfig = {
    ...activeLolbinRules[index],
    ...updates
  };

  activeLolbinRules[index] = updated;

  try {
    run(
      'INSERT OR REPLACE INTO system_metadata (key, value, updated_at) VALUES (?, ?, ?)',
      ['lolbin_rules_config', JSON.stringify(activeLolbinRules), new Date().toISOString()]
    );
  } catch (err) {
    log.warn('Failed to persist LOLBin rules config to database:', err);
  }

  log.info(`Updated LOLBin rule ${id}: enabled=${updated.enabled}, score=${updated.score}`);
  return updated;
}

export function resetLolbinRules(): LolbinRuleConfig[] {
  activeLolbinRules = [...DEFAULT_LOLBIN_RULES];
  try {
    run(
      'INSERT OR REPLACE INTO system_metadata (key, value, updated_at) VALUES (?, ?, ?)',
      ['lolbin_rules_config', JSON.stringify(activeLolbinRules), new Date().toISOString()]
    );
  } catch (err) {
    log.warn('Failed to reset LOLBin rules in database:', err);
  }
  return activeLolbinRules;
}
