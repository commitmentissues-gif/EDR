import { MonitoredLolbinName, LolbinProfile } from './types.js';

export const MONITORED_LOLBINS_LIST: MonitoredLolbinName[] = [
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

export const LOLBIN_PROFILES: Record<MonitoredLolbinName, LolbinProfile> = {
  'powershell.exe': {
    binary: 'powershell.exe',
    name: 'Windows PowerShell Interpreter',
    category: 'Scripting / Shell',
    standardPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    description: 'Native task-based command-line shell and scripting language built on .NET. Frequently abused for in-memory execution, cradle downloads, and post-exploitation.',
    primaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1059.001',
      technique_name: 'Command and Scripting Interpreter: PowerShell',
      subtechnique_id: 'T1059.001',
      subtechnique_name: 'PowerShell'
    },
    benignExamples: [
      'powershell.exe Get-Process',
      'powershell.exe Get-Date',
      'powershell.exe -Command "$PSVersionTable"',
      'powershell.exe Get-Service -Name Spooler'
    ],
    suspiciousIndicators: [
      '-enc',
      '-encodedcommand',
      '-e ',
      'frombase64string',
      'downloadstring',
      'downloadfile',
      'invoke-webrequest',
      'iwr',
      'invoke-expression',
      'iex',
      '-w hidden',
      '-windowstyle hidden',
      '-executionpolicy bypass',
      '-ep bypass',
      '-nop',
      '-noprofile',
      'system.net.webclient',
      'reflection.assembly'
    ],
    monitoredParents: [
      'winword.exe',
      'excel.exe',
      'powerpnt.exe',
      'outlook.exe',
      'chrome.exe',
      'msedge.exe',
      'firefox.exe',
      'brave.exe'
    ]
  },
  'cmd.exe': {
    binary: 'cmd.exe',
    name: 'Windows Command Processor',
    category: 'Scripting / Shell',
    standardPath: 'C:\\Windows\\System32\\cmd.exe',
    description: 'Default command-line interpreter for Windows. Abused to orchestrate batch scripts, LOLBin invocations, and shadow copy deletions.',
    primaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1059.003',
      technique_name: 'Command and Scripting Interpreter: Windows Command Shell',
      subtechnique_id: 'T1059.003',
      subtechnique_name: 'Windows Command Shell'
    },
    benignExamples: [
      'cmd.exe /c echo Hello World',
      'cmd.exe /c dir',
      'cmd.exe /c ver',
      'cmd.exe /c date /t'
    ],
    suspiciousIndicators: [
      '/c powershell',
      '/c certutil',
      '/c mshta',
      '/c bitsadmin',
      '/c regsvr32',
      '/c rundll32',
      'delete shadows',
      'vssadmin',
      'whoami /priv',
      'wmic shadowcopy'
    ],
    monitoredParents: [
      'winword.exe',
      'excel.exe',
      'chrome.exe',
      'msedge.exe',
      'firefox.exe'
    ]
  },
  'rundll32.exe': {
    binary: 'rundll32.exe',
    name: 'Run a DLL as an App',
    category: 'Execution Proxy',
    standardPath: 'C:\\Windows\\System32\\rundll32.exe',
    description: 'Executes 32-bit and 64-bit DLL routines. Abused to proxy malicious payload execution and evade application control policies.',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218.011',
      technique_name: 'System Binary Proxy Execution: Rundll32',
      subtechnique_id: 'T1218.011',
      subtechnique_name: 'Rundll32'
    },
    benignExamples: [
      'rundll32.exe shell32.dll,Control_RunDLL',
      'rundll32.exe user32.dll,LockWorkStation',
      'rundll32.exe printui.dll,PrintUIEntry'
    ],
    suspiciousIndicators: [
      'javascript:',
      'mshtml',
      'runhtmlapplication',
      '#1',
      '\\temp\\',
      '\\appdata\\',
      '\\users\\public\\',
      'davclnt.dll',
      'url.dll,openurl',
      'shell32.dll,shellexec_rundll'
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'wscript.exe',
      'cscript.exe'
    ]
  },
  'regsvr32.exe': {
    binary: 'regsvr32.exe',
    name: 'Microsoft Register Server',
    category: 'Execution Proxy',
    standardPath: 'C:\\Windows\\System32\\regsvr32.exe',
    description: 'Registers and unregisters OLE controls. Extensively abused via Squiblydoo to execute arbitrary COM scriptlets (.sct) over the network.',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218.010',
      technique_name: 'System Binary Proxy Execution: Regsvr32',
      subtechnique_id: 'T1218.010',
      subtechnique_name: 'Regsvr32'
    },
    benignExamples: [
      'regsvr32.exe /s ole32.dll',
      'regsvr32.exe /s actxprxy.dll'
    ],
    suspiciousIndicators: [
      '/i:http',
      '/i:https',
      '/i:ftp',
      '.sct',
      'scrobj.dll',
      '/s /u /i:',
      '\\temp\\',
      '\\users\\public\\'
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'winword.exe',
      'excel.exe'
    ]
  },
  'mshta.exe': {
    binary: 'mshta.exe',
    name: 'Microsoft HTML Application Host',
    category: 'Execution Proxy',
    standardPath: 'C:\\Windows\\System32\\mshta.exe',
    description: 'Executes Microsoft HTML Applications (.hta) and inline scripts. Frequently abused to execute VBScript or JavaScript payloads outside browser sandbox.',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218.005',
      technique_name: 'System Binary Proxy Execution: Mshta',
      subtechnique_id: 'T1218.005',
      subtechnique_name: 'Mshta'
    },
    benignExamples: [
      'mshta.exe C:\\Windows\\System32\\HelpPane.hta'
    ],
    suspiciousIndicators: [
      'javascript:',
      'vbscript:',
      'http://',
      'https://',
      '.hta',
      'wscript.shell',
      'run(',
      'exec('
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'winword.exe',
      'excel.exe',
      'chrome.exe'
    ]
  },
  'certutil.exe': {
    binary: 'certutil.exe',
    name: 'Certificate Services Utility',
    category: 'Utility / Transfer',
    standardPath: 'C:\\Windows\\System32\\certutil.exe',
    description: 'Windows command-line tool for Certificate Services. Widely abused to download remote malicious payloads and decode base64 files.',
    primaryMitre: {
      tactic: 'Command and Control',
      technique_id: 'T1105',
      technique_name: 'Ingress Tool Transfer'
    },
    benignExamples: [
      'certutil.exe -hashfile C:\\Windows\\System32\\notepad.exe SHA256',
      'certutil.exe -hashfile file.txt MD5',
      'certutil.exe -dump mycert.cer',
      'certutil.exe -v -store root'
    ],
    suspiciousIndicators: [
      '-urlcache',
      '-split',
      '-f http',
      '-f https',
      '-decode',
      '-decodehex',
      '-encode',
      '\\temp\\',
      '\\users\\public\\'
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'winword.exe',
      'excel.exe'
    ]
  },
  'bitsadmin.exe': {
    binary: 'bitsadmin.exe',
    name: 'BITS Administration Utility',
    category: 'Utility / Transfer',
    standardPath: 'C:\\Windows\\System32\\bitsadmin.exe',
    description: 'Manages Background Intelligent Transfer Service (BITS) jobs. Abused by adversaries for stealthy background downloads and payload staging.',
    primaryMitre: {
      tactic: 'Command and Control',
      technique_id: 'T1105',
      technique_name: 'Ingress Tool Transfer'
    },
    benignExamples: [
      'bitsadmin.exe /list /allusers',
      'bitsadmin.exe /reset'
    ],
    suspiciousIndicators: [
      '/transfer',
      '/download',
      '/addfile',
      '/setnotifycmdline',
      'http://',
      'https://',
      '\\temp\\'
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'winword.exe',
      'excel.exe'
    ]
  },
  'wmic.exe': {
    binary: 'wmic.exe',
    name: 'WMI Command-Line Utility',
    category: 'System Management',
    standardPath: 'C:\\Windows\\System32\\wbem\\wmic.exe',
    description: 'Provides command-line interface for Windows Management Instrumentation. Abused for process creation, defense evasion, and remote command execution.',
    primaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1047',
      technique_name: 'Windows Management Instrumentation'
    },
    benignExamples: [
      'wmic.exe os get caption,version',
      'wmic.exe cpu get name',
      'wmic.exe logicaldisk get size,freespace,caption',
      'wmic.exe bios get serialnumber'
    ],
    suspiciousIndicators: [
      'process call create',
      'shadowcopy delete',
      '/node:',
      '/user:',
      'startup list',
      'process get commandline',
      'os where',
      'antivirusproduct'
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'winword.exe',
      'excel.exe'
    ]
  },
  'cscript.exe': {
    binary: 'cscript.exe',
    name: 'Microsoft Console-Based Script Host',
    category: 'Scripting / Shell',
    standardPath: 'C:\\Windows\\System32\\cscript.exe',
    description: 'Console-based Windows Script Host for executing VBScript and JScript files. Used for proxy script execution.',
    primaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1059.005',
      technique_name: 'Command and Scripting Interpreter: Visual Basic',
      subtechnique_id: 'T1059.005',
      subtechnique_name: 'Visual Basic'
    },
    benignExamples: [
      'cscript.exe //nologo C:\\Windows\\System32\\Printing_Admin_Scripts\\en-US\\prnmngr.vbs -l',
      'cscript.exe //nologo slmgr.vbs /dli'
    ],
    suspiciousIndicators: [
      '//e:vbscript',
      '//e:jscript',
      '\\temp\\',
      '\\users\\public\\',
      '\\appdata\\',
      '.vbe',
      '.jse',
      '.wsf'
    ],
    monitoredParents: [
      'winword.exe',
      'excel.exe',
      'chrome.exe'
    ]
  },
  'wscript.exe': {
    binary: 'wscript.exe',
    name: 'Microsoft Windows-Based Script Host',
    category: 'Scripting / Shell',
    standardPath: 'C:\\Windows\\System32\\wscript.exe',
    description: 'GUI-based Windows Script Host for executing VBScript and JScript files. Commonly abused in phishing attachments.',
    primaryMitre: {
      tactic: 'Execution',
      technique_id: 'T1059.005',
      technique_name: 'Command and Scripting Interpreter: Visual Basic',
      subtechnique_id: 'T1059.005',
      subtechnique_name: 'Visual Basic'
    },
    benignExamples: [
      'wscript.exe //b C:\\Windows\\System32\\slmgr.vbs'
    ],
    suspiciousIndicators: [
      '//e:vbscript',
      '//e:jscript',
      '\\temp\\',
      '\\users\\public\\',
      '\\appdata\\',
      '.vbs',
      '.js'
    ],
    monitoredParents: [
      'winword.exe',
      'excel.exe',
      'outlook.exe',
      'chrome.exe',
      'msedge.exe'
    ]
  },
  'msiexec.exe': {
    binary: 'msiexec.exe',
    name: 'Windows Installer Executable',
    category: 'Execution Proxy',
    standardPath: 'C:\\Windows\\System32\\msiexec.exe',
    description: 'Windows Installer component for installing and managing MSI and MSP packages. Abused to download and execute remote packages silently.',
    primaryMitre: {
      tactic: 'Defense Evasion',
      technique_id: 'T1218.007',
      technique_name: 'System Binary Proxy Execution: Msiexec',
      subtechnique_id: 'T1218.007',
      subtechnique_name: 'Msiexec'
    },
    benignExamples: [
      'msiexec.exe /i package.msi /qn',
      'msiexec.exe /x {GUID} /qn',
      'msiexec.exe /?'
    ],
    suspiciousIndicators: [
      '/q /i http',
      '/qn /i http',
      '/i http://',
      '/i https://',
      '/y ',
      '/z ',
      '\\temp\\',
      '\\users\\public\\'
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'winword.exe',
      'excel.exe'
    ]
  },
  'schtasks.exe': {
    binary: 'schtasks.exe',
    name: 'Task Scheduler Command-Line Utility',
    category: 'System Management',
    standardPath: 'C:\\Windows\\System32\\schtasks.exe',
    description: 'Enables administrator to create, delete, query, change, run, and end scheduled tasks on a local or remote computer.',
    primaryMitre: {
      tactic: 'Persistence',
      technique_id: 'T1053.005',
      technique_name: 'Scheduled Task/Job: Scheduled Task',
      subtechnique_id: 'T1053.005',
      subtechnique_name: 'Scheduled Task'
    },
    benignExamples: [
      'schtasks.exe /query',
      'schtasks.exe /query /fo list',
      'schtasks.exe /query /tn "Microsoft\\Windows\\Defrag"',
      'schtasks.exe /?'
    ],
    suspiciousIndicators: [
      '/create',
      '/change',
      '/run',
      '/tr powershell',
      '/tr cmd',
      '/tr mshta',
      '/tr certutil',
      '/sc onlogon',
      '/sc onstart'
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'winword.exe',
      'excel.exe'
    ]
  },
  'reg.exe': {
    binary: 'reg.exe',
    name: 'Windows Registry Console Tool',
    category: 'System Management',
    standardPath: 'C:\\Windows\\System32\\reg.exe',
    description: 'Manipulates registry keys, values, and security permissions. Extensively abused to establish persistence in Run/RunOnce keys or disable security controls.',
    primaryMitre: {
      tactic: 'Persistence',
      technique_id: 'T1547.001',
      technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
      subtechnique_id: 'T1547.001',
      subtechnique_name: 'Registry Run Keys'
    },
    benignExamples: [
      'reg.exe query HKLM\\Software\\Microsoft\\Windows',
      'reg.exe query HKCU\\Software',
      'reg.exe /?'
    ],
    suspiciousIndicators: [
      'add ',
      'delete ',
      '\\currentversion\\run',
      '\\currentversion\\runonce',
      '\\services\\',
      '\\image file execution options',
      'disableantivirus',
      'disablerealtimemonitoring'
    ],
    monitoredParents: [
      'powershell.exe',
      'cmd.exe',
      'winword.exe',
      'excel.exe'
    ]
  }
};
