import { TelemetryEvent } from '../types.js';
import { 
  MonitoredBinaryName, 
  ContextualBehaviorType, 
  LolbinDetectionResult,
  LolbinGlobalConfig
} from './types.js';
import { 
  MONITORED_BINARIES, 
  CONTEXTUAL_BEHAVIORS, 
  DEFAULT_LOLBIN_CONFIG 
} from './definitions.js';

function normalize(val?: string | null): string {
  return (val || '').trim().toLowerCase();
}

function cleanProcName(raw?: string | null): string {
  if (!raw) return '';
  const base = raw.includes('\\') ? raw.split('\\').pop() : (raw.includes('/') ? raw.split('/').pop() : raw);
  return normalize(base);
}

/**
 * Contextual LOLBin and PowerShell Detection Engine
 * Accurately detects suspicious behavioral patterns on all 13 monitored binaries
 * while suppressing false positives on benign administrative commands.
 */
export class LolbinContextualDetector {
  private config: LolbinGlobalConfig = { ...DEFAULT_LOLBIN_CONFIG };
  private binaryStatus: Map<MonitoredBinaryName, boolean> = new Map();

  constructor(customConfig?: Partial<LolbinGlobalConfig>) {
    if (customConfig) {
      this.config = { ...this.config, ...customConfig };
    }
    // Initialize all monitored binaries as enabled
    for (const b of MONITORED_BINARIES) {
      this.binaryStatus.set(b.name, b.enabled);
    }
  }

  public setConfig(newConfig: Partial<LolbinGlobalConfig>): void {
    this.config = { ...this.config, ...newConfig, lastUpdated: new Date().toISOString() };
  }

  public getConfig(): LolbinGlobalConfig {
    return { ...this.config };
  }

  public setBinaryEnabled(name: MonitoredBinaryName, enabled: boolean): void {
    this.binaryStatus.set(name, enabled);
  }

  public isBinaryEnabled(name: MonitoredBinaryName): boolean {
    return this.binaryStatus.get(name) ?? true;
  }

  /**
   * Evaluates a telemetry event contextually
   */
  public evaluate(event: TelemetryEvent): LolbinDetectionResult {
    const procName = cleanProcName(event.process_name || event.image_path);
    const parentName = cleanProcName(event.parent_process_name);
    const cmdLine = normalize(event.command_line);
    const imagePath = normalize(event.image_path || event.process_path || event.executable_path);

    // Identify target binary
    let monitoredBinary: MonitoredBinaryName | undefined;
    if (procName === 'pwsh.exe' || procName === 'powershell.exe') {
      monitoredBinary = 'powershell.exe';
    } else {
      const match = MONITORED_BINARIES.find(b => b.name === procName);
      if (match) monitoredBinary = match.name;
    }

    // Check if parent is a monitored LOLBin (e.g. for PowerShell -> LOLBin or LOLBin -> Executable)
    const isParentLolbin = MONITORED_BINARIES.some(b => b.name === parentName || (parentName === 'pwsh.exe' && b.name === 'powershell.exe'));
    const isLolbinEvent = Boolean(monitoredBinary) || isParentLolbin;

    const emptyResult: LolbinDetectionResult = {
      isLolbinEvent,
      monitoredBinary,
      isSuspicious: false,
      isBenignMatch: false,
      behaviorsDetected: [],
      behaviorDetails: [],
      totalScore: 0,
      severity: 'INFO',
      summary: 'No suspicious LOLBin activity detected.',
      recommendation: 'No action required.',
      processLineage: [
        { role: 'parent', name: event.parent_process_name || 'unknown.exe', pid: event.parent_process_id || 0 },
        { role: 'target', name: event.process_name || 'unknown.exe', pid: event.process_id || 0, commandLine: event.command_line }
      ]
    };

    if (!isLolbinEvent && !this.isExecutionFromTemp(imagePath, cmdLine)) {
      return emptyResult;
    }

    // If contextual detection is globally disabled, return clean
    if (!this.config.contextualDetectionEnabled) {
      return emptyResult;
    }

    // Check if the monitored binary is disabled by configuration
    if (monitoredBinary && !this.isBinaryEnabled(monitoredBinary)) {
      return emptyResult;
    }

    // Step 1: Check for Known Benign Usage (Prevent False Positives!)
    if (this.config.suppressBenignAdministrativeCommands && this.isKnownBenign(monitoredBinary, cmdLine, parentName)) {
      return {
        ...emptyResult,
        isBenignMatch: true,
        summary: `Benign administrative command verified for ${monitoredBinary || procName}. Alert suppressed to prevent false positive.`
      };
    }

    // Step 2: Contextual Behavioral Checks
    const detected: ContextualBehaviorType[] = [];
    const details: LolbinDetectionResult['behaviorDetails'] = [];

    // Behavior 1: Encoded PowerShell
    if (monitoredBinary === 'powershell.exe' && this.isEncodedPowerShell(cmdLine)) {
      detected.push('encoded_powershell');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'encoded_powershell')!;
      details.push({
        type: 'encoded_powershell',
        name: def.name,
        description: def.description,
        evidence: `PowerShell executed with obfuscated encoding parameter in command: '${event.command_line}'`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    // Behavior 2: Suspicious Download Commands
    if (this.isSuspiciousDownload(monitoredBinary, cmdLine)) {
      detected.push('suspicious_download');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'suspicious_download')!;
      details.push({
        type: 'suspicious_download',
        name: def.name,
        description: def.description,
        evidence: `Remote download cradle or file transfer parameter detected in command: '${event.command_line}'`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    // Behavior 3: Hidden Execution
    if (this.isHiddenExecution(cmdLine)) {
      detected.push('hidden_execution');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'hidden_execution')!;
      details.push({
        type: 'hidden_execution',
        name: def.name,
        description: def.description,
        evidence: `Stealth/hidden window parameter (-WindowStyle Hidden / vbhide / /b) detected in: '${event.command_line}'`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    // Behavior 4: Unusual Parent Process
    if ((monitoredBinary === 'cmd.exe' || monitoredBinary === 'powershell.exe' || monitoredBinary === 'cscript.exe' || monitoredBinary === 'wscript.exe') 
        && this.isUnusualParent(parentName)) {
      detected.push('unusual_parent');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'unusual_parent')!;
      details.push({
        type: 'unusual_parent',
        name: def.name,
        description: def.description,
        evidence: `Command shell spawned by anomalous system background service '${event.parent_process_name}'`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    // Behavior 5: Office → PowerShell
    if (monitoredBinary === 'powershell.exe' && this.isOfficeParent(parentName)) {
      detected.push('office_to_powershell');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'office_to_powershell')!;
      details.push({
        type: 'office_to_powershell',
        name: def.name,
        description: def.description,
        evidence: `Microsoft Office application '${event.parent_process_name}' spawned PowerShell interpreter (Macro / Exploit)`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    // Behavior 6: Browser → PowerShell
    if ((monitoredBinary === 'powershell.exe' || monitoredBinary === 'cmd.exe') && this.isBrowserParent(parentName)) {
      detected.push('browser_to_powershell');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'browser_to_powershell')!;
      details.push({
        type: 'browser_to_powershell',
        name: def.name,
        description: def.description,
        evidence: `Web browser '${event.parent_process_name}' spawned command interpreter (Drive-by compromise / exploit)`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    // Behavior 7: PowerShell → LOLBin
    if (this.isPowerShellParent(parentName) && monitoredBinary && monitoredBinary !== 'powershell.exe') {
      detected.push('powershell_to_lolbin');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'powershell_to_lolbin')!;
      details.push({
        type: 'powershell_to_lolbin',
        name: def.name,
        description: def.description,
        evidence: `PowerShell execution chain spawned secondary LOLBin '${monitoredBinary}'`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    // Behavior 8: LOLBin → Executable
    if (isParentLolbin && this.isTargetExecutable(procName)) {
      detected.push('lolbin_to_executable');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'lolbin_to_executable')!;
      details.push({
        type: 'lolbin_to_executable',
        name: def.name,
        description: def.description,
        evidence: `Living-off-the-Land binary '${event.parent_process_name}' spawned executable payload '${event.process_name}'`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    // Behavior 9: Execution from Temporary Locations
    if (this.isExecutionFromTemp(imagePath, cmdLine)) {
      detected.push('temp_location_execution');
      const def = CONTEXTUAL_BEHAVIORS.find(b => b.id === 'temp_location_execution')!;
      details.push({
        type: 'temp_location_execution',
        name: def.name,
        description: def.description,
        evidence: `Binary or target path is located in temporary directory staging location: '${event.image_path || event.command_line}'`,
        score: def.baseScore,
        mitre: def.primaryMitre
      });
    }

    const isSuspicious = detected.length > 0;
    if (!isSuspicious) {
      return emptyResult;
    }

    // Calculate composite risk score
    const maxScore = Math.max(...details.map(d => d.score));
    const bonus = Math.min(20, (details.length - 1) * 10);
    const totalScore = Math.min(100, maxScore + bonus);

    let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
    if (totalScore >= 85) severity = 'CRITICAL';
    else if (totalScore >= 70) severity = 'HIGH';
    else if (totalScore >= 50) severity = 'MEDIUM';
    else severity = 'LOW';

    const behaviorNames = details.map(d => d.name).join(', ');
    const summary = `Suspicious LOLBin activity on ${monitoredBinary || procName}: Detected [${behaviorNames}] (Risk Score: ${totalScore}/100 [${severity}])`;
    const recommendation = `Isolate endpoint, terminate process tree (PID ${event.process_id || 'unknown'}), and analyze command line: '${event.command_line}'`;

    return {
      isLolbinEvent,
      monitoredBinary,
      isSuspicious: true,
      isBenignMatch: false,
      behaviorsDetected: detected,
      behaviorDetails: details,
      totalScore,
      severity,
      summary,
      recommendation,
      processLineage: [
        { role: 'parent', name: event.parent_process_name || 'parent.exe', pid: event.parent_process_id || 0 },
        { role: 'target', name: event.process_name || 'target.exe', pid: event.process_id || 0, commandLine: event.command_line }
      ]
    };
  }

  // --- Helper contextual checks ---

  private isKnownBenign(binary: MonitoredBinaryName | undefined, cmd: string, parent: string): boolean {
    if (!binary) return false;

    // Normal parent (explorer.exe or cmd.exe) with benign arguments
    const isNormalInteractiveParent = ['explorer.exe', 'cmd.exe', 'powershell.exe', 'windowsterminal.exe', 'code.exe', 'devenv.exe'].includes(parent);

    // cmd.exe benign: cmd /c echo, cmd /c dir, cmd /k vcvars
    if (binary === 'cmd.exe') {
      if ((cmd.includes('/c echo') || cmd.includes('/c dir') || cmd.includes('vcvars')) && 
          !cmd.includes('http://') && !cmd.includes('https://') && !cmd.includes('download') && !cmd.includes('-enc') && !cmd.includes('whoami')) {
        return true;
      }
    }

    // powershell.exe benign: Get-Date, Get-Process, Get-Service, Get-Command without enc, without hidden, without download
    if (binary === 'powershell.exe') {
      const benignCmdlets = ['get-date', 'get-process', 'get-service', 'get-command', 'get-item', 'write-host', 'get-help'];
      const hasBenignCmdlet = benignCmdlets.some(c => cmd.includes(c));
      const hasSuspiciousFlag = cmd.includes('-enc') || cmd.includes('-encodedcommand') || cmd.includes('-w hidden') || 
                                cmd.includes('downloadstring') || cmd.includes('downloadfile') || cmd.includes('invoke-webrequest') ||
                                cmd.includes('iwr ') || cmd.includes('net.webclient') || cmd.includes('bitstransfer') || cmd.includes('iex');
      if (hasBenignCmdlet && !hasSuspiciousFlag && isNormalInteractiveParent) {
        return true;
      }
    }

    // certutil.exe benign: -hashfile, -dump, -verifystore (without -urlcache, -split, -verifyctl)
    if (binary === 'certutil.exe') {
      if ((cmd.includes('-hashfile') || cmd.includes('-dump')) && !cmd.includes('-urlcache') && !cmd.includes('-split') && !cmd.includes('http')) {
        return true;
      }
    }

    // bitsadmin.exe benign: /list, /reset, /cancel (without /transfer, /download, /addfile)
    if (binary === 'bitsadmin.exe') {
      if ((cmd.includes('/list') || cmd.includes('/reset')) && !cmd.includes('/transfer') && !cmd.includes('/download') && !cmd.includes('/addfile')) {
        return true;
      }
    }

    // schtasks.exe benign: /query without /create or /change
    if (binary === 'schtasks.exe') {
      if (cmd.includes('/query') && !cmd.includes('/create') && !cmd.includes('/change') && !cmd.includes('/run')) {
        return true;
      }
    }

    // reg.exe benign: query without add, delete, import
    if (binary === 'reg.exe') {
      if (cmd.includes('query') && !cmd.includes('add') && !cmd.includes('delete') && !cmd.includes('import')) {
        return true;
      }
    }

    // wmic.exe benign: os get, bios get, cpu get without process call create or shadowcopy delete
    if (binary === 'wmic.exe') {
      if ((cmd.includes('os get') || cmd.includes('bios get') || cmd.includes('cpu get')) && !cmd.includes('process call create') && !cmd.includes('delete')) {
        return true;
      }
    }

    return false;
  }

  private isEncodedPowerShell(cmd: string): boolean {
    const encFlags = ['-enc', '-encodedcommand', '-encoded', '-e ', '-ec ', '-en '];
    return encFlags.some(flag => cmd.includes(flag));
  }

  private isSuspiciousDownload(binary: MonitoredBinaryName | undefined, cmd: string): boolean {
    if (binary === 'powershell.exe') {
      const psDownloads = ['downloadstring', 'downloadfile', 'invoke-webrequest', 'iwr ', 'start-bitstransfer', 'net.webclient'];
      return psDownloads.some(d => cmd.includes(d));
    }
    if (binary === 'certutil.exe') {
      return (cmd.includes('-urlcache') || cmd.includes('-split') || cmd.includes('-verifyctl') || cmd.includes('http://') || cmd.includes('https://'));
    }
    if (binary === 'bitsadmin.exe') {
      return (cmd.includes('/transfer') || cmd.includes('/download') || cmd.includes('/addfile'));
    }
    if (binary === 'mshta.exe') {
      return (cmd.includes('http://') || cmd.includes('https://') || cmd.includes('javascript:') || cmd.includes('vbscript:'));
    }
    if (binary === 'msiexec.exe') {
      return ((cmd.includes('/q /i') || cmd.includes('/quiet /i') || cmd.includes('/qn /i')) && (cmd.includes('http://') || cmd.includes('https://')));
    }
    if (binary === 'regsvr32.exe') {
      return ((cmd.includes('/s /u') || cmd.includes('/i:http')) && (cmd.includes('http://') || cmd.includes('https://') || cmd.includes('.sct')));
    }
    if (binary === 'rundll32.exe') {
      return (cmd.includes('javascript:') || cmd.includes('url.dll') || cmd.includes('scrobj.dll'));
    }
    if (binary === 'cmd.exe') {
      return ((cmd.includes('curl ') || cmd.includes('wget ')) && (cmd.includes('http://') || cmd.includes('https://')));
    }
    return false;
  }

  private isHiddenExecution(cmd: string): boolean {
    const hiddenFlags = ['-windowstyle hidden', '-w hidden', '-win hidden', '-w 1', '-win 1', 'vbhide', 'start /b'];
    return hiddenFlags.some(flag => cmd.includes(flag));
  }

  private isUnusualParent(parent: string): boolean {
    return this.config.anomalousSystemServices.some(svc => parent === svc || parent.endsWith('\\' + svc));
  }

  private isOfficeParent(parent: string): boolean {
    return this.config.monitoredOfficeParents.some(office => parent === office || parent.endsWith('\\' + office));
  }

  private isBrowserParent(parent: string): boolean {
    return this.config.monitoredBrowserParents.some(browser => parent === browser || parent.endsWith('\\' + browser));
  }

  private isPowerShellParent(parent: string): boolean {
    return parent === 'powershell.exe' || parent === 'pwsh.exe' || parent.endsWith('\\powershell.exe') || parent.endsWith('\\pwsh.exe');
  }

  private isTargetExecutable(procName: string): boolean {
    const exeExts = ['.exe', '.scr', '.com', '.bat', '.cmd', '.pif'];
    const isExe = exeExts.some(ext => procName.endsWith(ext)) || (!procName.includes('.') && procName.length > 0);
    return isExe && procName !== 'conhost.exe';
  }

  private isExecutionFromTemp(path: string, cmd: string): boolean {
    const combined = `${path} ${cmd}`;
    return this.config.monitoredTempDirectories.some(dir => combined.includes(dir));
  }
}

export const lolbinDetector = new LolbinContextualDetector();
