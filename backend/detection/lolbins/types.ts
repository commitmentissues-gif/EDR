export type MonitoredBinaryName = 
  | 'powershell.exe'
  | 'cmd.exe'
  | 'rundll32.exe'
  | 'regsvr32.exe'
  | 'mshta.exe'
  | 'certutil.exe'
  | 'bitsadmin.exe'
  | 'wmic.exe'
  | 'cscript.exe'
  | 'wscript.exe'
  | 'msiexec.exe'
  | 'schtasks.exe'
  | 'reg.exe';

export type ContextualBehaviorType =
  | 'encoded_powershell'
  | 'suspicious_download'
  | 'hidden_execution'
  | 'unusual_parent'
  | 'office_to_powershell'
  | 'browser_to_powershell'
  | 'powershell_to_lolbin'
  | 'lolbin_to_executable'
  | 'temp_location_execution';

export interface LolbinMitreMapping {
  tactic: string;
  technique_id: string;
  technique_name: string;
  subtechnique_id?: string;
  subtechnique_name?: string;
}

export interface MonitoredBinaryMeta {
  name: MonitoredBinaryName;
  displayName: string;
  category: 'Script Host' | 'Command Interpreter' | 'System Utility' | 'Installer' | 'Task Manager';
  description: string;
  defaultEnabled: boolean;
  mitreTechniques: string[];
  legitimateUse: string;
  commonAbuse: string;
  suspiciousKeywords: string[];
  benignExamples: string[];
  riskWeight: number; // 1-100
  enabled: boolean;
  totalDetections: number;
}

export interface ContextualBehaviorDefinition {
  id: ContextualBehaviorType;
  name: string;
  description: string;
  primaryMitre: LolbinMitreMapping;
  secondaryMitre?: LolbinMitreMapping;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  baseScore: number;
  indicators: string[];
  benignExclusions: string[];
  enabled: boolean;
}

export interface LolbinGlobalConfig {
  contextualDetectionEnabled: boolean;
  suppressBenignAdministrativeCommands: boolean;
  strictLineageVerification: boolean;
  monitoredTempDirectories: string[];
  monitoredOfficeParents: string[];
  monitoredBrowserParents: string[];
  anomalousSystemServices: string[];
  minimumDetectionScore: number;
  lastUpdated: string;
}

export interface LolbinDetectionResult {
  isLolbinEvent: boolean;
  monitoredBinary?: MonitoredBinaryName;
  isSuspicious: boolean;
  isBenignMatch: boolean;
  behaviorsDetected: ContextualBehaviorType[];
  behaviorDetails: Array<{
    type: ContextualBehaviorType;
    name: string;
    description: string;
    evidence: string;
    score: number;
    mitre: LolbinMitreMapping;
  }>;
  totalScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  summary: string;
  recommendation: string;
  processLineage: Array<{
    role: 'parent' | 'target' | 'child';
    name: string;
    pid: number;
    commandLine?: string;
  }>;
}

export interface SafeSimulationScenario {
  id: string;
  name: string;
  category: 'benign_safe' | 'contextual_detection';
  targetBinary: MonitoredBinaryName;
  expectedAlert: boolean;
  behavior?: ContextualBehaviorType;
  mitre?: string;
  description: string;
  commandLine: string;
  parentProcess: string;
  imagePath: string;
  explanation: string;
}
