export type MonitoredLolbinName =
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

export type LolbinBehaviorCategory =
  | 'encoded_powershell'
  | 'suspicious_download'
  | 'hidden_execution'
  | 'unusual_parent'
  | 'office_to_powershell'
  | 'browser_to_powershell'
  | 'powershell_to_lolbin'
  | 'lolbin_to_executable'
  | 'temp_location_execution';

export interface LolbinProfile {
  binary: MonitoredLolbinName;
  name: string;
  category: 'Scripting / Shell' | 'Execution Proxy' | 'Utility / Transfer' | 'System Management';
  standardPath: string;
  description: string;
  primaryMitre: {
    tactic: string;
    technique_id: string;
    technique_name: string;
    subtechnique_id?: string;
    subtechnique_name?: string;
  };
  benignExamples: string[];
  suspiciousIndicators: string[];
  monitoredParents: string[];
}

export interface LolbinRuleConfig {
  id: string;
  name: string;
  behavior: LolbinBehaviorCategory;
  targetBinaries: MonitoredLolbinName[];
  enabled: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  score: number;
  mitre: {
    tactic: string;
    technique_id: string;
    technique_name: string;
    subtechnique_id?: string;
    subtechnique_name?: string;
  };
  description: string;
  recommendedAction: string;
  customWhitelistPatterns?: string[];
}

export interface LolbinEvaluationResult {
  matched: boolean;
  ruleId?: string;
  ruleName?: string;
  behavior?: LolbinBehaviorCategory;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  score?: number;
  mitre?: {
    tactic: string;
    technique_id: string;
    technique_name: string;
    subtechnique_id?: string;
    subtechnique_name?: string;
  };
  matchedCriteria: string[];
  evidence: Record<string, any>;
  isBenign: boolean;
  benignReason?: string;
  whyTriggered?: string;
  recommendedAction?: string;
}
