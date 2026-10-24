export type FileActionType = 'create' | 'modify' | 'delete' | 'rename';

export type FileCategoryType = 
  | 'executable' // .exe, .scr, .com, .pif
  | 'dll'        // .dll, .ocx, .cpl
  | 'script'     // .ps1, .bat, .cmd, .vbs, .js, .wsf, .hta, .sh, .py
  | 'document'   // .docx, .xlsx, .pdf, .txt, .rtf
  | 'archive'    // .zip, .rar, .7z, .tar, .gz, .iso
  | 'system'     // .sys, .inf, .drv, .cat
  | 'other';

export type SecurityLocationType = 
  | 'startup'      // Startup folders & Run persistence
  | 'temp'         // Temporary staging directories
  | 'downloads'    // Web/Email downloads folder
  | 'system32'     // Windows System32 & SysWOW64
  | 'windows'      // Windows base & driver directories
  | 'persistence'  // Tasks, Wbem, Spool, GroupPolicy
  | 'custom';

export type HashCalculationReason = 
  | 'executed'
  | 'suspicious'
  | 'alert_correlation'
  | 'manual_scan'
  | 'persistence_location'
  | 'threat_intel_match';

export interface FileEvent {
  id?: number;
  event_uuid: string;
  timestamp: string;
  action: FileActionType;
  file_path: string;
  old_file_path?: string; // Present on rename
  file_name: string;
  file_extension: string;
  file_size_bytes?: number;
  file_category: FileCategoryType;
  security_location: SecurityLocationType;
  file_hash?: string; // SHA-256 (calculated selectively only!)
  hash_calculated: boolean;
  hash_calculation_reason?: HashCalculationReason | string;
  pid?: number;
  process_name?: string;
  process_path?: string;
  is_suspicious: boolean;
  detection_tags: string[]; // e.g. ['STARTUP_PERSISTENCE', 'TEMP_EXECUTABLE_DROP', 'DOUBLE_EXTENSION_MASQUERADE']
  risk_score: number; // 0-100
  detection_reasons?: string[];
  created_at: string;
}

export interface SecurityLocationDef {
  id: string;
  name: string;
  type: SecurityLocationType;
  description: string;
  patterns: string[];
  riskWeight: number;
}

export interface FileFilterOptions {
  search?: string;
  action?: FileActionType | 'all';
  category?: FileCategoryType | 'all';
  location?: SecurityLocationType | 'all';
  is_suspicious?: boolean;
  has_hash?: boolean;
  pid?: number;
  process_name?: string;
  limit?: number;
  offset?: number;
}

export interface FileAggregatedStats {
  totalEvents: number;
  createsCount: number;
  modifiesCount: number;
  deletesCount: number;
  renamesCount: number;
  executablesCreatedCount: number;
  dllsCreatedCount: number;
  scriptsCreatedCount: number;
  suspiciousCount: number;
  hashesCalculatedCount: number;
  topSecurityLocations: Array<{ location: SecurityLocationType; name: string; count: number; suspiciousCount: number }>;
  topActiveProcesses: Array<{ process_name: string; pid: number; fileOpsCount: number; isSuspicious: boolean }>;
  recentDetections: FileEvent[];
}

export interface FileMonitorConfig {
  enabled: boolean;
  watchStartupFolders: boolean;
  watchTempDirectories: boolean;
  watchDownloads: boolean;
  watchSystem32: boolean;
  watchPersistenceLocations: boolean;
  selectiveHashing: {
    hashExecutedFiles: boolean;
    hashSuspiciousFiles: boolean;
    hashAlertCorrelatedFiles: boolean;
    hashManualScans: boolean;
    maxFileSizeBytes: number; // Skip files > e.g. 100MB
  };
  dedupDebounceMs: number;
}

export interface SafeFileSimulationScenario {
  id: string;
  name: string;
  category: 'benign_file' | 'malicious_file_detection';
  description: string;
  expectedAlert: boolean;
  action: FileActionType;
  file_path: string;
  old_file_path?: string;
  process_name: string;
  pid: number;
  explanation: string;
}

export interface IncidentTimelineItem {
  id: string;
  timestamp: string;
  type: 'ALERT' | 'FILE' | 'PROCESS' | 'NETWORK';
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  process_name?: string;
  pid?: number;
  file_path?: string;
  file_action?: FileActionType;
  file_hash?: string;
  destination_ip?: string;
  destination_port?: number;
  mitre_technique_id?: string;
  tags?: string[];
}
