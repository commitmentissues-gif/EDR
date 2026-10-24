import { 
  FileEvent, 
  FileActionType, 
  FileCategoryType, 
  SecurityLocationType 
} from './types.js';
import { isDoubleExtension } from './locations.js';
import { query } from '../db/index.js';

export interface FileDetectionResult {
  isSuspicious: boolean;
  riskScore: number;
  tags: string[];
  reasons: string[];
  mitreTechniques: Array<{ tactic: string; technique_id: string; technique_name: string }>;
}

export class FileDetector {
  /**
   * Analyzes file event for suspicious activity
   */
  analyzeFileEvent(event: {
    action: FileActionType;
    file_path: string;
    old_file_path?: string;
    file_name: string;
    file_extension: string;
    file_category: FileCategoryType;
    security_location: SecurityLocationType;
    file_hash?: string;
    process_name?: string;
  }): FileDetectionResult {
    const tags: string[] = [];
    const reasons: string[] = [];
    const mitreTechniques: Array<{ tactic: string; technique_id: string; technique_name: string }> = [];
    let riskScore = 0;

    const procName = (event.process_name || '').toLowerCase();
    const fileName = event.file_name.toLowerCase();
    const filePath = event.file_path.toLowerCase();
    const action = event.action;
    const category = event.file_category;
    const location = event.security_location;

    // 1. Startup Folder Persistence
    if (location === 'startup' && (action === 'create' || action === 'modify' || action === 'rename')) {
      if (category === 'executable' || category === 'script' || category === 'dll' || category === 'other') {
        tags.push('STARTUP_PERSISTENCE');
        reasons.push(`Executable, script, or shortcut dropped into Startup autorun folder: '${event.file_path}'`);
        riskScore = Math.max(riskScore, 90);
        mitreTechniques.push({
          tactic: 'Persistence',
          technique_id: 'T1547.001',
          technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
        });
      }
    }

    // 2. Executable / DLL Drop in Temporary Directory
    if (location === 'temp' && (action === 'create' || action === 'rename')) {
      if (category === 'executable' || category === 'dll') {
        tags.push('TEMP_EXECUTABLE_DROP');
        reasons.push(`Binary executable or DLL staged in temporary directory: '${event.file_path}'`);
        riskScore = Math.max(riskScore, 75);
        mitreTechniques.push({
          tactic: 'Defense Evasion',
          technique_id: 'T1027',
          technique_name: 'Obfuscated Files or Information'
        });
      } else if (category === 'script') {
        tags.push('TEMP_SCRIPT_DROP');
        reasons.push(`Script file written to temporary directory: '${event.file_path}'`);
        riskScore = Math.max(riskScore, 65);
        mitreTechniques.push({
          tactic: 'Execution',
          technique_id: 'T1059',
          technique_name: 'Command and Scripting Interpreter'
        });
      }
    }

    // 3. Double Extension Masquerade (e.g. invoice.pdf.exe)
    if (isDoubleExtension(event.file_name)) {
      tags.push('DOUBLE_EXTENSION_MASQUERADE');
      reasons.push(`Deceptive double file extension detected: '${event.file_name}' disguises executable payload as a document`);
      riskScore = Math.max(riskScore, 85);
      mitreTechniques.push({
        tactic: 'Defense Evasion',
        technique_id: 'T1036.007',
        technique_name: 'Masquerading: Double File Extension'
      });
    }

    // 4. Windows System32 / Drivers Modification
    if (location === 'system32' && (action === 'create' || action === 'modify' || action === 'rename')) {
      if (category === 'dll' || category === 'executable' || category === 'system') {
        // Exclude legitimate Windows Update or TrustedInstaller processes if known
        if (procName !== 'trustedinstaller.exe' && procName !== 'tiworker.exe') {
          tags.push('SYSTEM32_MODIFICATION');
          reasons.push(`System integrity alert: Unverified binary or DLL dropped in Windows System directory: '${event.file_path}'`);
          riskScore = Math.max(riskScore, 90);
          mitreTechniques.push({
            tactic: 'Defense Evasion',
            technique_id: 'T1574',
            technique_name: 'Hijack Execution Flow'
          });
        }
      }
    }

    // 5. Common Persistence Locations (Tasks, Wbem, Spool)
    if (location === 'persistence' && (action === 'create' || action === 'modify')) {
      tags.push('PERSISTENCE_LOCATION_MODIFICATION');
      reasons.push(`File activity in Windows persistence infrastructure: '${event.file_path}'`);
      riskScore = Math.max(riskScore, 80);
      mitreTechniques.push({
        tactic: 'Persistence',
        technique_id: 'T1053.005',
        technique_name: 'Scheduled Task/Job: Scheduled Task'
      });
    }

    // 6. Office or Browser Writing Executable / Script
    const dropperParents = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'chrome.exe', 'msedge.exe'];
    if (dropperParents.includes(procName) && (category === 'executable' || category === 'script' || category === 'dll')) {
      tags.push('OFFICE_BROWSER_DROPPER');
      reasons.push(`Office/Browser process '${procName}' dropped executable or script: '${event.file_path}'`);
      riskScore = Math.max(riskScore, 85);
      mitreTechniques.push({
        tactic: 'Execution',
        technique_id: 'T1204.002',
        technique_name: 'User Execution: Malicious File'
      });
    }

    // 7. Threat Intel Known Malicious Hash Match
    if (event.file_hash) {
      try {
        const matches = query<{ value: string; threat_actor: string; description: string }>(
          'SELECT value, threat_actor, description FROM threat_intel WHERE value = ? AND type = "sha256" LIMIT 1',
          [event.file_hash]
        );
        if (matches && matches.length > 0) {
          tags.push('KNOWN_MALICIOUS_HASH');
          reasons.push(`File hash '${event.file_hash}' matches threat intelligence IoC (${matches[0].threat_actor}: ${matches[0].description})`);
          riskScore = 100;
          mitreTechniques.push({
            tactic: 'Execution',
            technique_id: 'T1204.002',
            technique_name: 'User Execution: Malicious File'
          });
        }
      } catch {
        // Ignore DB transient
      }
    }

    const isSuspicious = tags.length > 0;

    return {
      isSuspicious,
      riskScore: Math.min(100, riskScore),
      tags: Array.from(new Set(tags)),
      reasons,
      mitreTechniques
    };
  }
}

export const fileDetector = new FileDetector();
