import path from 'path';
import { SecurityLocationType, FileCategoryType, SecurityLocationDef } from './types.js';

export const SECURITY_LOCATIONS: SecurityLocationDef[] = [
  {
    id: 'loc-startup',
    name: 'Startup Folders (Autorun Persistence)',
    type: 'startup',
    description: 'Files dropped into Start Menu Startup directories execute automatically upon user login.',
    patterns: [
      'start menu\\programs\\startup',
      'start menu/programs/startup',
      'appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup',
      'programdata\\microsoft\\windows\\start menu\\programs\\startup',
      'autostart',
      '/startup'
    ],
    riskWeight: 90
  },
  {
    id: 'loc-temp',
    name: 'Temporary Directories (Staging & Execution)',
    type: 'temp',
    description: 'User and system temporary directories frequently abused by droppers and malware stages.',
    patterns: [
      'appdata\\local\\temp',
      'appdata/local/temp',
      'windows\\temp',
      'windows/temp',
      '/tmp',
      '/var/tmp'
    ],
    riskWeight: 75
  },
  {
    id: 'loc-downloads',
    name: 'User Downloads (Ingress Staging)',
    type: 'downloads',
    description: 'Default target for browser and email web downloads and initial ingress file creation.',
    patterns: [
      '\\downloads',
      '/downloads',
      'user\\downloads'
    ],
    riskWeight: 65
  },
  {
    id: 'loc-system32',
    name: 'Windows System32 & Drivers (System Integrity)',
    type: 'system32',
    description: 'Core Windows operating system binaries, DLLs, and kernel-mode drivers.',
    patterns: [
      'windows\\system32',
      'windows/system32',
      'windows\\syswow64',
      'windows/syswow64',
      'system32\\drivers',
      'system32/drivers'
    ],
    riskWeight: 95
  },
  {
    id: 'loc-persistence',
    name: 'Persistence Infrastructure (Tasks & WMI)',
    type: 'persistence',
    description: 'Scheduled task definitions, WMI repositories, and print processor persistence paths.',
    patterns: [
      'system32\\tasks',
      'system32/tasks',
      'system32\\wbem',
      'system32/wbem',
      'system32\\spool\\prtprocs',
      'grouppolicy\\machine\\scripts',
      'grouppolicy\\user\\scripts'
    ],
    riskWeight: 85
  }
];

const EXECUTABLE_EXTENSIONS = new Set(['.exe', '.scr', '.com', '.pif']);
const DLL_EXTENSIONS = new Set(['.dll', '.ocx', '.cpl']);
const SCRIPT_EXTENSIONS = new Set(['.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.py', '.sh']);
const DOCUMENT_EXTENSIONS = new Set(['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.txt', '.rtf', '.csv']);
const ARCHIVE_EXTENSIONS = new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.cab', '.img']);
const SYSTEM_EXTENSIONS = new Set(['.sys', '.inf', '.drv', '.cat']);

/**
 * Classifies file category based on extension
 */
export function classifyFileCategory(fileNameOrPath: string): FileCategoryType {
  const ext = path.extname(fileNameOrPath).toLowerCase();
  if (EXECUTABLE_EXTENSIONS.has(ext)) return 'executable';
  if (DLL_EXTENSIONS.has(ext)) return 'dll';
  if (SCRIPT_EXTENSIONS.has(ext)) return 'script';
  if (DOCUMENT_EXTENSIONS.has(ext)) return 'document';
  if (ARCHIVE_EXTENSIONS.has(ext)) return 'archive';
  if (SYSTEM_EXTENSIONS.has(ext)) return 'system';
  return 'other';
}

/**
 * Classifies security location based on file path
 */
export function classifyLocation(filePath: string): SecurityLocationType {
  if (!filePath) return 'custom';
  const normalized = filePath.toLowerCase().replace(/\//g, '\\');

  if (
    normalized.includes('start menu\\programs\\startup') || 
    normalized.includes('autostart')
  ) {
    return 'startup';
  }

  if (
    normalized.includes('\\system32\\tasks') ||
    normalized.includes('\\system32\\wbem') ||
    normalized.includes('\\system32\\spool\\prtprocs') ||
    normalized.includes('\\grouppolicy\\')
  ) {
    return 'persistence';
  }

  if (
    normalized.includes('windows\\system32') ||
    normalized.includes('windows\\syswow64')
  ) {
    return 'system32';
  }

  if (
    normalized.includes('appdata\\local\\temp') ||
    normalized.includes('windows\\temp') ||
    normalized.startsWith('/tmp') ||
    normalized.startsWith('/var/tmp')
  ) {
    return 'temp';
  }

  if (normalized.includes('\\downloads')) {
    return 'downloads';
  }

  if (normalized.includes('c:\\windows') || normalized.startsWith('/windows')) {
    return 'windows';
  }

  return 'custom';
}

/**
 * Checks for deceptive double extensions (e.g. invoice.pdf.exe, report.docx.vbs)
 */
export function isDoubleExtension(fileName: string): boolean {
  if (!fileName) return false;
  const parts = fileName.toLowerCase().split('.');
  if (parts.length < 3) return false;

  const lastExt = '.' + parts[parts.length - 1];
  const secondLastExt = '.' + parts[parts.length - 2];

  // If the last extension is an executable or script, and the previous one looks like a benign document or image
  const isTargetExecutable = EXECUTABLE_EXTENSIONS.has(lastExt) || SCRIPT_EXTENSIONS.has(lastExt);
  const isDecoyDocument = DOCUMENT_EXTENSIONS.has(secondLastExt) || ['.jpg', '.png', '.gif', '.mp3', '.mp4'].includes(secondLastExt);

  return isTargetExecutable && isDecoyDocument;
}

export function isExecutableExtension(ext: string): boolean {
  return EXECUTABLE_EXTENSIONS.has(ext.toLowerCase());
}

export function isDllExtension(ext: string): boolean {
  return DLL_EXTENSIONS.has(ext.toLowerCase());
}

export function isScriptExtension(ext: string): boolean {
  return SCRIPT_EXTENSIONS.has(ext.toLowerCase());
}
