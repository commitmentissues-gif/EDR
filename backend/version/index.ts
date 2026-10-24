import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export interface VersionInfo {
  name: string;
  version: string;
  buildDate: string;
  apiVersion: string;
  architecture: string;
  targetOS: string;
  commit: string;
  components: Record<string, string>;
  capabilities: string[];
  runtime: {
    platform: string;
    nodeVersion: string;
    hostname: string;
    uptimeSeconds: number;
    arch: string;
  };
}

let cachedVersion: any = null;

export function getVersionInfo(): VersionInfo {
  if (!cachedVersion) {
    const versionPath = path.resolve(process.cwd(), 'config', 'version.json');
    if (fs.existsSync(versionPath)) {
      try {
        cachedVersion = JSON.parse(fs.readFileSync(versionPath, 'utf-8'));
      } catch {
        cachedVersion = { name: 'LocalEDR', version: '1.0.0-alpha.1' };
      }
    } else {
      cachedVersion = { name: 'LocalEDR', version: '1.0.0-alpha.1' };
    }
  }

  return {
    ...cachedVersion,
    runtime: {
      platform: os.platform(),
      nodeVersion: process.version,
      hostname: os.hostname(),
      uptimeSeconds: Math.floor(process.uptime()),
      arch: os.arch()
    }
  };
}
