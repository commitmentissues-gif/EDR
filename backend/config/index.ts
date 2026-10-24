import fs from 'node:fs';
import path from 'node:path';

export interface LocalEDRConfig {
  server: {
    host: string;
    port: number;
    corsAllowedOrigins: string[];
    adminToken: string;
  };
  agent: {
    serviceName: string;
    displayName: string;
    heartbeatIntervalSeconds: number;
    maxMemoryMb: number;
    maxCpuPercent: number;
  };
  database: {
    filePath: string;
    walMode: boolean;
    autoSaveIntervalMs: number;
    maxEventRetentionDays: number;
  };
  queue: {
    maxCapacity: number;
    batchFlushSize: number;
    flushIntervalMs: number;
  };
  logging: {
    level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'AUDIT';
    logToFile: boolean;
    logFilePath: string;
    format: 'json' | 'pretty';
  };
}

let activeConfig: LocalEDRConfig | null = null;

export function loadConfig(customPath?: string): LocalEDRConfig {
  const rootDir = process.cwd();
  const defaultConfigPath = path.resolve(rootDir, 'config', 'localedr.default.json');
  const userConfigPath = customPath || path.resolve(rootDir, 'config', 'localedr.json');

  let configData: any = {};

  // 1. Load default configuration
  if (fs.existsSync(defaultConfigPath)) {
    try {
      configData = JSON.parse(fs.readFileSync(defaultConfigPath, 'utf-8'));
    } catch (err) {
      console.error(`[Config] Failed to parse default config at ${defaultConfigPath}:`, err);
    }
  }

  // 2. Merge user override if present
  if (fs.existsSync(userConfigPath)) {
    try {
      const userConfig = JSON.parse(fs.readFileSync(userConfigPath, 'utf-8'));
      configData = deepMerge(configData, userConfig);
    } catch (err) {
      console.warn(`[Config] Failed to parse user config at ${userConfigPath}:`, err);
    }
  }

  // 3. Environment Variable Overrides
  if (process.env.LOCALEDR_HOST) configData.server.host = process.env.LOCALEDR_HOST;
  if (process.env.LOCALEDR_PORT) {
    configData.server.port = parseInt(process.env.LOCALEDR_PORT, 10);
  } else if (process.env.NODE_ENV === 'production' && process.env.PORT) {
    configData.server.port = parseInt(process.env.PORT, 10);
  } else {
    configData.server.port = 3000;
  }
  if (process.env.LOCALEDR_ADMIN_TOKEN) configData.server.adminToken = process.env.LOCALEDR_ADMIN_TOKEN;
  if (process.env.LOCALEDR_DB_PATH) configData.database.filePath = process.env.LOCALEDR_DB_PATH;
  if (process.env.LOCALEDR_LOG_LEVEL) configData.logging.level = process.env.LOCALEDR_LOG_LEVEL.toUpperCase();

  // 4. Validate essential fields
  validateConfig(configData);

  activeConfig = configData as LocalEDRConfig;
  return activeConfig;
}

export function getConfig(): LocalEDRConfig {
  if (!activeConfig) {
    return loadConfig();
  }
  return activeConfig;
}

function validateConfig(config: any) {
  if (!config.server || typeof config.server.port !== 'number') {
    throw new Error('Config Validation Error: server.port must be a valid number');
  }
  if (!config.database || typeof config.database.filePath !== 'string') {
    throw new Error('Config Validation Error: database.filePath must be a string');
  }
  const validLevels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'AUDIT'];
  if (!validLevels.includes(config.logging?.level)) {
    config.logging.level = 'INFO';
  }
}

function deepMerge(target: any, source: any): any {
  const output = { ...target };
  if (isObject(target) && isObject(source)) {
    Object.keys(source).forEach(key => {
      if (isObject(source[key])) {
        if (!(key in target)) {
          Object.assign(output, { [key]: source[key] });
        } else {
          output[key] = deepMerge(target[key], source[key]);
        }
      } else {
        Object.assign(output, { [key]: source[key] });
      }
    });
  }
  return output;
}

function isObject(item: any): boolean {
  return item && typeof item === 'object' && !Array.isArray(item);
}
