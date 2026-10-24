import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { checkDatabaseHealth } from '../db/index.js';
import { getConfig } from '../config/index.js';
import { getVersionInfo } from '../version/index.js';

export interface HealthCheckResult {
  status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';
  timestamp: string;
  uptimeSeconds: number;
  version: string;
  subsystems: {
    database: {
      status: 'UP' | 'DOWN';
      latencyMs: number;
      fileSizeBytes: number;
      error?: string;
    };
    memory: {
      status: 'UP' | 'WARNING' | 'CRITICAL';
      rssMb: number;
      heapUsedMb: number;
      maxLimitMb: number;
    };
    system: {
      platform: string;
      arch: string;
      loadAvg: number[];
      freeMemMb: number;
    };
    eventQueue: {
      status: 'UP' | 'DEGRADED';
      queuedEvents: number;
      capacity: number;
    };
  };
}

export function performHealthCheck(queueCount: number = 0): HealthCheckResult {
  const config = getConfig();
  const version = getVersionInfo();
  const dbHealth = checkDatabaseHealth();
  const memUsage = process.memoryUsage();

  const rssMb = +(memUsage.rss / 1024 / 1024).toFixed(1);
  const heapUsedMb = +(memUsage.heapUsed / 1024 / 1024).toFixed(1);
  const maxMemMb = config.agent.maxMemoryMb || 150;

  // Evaluate memory status based on Node heap usage and process RSS
  // In development mode with Vite middleware, RSS includes the Vite compiler and esbuild
  let memoryStatus: 'UP' | 'WARNING' | 'CRITICAL' = 'UP';
  if (heapUsedMb > 120 || rssMb > maxMemMb * 1.5) {
    memoryStatus = 'CRITICAL';
  } else if (heapUsedMb > 90 || rssMb > maxMemMb) {
    memoryStatus = 'WARNING';
  }

  // Get DB file size
  let dbSizeBytes = 0;
  const dbPath = path.resolve(process.cwd(), config.database.filePath);
  if (fs.existsSync(dbPath)) {
    try {
      dbSizeBytes = fs.statSync(dbPath).size;
    } catch {
      dbSizeBytes = 0;
    }
  }

  // Overall status evaluation
  let overallStatus: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY' = 'HEALTHY';
  if (!dbHealth.healthy) {
    overallStatus = 'UNHEALTHY';
  } else if (memoryStatus === 'CRITICAL' || queueCount > (config.queue.maxCapacity * 0.9)) {
    overallStatus = 'DEGRADED';
  }

  return {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    version: version.version,
    subsystems: {
      database: {
        status: dbHealth.healthy ? 'UP' : 'DOWN',
        latencyMs: dbHealth.latencyMs,
        fileSizeBytes: dbSizeBytes,
        ...(dbHealth.error ? { error: dbHealth.error } : {})
      },
      memory: {
        status: memoryStatus,
        rssMb,
        heapUsedMb,
        maxLimitMb: maxMemMb
      },
      system: {
        platform: os.platform(),
        arch: os.arch(),
        loadAvg: os.loadavg(),
        freeMemMb: +(os.freemem() / 1024 / 1024).toFixed(0)
      },
      eventQueue: {
        status: queueCount < config.queue.maxCapacity ? 'UP' : 'DEGRADED',
        queuedEvents: queueCount,
        capacity: config.queue.maxCapacity
      }
    }
  };
}
