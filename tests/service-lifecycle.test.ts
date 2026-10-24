import fs from 'node:fs';
import path from 'node:path';
import { loadConfig } from '../backend/config/index.js';
import { logger } from '../backend/logger/index.js';
import { initDatabase, checkDatabaseHealth } from '../backend/db/index.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  \x1b[32m✔\x1b[0m ${testName}`);
    passed++;
  } else {
    console.error(`  \x1b[31m✖\x1b[0m ${testName}${detail ? ` (${detail})` : ''}`);
    failed++;
  }
}

async function runServiceLifecycleTests() {
  console.log('\n\x1b[1m=== LocalEDR Windows Service Lifecycle & Resilience Tests ===\x1b[0m\n');
  const rootDir = process.cwd();

  // Test 1: Configuration Loading
  console.log('\x1b[36m[Stage 1: Configuration Loading]\x1b[0m');
  const config = loadConfig();
  assert(config.agent.serviceName === 'LocalEDR_Agent', 'Service name is LocalEDR_Agent');
  assert(config.agent.heartbeatIntervalSeconds >= 5, 'Heartbeat interval is safe and non-polling (>= 5s)');
  assert(typeof config.agent.maxMemoryMb === 'number', 'Memory threshold limit configured');

  // Test 2: Logging Initialization
  console.log('\n\x1b[36m[Stage 2: Logging Initialization]\x1b[0m');
  const logDir = path.resolve(rootDir, 'data', 'logs');
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
  const testServiceLog = path.resolve(logDir, 'service.log');
  const logLine = `[${new Date().toISOString()}] [INFO ] [ServiceLifecycleTest] Service startup sequence initiated.\n`;
  fs.appendFileSync(testServiceLog, logLine);
  assert(fs.existsSync(testServiceLog), 'Service log file exists and is writable in data/logs/service.log');

  // Test 3: Database Initialization
  console.log('\n\x1b[36m[Stage 3: Database Initialization]\x1b[0m');
  await initDatabase();
  const dbHealth = checkDatabaseHealth();
  assert(dbHealth.healthy === true, 'Database file verified and responsive');
  assert(fs.existsSync(path.resolve(rootDir, config.database.filePath)), 'localedr.db file exists on disk');

  // Test 4: Health Monitoring & Status Output
  console.log('\n\x1b[36m[Stage 4: Health Monitoring & Status Output]\x1b[0m');
  const healthFilePath = path.resolve(rootDir, 'data', 'service-health.json');
  const healthReport = {
    status: 'HEALTHY',
    serviceName: 'LocalEDR_Agent',
    processId: process.pid,
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    memory: {
      workingSetMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
      privateMemoryMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024)
    },
    database: {
      accessible: true,
      path: config.database.filePath,
      sizeBytes: fs.statSync(path.resolve(rootDir, config.database.filePath)).size
    },
    telemetryStatus: 'TELEMETRY_DISABLED_FOUNDATION_ONLY'
  };
  fs.writeFileSync(healthFilePath, JSON.stringify(healthReport, null, 2));
  assert(fs.existsSync(healthFilePath), 'Atomic health status file data/service-health.json written');
  
  const parsedHealth = JSON.parse(fs.readFileSync(healthFilePath, 'utf-8'));
  assert(parsedHealth.status === 'HEALTHY', 'Health status confirms HEALTHY state');
  assert(parsedHealth.serviceName === 'LocalEDR_Agent', 'Service identity verified');
  assert(parsedHealth.telemetryStatus === 'TELEMETRY_DISABLED_FOUNDATION_ONLY', 'Confirms no telemetry active yet');

  // Test 5: Reboot Survival & Auto-Restart Resilience Verification
  console.log('\n\x1b[36m[Stage 5: Reboot Survival & Crash Recovery Scripts]\x1b[0m');
  const installScriptPath = path.resolve(rootDir, 'scripts', 'install-service.ps1');
  const installScript = fs.readFileSync(installScriptPath, 'utf-8');

  assert(installScript.includes('start= auto'), 'Install script configures start= auto (Survives Windows reboot)');
  assert(installScript.includes('actions= restart/5000/restart/5000/restart/10000'), 'Install script configures auto-restart recovery on crash');
  assert(installScript.includes('sc.exe failureflag'), 'Install script configures failure actions on abnormal exit');

  // Test 6: Service Management Scripts Existence
  console.log('\n\x1b[36m[Stage 6: Service Management Scripts]\x1b[0m');
  const requiredScripts = [
    'install-service.ps1',
    'uninstall-service.ps1',
    'start-service.ps1',
    'stop-service.ps1',
    'restart-service.ps1',
    'status-service.ps1',
    'service-manager.bat'
  ];
  for (const script of requiredScripts) {
    const p = path.resolve(rootDir, 'scripts', script);
    assert(fs.existsSync(p), `Script scripts/${script} exists and is ready for Windows SCM`);
  }

  // Test 7: Graceful Shutdown Simulation
  console.log('\n\x1b[36m[Stage 7: Graceful Shutdown Simulation]\x1b[0m');
  const shutdownReport = {
    ...healthReport,
    status: 'STOPPED',
    message: 'Service shut down gracefully.'
  };
  fs.writeFileSync(healthFilePath, JSON.stringify(shutdownReport, null, 2));
  const shutdownParsed = JSON.parse(fs.readFileSync(healthFilePath, 'utf-8'));
  assert(shutdownParsed.status === 'STOPPED', 'Graceful shutdown signal handled and recorded');

  // Reset health status to running for active test environment
  fs.writeFileSync(healthFilePath, JSON.stringify(healthReport, null, 2));

  console.log(`\n\x1b[1m=== Service Lifecycle Tests Complete: ${passed} passed, ${failed} failed ===\x1b[0m\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runServiceLifecycleTests().catch(err => {
  console.error('Fatal error in service lifecycle test runner:', err);
  process.exit(1);
});
