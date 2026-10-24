import fs from 'node:fs';
import path from 'node:path';
import { getConfig } from '../config/index.js';

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'AUDIT';

const LEVEL_SEVERITY: Record<LogLevel, number> = {
  DEBUG: 10,
  INFO: 20,
  WARN: 30,
  ERROR: 40,
  AUDIT: 50
};

export class Logger {
  private component: string;
  private logFilePath: string | null = null;

  constructor(component: string = 'Core') {
    this.component = component;
    this.ensureLogDir();
  }

  private ensureLogDir() {
    try {
      const config = getConfig();
      if (config.logging.logToFile) {
        this.logFilePath = path.resolve(process.cwd(), config.logging.logFilePath);
        const dir = path.dirname(this.logFilePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
      }
    } catch {
      // Fallback if config is not ready yet
      this.logFilePath = null;
    }
  }

  private shouldLog(level: LogLevel): boolean {
    try {
      const config = getConfig();
      const currentSeverity = LEVEL_SEVERITY[config.logging.level] || 20;
      return LEVEL_SEVERITY[level] >= currentSeverity;
    } catch {
      return true;
    }
  }

  private write(level: LogLevel, message: string, context?: any) {
    if (!this.shouldLog(level)) return;

    const timestamp = new Date().toISOString();
    const entry = {
      timestamp,
      level,
      component: this.component,
      message,
      ...(context ? { context } : {})
    };

    let formatted = '';
    const config = getConfig();
    if (config.logging.format === 'json') {
      formatted = JSON.stringify(entry);
    } else {
      const ctxStr = context ? ` | ${JSON.stringify(context)}` : '';
      formatted = `[${timestamp}] [${level.padEnd(5)}] [${this.component}] ${message}${ctxStr}`;
    }

    // Output to stdout / stderr
    if (level === 'ERROR') {
      console.error(formatted);
    } else if (level === 'WARN') {
      console.warn(formatted);
    } else {
      console.log(formatted);
    }

    // Output to log file
    if (this.logFilePath) {
      try {
        fs.appendFileSync(this.logFilePath, formatted + '\n');
      } catch {
        // Suppress disk write failure in log handler to avoid loops
      }
    }
  }

  debug(message: string, context?: any) {
    this.write('DEBUG', message, context);
  }

  info(message: string, context?: any) {
    this.write('INFO', message, context);
  }

  warn(message: string, context?: any) {
    this.write('WARN', message, context);
  }

  error(message: string, context?: any) {
    this.write('ERROR', message, context);
  }

  audit(action: string, actor: string, details?: any) {
    this.write('AUDIT', `ACTION=${action} ACTOR=${actor}`, details);
  }

  forComponent(subComponent: string): Logger {
    return new Logger(`${this.component}:${subComponent}`);
  }
}

export const logger = new Logger('LocalEDR');
