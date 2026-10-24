import { getConfig } from '../config/index.js';
import { logger } from '../logger/index.js';

const log = logger.forComponent('EventQueue');

export interface QueueItem<T = any> {
  id: string;
  timestamp: string;
  data: T;
}

export class LocalEventQueue<T = any> {
  private queue: QueueItem<T>[] = [];
  private maxCapacity: number;
  private batchFlushSize: number;
  private flushIntervalMs: number;
  private flushTimer: NodeJS.Timeout | null = null;
  private processor: ((batch: QueueItem<T>[]) => Promise<void> | void) | null = null;
  private totalEnqueued: number = 0;
  private totalProcessed: number = 0;
  private totalDropped: number = 0;

  constructor() {
    const config = getConfig();
    this.maxCapacity = config.queue.maxCapacity || 10000;
    this.batchFlushSize = config.queue.batchFlushSize || 100;
    this.flushIntervalMs = config.queue.flushIntervalMs || 500;
  }

  setProcessor(processor: (batch: QueueItem<T>[]) => Promise<void> | void) {
    this.processor = processor;
    this.startFlushTimer();
  }

  enqueue(data: T): boolean {
    if (this.queue.length >= this.maxCapacity) {
      this.totalDropped++;
      log.warn(`Event queue capacity reached (${this.maxCapacity}). Dropping event to preserve system stability.`);
      return false;
    }

    const item: QueueItem<T> = {
      id: `Q-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toISOString(),
      data
    };

    this.queue.push(item);
    this.totalEnqueued++;

    if (this.queue.length >= this.batchFlushSize) {
      this.flushSync();
    }

    return true;
  }

  get length(): number {
    return this.queue.length;
  }

  getMetrics() {
    return {
      currentDepth: this.queue.length,
      maxCapacity: this.maxCapacity,
      totalEnqueued: this.totalEnqueued,
      totalProcessed: this.totalProcessed,
      totalDropped: this.totalDropped
    };
  }

  private startFlushTimer() {
    if (this.flushTimer) clearInterval(this.flushTimer);
    this.flushTimer = setInterval(() => {
      this.flushSync();
    }, this.flushIntervalMs);
  }

  private async flushSync() {
    if (this.queue.length === 0 || !this.processor) return;

    const batch = this.queue.splice(0, this.batchFlushSize);
    try {
      await this.processor(batch);
      this.totalProcessed += batch.length;
    } catch (err) {
      log.error('Error processing event queue batch:', err);
      // Re-queue items if needed or log error
    }
  }

  stop() {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }
}

export const eventQueue = new LocalEventQueue();
