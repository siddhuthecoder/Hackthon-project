import { EventEmitter } from 'node:events';

export type BusTopic = 'event' | 'detection' | 'incident' | 'finding' | 'scan' | 'verification' | 'simulation' | 'response' | 'agent';

export interface BusMessage {
  topic: BusTopic;
  at: string;
  data: unknown;
}

const emitter = new EventEmitter();
emitter.setMaxListeners(200);

export function publish(topic: BusTopic, data: unknown): void {
  const message: BusMessage = { topic, at: new Date().toISOString(), data };
  emitter.emit('message', message);
}

export function subscribe(listener: (message: BusMessage) => void): () => void {
  emitter.on('message', listener);
  return () => emitter.off('message', listener);
}
