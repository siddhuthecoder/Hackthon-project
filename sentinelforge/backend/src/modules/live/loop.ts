import { config } from '../../config';
import { Application } from '../../db/models';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { runDetection } from '../detection/service';
import { ingestEvents } from '../events/ingest';

let timer: NodeJS.Timeout | undefined;

export function startLiveLoop(): void {
  if (timer) return;
  timer = setInterval(tick, config.cyberlab.pollMs);
}

export function stopLiveLoop(): void {
  if (timer) clearInterval(timer);
  timer = undefined;
}

async function tick(): Promise<void> {
  try {
    const apps = await Application.find({ adapter: 'cyberlab', status: { $ne: 'REGISTERED' } });
    for (const app of apps) {
      const lab = new CyberLabAdapter(app.baseUrl);
      await ingestEvents(app.id, lab);
      await runDetection(app.id);
    }
  } catch {
    // Transient failures (CyberLab briefly unreachable) are expected during a demo reset;
    // the next tick retries. Nothing to surface to a user mid-poll.
  }
}
