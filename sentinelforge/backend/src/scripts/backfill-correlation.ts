import { connectDb, disconnectDb } from '../db/connection';
import { correlateAllRecent } from '../modules/correlation/service';
import { Incident } from '../db/models';
import { buildAttackPath } from '../modules/graph/service';

async function main(): Promise<void> {
  await connectDb();
  const created = await correlateAllRecent();
  const incidents = await Incident.find({});
  for (const i of incidents) await buildAttackPath(i.id);
  console.log(`correlations created: ${created}, attack paths rebuilt: ${incidents.length}`);
  await disconnectDb();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
