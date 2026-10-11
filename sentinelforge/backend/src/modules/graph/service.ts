import { AttackPath, Correlation, IAttackEdge, IAttackNode, Incident, Vulnerability } from '../../db/models';
import { newId } from '../../lib/util';

/**
 * Builds a React-Flow-ready attack graph for one incident, strictly from data already in the DB:
 * the incident's subject/users/assets, its correlated finding(s) (if any), and the endpoint they
 * share. No node or edge is invented — an incident with no correlation still gets a graph, just a
 * shorter one (user -> endpoint -> asset).
 */
export async function buildAttackPath(incidentId: string): Promise<void> {
  const incident = await Incident.findById(incidentId);
  if (!incident) return;

  const correlations = await Correlation.find({ incidentId });
  const findings = correlations.length
    ? await Vulnerability.find({ _id: { $in: correlations.map(c => c.findingId) } })
    : [];

  const nodes: IAttackNode[] = [];
  const edges: IAttackEdge[] = [];

  const userId = incident.users[0] ?? incident.subject;
  const userNode = `user-${userId}`;
  nodes.push({ id: userNode, type: 'USER', label: userId, metadata: { role: incident.subject === incident.sourceIp ? 'unknown' : 'authenticated' } });

  if (incident.sourceIp) {
    const ipNode = `ip-${incident.sourceIp}`;
    nodes.push({ id: ipNode, type: 'IP', label: incident.sourceIp, metadata: {} });
    edges.push({ id: newId('edge'), source: ipNode, target: userNode, type: 'AUTHENTICATED' });
  }

  const endpointNode = `endpoint-${incident.assets[0] ?? incident.rule}`;
  nodes.push({ id: endpointNode, type: 'ENDPOINT', label: incident.assets[0] ?? 'unknown endpoint', metadata: { rule: incident.rule } });
  edges.push({ id: newId('edge'), source: userNode, target: endpointNode, type: 'ACCESSED' });

  for (const finding of findings) {
    const vulnNode = `vuln-${finding.vulnKey}`;
    nodes.push({ id: vulnNode, type: 'VULNERABILITY', label: `${finding.vulnKey}: ${finding.title}`, metadata: { cwe: finding.cwe, severity: finding.severity } });
    edges.push({ id: newId('edge'), source: endpointNode, target: vulnNode, type: 'EXPLOITED' });

    const assetNode = `asset-${finding.vulnKey}`;
    nodes.push({ id: assetNode, type: 'ASSET', label: `Data behind ${finding.endpoint}`, metadata: {} });
    edges.push({ id: newId('edge'), source: vulnNode, target: assetNode, type: 'ACCESSES' });
  }

  const summary = findings.length
    ? `${userId} exploited ${findings.map(f => f.vulnKey).join(', ')} via ${incident.assets[0] ?? 'the affected endpoint'}.`
    : `${userId} triggered ${incident.rule} against ${incident.assets[0] ?? 'the affected endpoint'} (no prior finding correlated yet).`;

  await AttackPath.findOneAndUpdate(
    { incidentId },
    { $set: { summary, nodes, edges }, $setOnInsert: { _id: newId('path'), incidentId } },
    { upsert: true },
  );
}
