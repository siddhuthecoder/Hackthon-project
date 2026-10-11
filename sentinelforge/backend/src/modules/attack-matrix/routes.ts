import { FastifyInstance } from 'fastify';
import { Application, Incident } from '../../db/models';
import { authenticate } from '../../plugins/auth';
import { TACTIC_ORDER, TECHNIQUE_CATALOG } from './catalog';

export async function attackMatrixRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/attack-matrix', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const incidents = await Incident.find({ applicationId: { $in: apps.map(a => a.id) } }).select('mitre title severity');

    const countsByTechnique = new Map<string, number>();
    const examplesByTechnique = new Map<string, string>();
    for (const incident of incidents) {
      if (!incident.mitre) continue;
      const techniqueId = incident.mitre.split(' ')[0];
      countsByTechnique.set(techniqueId, (countsByTechnique.get(techniqueId) ?? 0) + 1);
      if (!examplesByTechnique.has(techniqueId)) examplesByTechnique.set(techniqueId, incident.title);
    }

    const techniques = TECHNIQUE_CATALOG.map(t => ({
      ...t,
      observedCount: countsByTechnique.get(t.id) ?? 0,
      exampleIncidentTitle: examplesByTechnique.get(t.id),
    }));

    reply.send({
      tacticOrder: TACTIC_ORDER,
      techniques,
      observedTechniques: techniques.filter(t => t.observedCount > 0).length,
      totalTechniques: techniques.length,
    });
  });
}
