import { FastifyInstance } from 'fastify';
import { Application, Vulnerability } from '../../db/models';
import { authenticate } from '../../plugins/auth';
import { API_TOP_10_TOTAL, OWASP_CATALOG, WEB_TOP_10_TOTAL } from './catalog';

export async function complianceRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/compliance/coverage', { preHandler: authenticate('read') }, async (request, reply) => {
    const apps = await Application.find({ organizationId: request.user.org }).select('_id');
    const findings = await Vulnerability.find({ applicationId: { $in: apps.map(a => a.id) } });

    const openByCode = new Map<string, number>();
    const totalByCode = new Map<string, number>();
    for (const f of findings) {
      if (!f.owasp) continue;
      totalByCode.set(f.owasp, (totalByCode.get(f.owasp) ?? 0) + 1);
      if (f.status === 'OPEN' || f.status === 'CONFIRMED') {
        openByCode.set(f.owasp, (openByCode.get(f.owasp) ?? 0) + 1);
      }
    }

    const categories = Object.values(OWASP_CATALOG).map(cat => ({
      ...cat,
      openFindings: openByCode.get(cat.code) ?? 0,
      totalFindings: totalByCode.get(cat.code) ?? 0,
    }));

    const apiCategories = categories.filter(c => c.family === 'api-top-10');
    const webCategories = categories.filter(c => c.family === 'web-top-10');

    reply.send({
      apiTop10: { tested: apiCategories.length, total: API_TOP_10_TOTAL, categories: apiCategories },
      webTop10: { tested: webCategories.length, total: WEB_TOP_10_TOTAL, categories: webCategories },
    });
  });
}
