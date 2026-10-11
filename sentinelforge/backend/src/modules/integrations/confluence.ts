/**
 * Real Confluence page publishing via the Confluence Cloud v2 REST API. Reuses the Jira
 * site/email/token (one Atlassian account) and only adds a target space id.
 */
import { config } from '../../config';

export class ConfluenceRequestError extends Error {}

export interface ConfluencePage {
  id: string;
  url: string;
}

export function confluenceConfigured(): boolean {
  return Boolean(config.jira.siteUrl && config.jira.email && config.jira.apiToken && config.confluence.spaceId);
}

/** Escapes text for Confluence storage format (XHTML). */
export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export async function createConfluencePage(title: string, storageBody: string): Promise<ConfluencePage> {
  const auth = 'Basic ' + Buffer.from(`${config.jira.email}:${config.jira.apiToken}`).toString('base64');
  const res = await fetch(`https://${config.jira.siteUrl}/wiki/api/v2/pages`, {
    method: 'POST',
    headers: { Authorization: auth, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      spaceId: config.confluence.spaceId,
      status: 'current',
      title,
      body: { representation: 'storage', value: storageBody },
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new ConfluenceRequestError(`Confluence page creation failed: HTTP ${res.status} ${text.slice(0, 300)}`);
  }
  const data = (await res.json()) as { id: string; _links?: { webui?: string } };
  const path = data._links?.webui ?? `/pages/${data.id}`;
  return { id: data.id, url: `https://${config.jira.siteUrl}/wiki${path}` };
}
