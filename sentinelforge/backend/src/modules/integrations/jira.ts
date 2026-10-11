/**
 * Real Jira ticket creation for the generate_ticket response action — previously a DB-only stub
 * ("simulated action, no real system is touched"). Uses the Jira Cloud REST API v3 directly (no
 * SDK needed: one POST, Basic auth with an API token). If any of JIRA_SITE_URL/EMAIL/API_TOKEN/
 * PROJECT_KEY is unset, callers should treat ticketing as unavailable and keep the existing
 * simulated behavior — this module never silently invents a fake ticket.
 */
import { config } from '../../config';

export class JiraNotConfiguredError extends Error {}
export class JiraRequestError extends Error {}

export interface JiraTicket {
  key: string;
  url: string;
}

function basicAuthHeader(): string {
  return 'Basic ' + Buffer.from(`${config.jira.email}:${config.jira.apiToken}`).toString('base64');
}

// Jira Cloud's v3 API requires the description as Atlassian Document Format, not a plain string.
function toAdf(text: string): object {
  return { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text }] }] };
}

export function jiraConfigured(): boolean {
  return Boolean(config.jira.siteUrl && config.jira.email && config.jira.apiToken && config.jira.projectKey);
}

export async function createJiraTicket(summary: string, description: string): Promise<JiraTicket> {
  if (!jiraConfigured()) {
    throw new JiraNotConfiguredError('Jira is not configured (JIRA_SITE_URL/EMAIL/API_TOKEN/PROJECT_KEY).');
  }
  const res = await fetch(`https://${config.jira.siteUrl}/rest/api/3/issue`, {
    method: 'POST',
    headers: { Authorization: basicAuthHeader(), 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fields: {
        project: { key: config.jira.projectKey },
        summary,
        description: toAdf(description),
        issuetype: { name: 'Task' },
      },
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new JiraRequestError(`Jira issue creation failed: HTTP ${res.status} ${body.slice(0, 300)}`);
  }
  const data = (await res.json()) as { key: string };
  return { key: data.key, url: `https://${config.jira.siteUrl}/browse/${data.key}` };
}
