/**
 * SOC Copilot: natural-language threat hunting across ALL of an org's recorded security events,
 * not just one incident/finding (the existing /api/assistant/ask is scoped to a single record).
 * Two-phase, same anti-hallucination pattern as the rest of modules/ai: (1) the model translates
 * the question into a whitelisted structured filter — never a raw query string, so there is no
 * injection surface — which this code alone turns into an actual Mongo query; (2) the model
 * summarizes strictly from the real rows that query returned. Both phases fall back to a
 * deterministic offline heuristic/template if no model is configured or the call fails.
 */
import { Application, ISecurityEvent, SecurityEvent } from '../../db/models';
import { callStructured } from '../ai/client';

export interface HuntFilter {
  eventTypes?: string[];
  severities?: ('low' | 'medium' | 'high' | 'critical')[];
  sourceIp?: string;
  userId?: string;
  endpointContains?: string;
  sinceHours?: number;
}

const KNOWN_EVENT_TYPES = [
  'AUTH_SUCCESS', 'AUTH_FAILURE', 'PASSWORD_RESET', 'SESSION_CREATED', 'SESSION_REVOKED',
  'API_REQUEST', 'API_ERROR', 'AUTHORIZATION_FAILURE', 'PRIVILEGE_CHANGE', 'ADMIN_ACTION',
  'DATA_ACCESS', 'BULK_DATA_ACCESS', 'CROSS_TENANT_ACCESS_ATTEMPT', 'FILE_UPLOAD', 'FILE_DOWNLOAD',
  'SUSPICIOUS_REQUEST', 'RATE_LIMIT_TRIGGERED', 'PAYMENT_CREATED', 'SECURITY_FINDING_TRIGGERED',
  'DATA_EXPORT', 'SUSPICIOUS_ACTIVITY', 'CROSS_RESOURCE_ACCESS', 'CANARY_TRIGGERED',
];

function offlineFilter(question: string): HuntFilter {
  const q = question.toLowerCase();
  const filter: HuntFilter = {};
  const eventTypes: string[] = [];
  if (q.includes('failed login') || q.includes('brute')) eventTypes.push('AUTH_FAILURE');
  if (q.includes('successful login') || q.includes('logged in')) eventTypes.push('AUTH_SUCCESS');
  if (q.includes('canary') || q.includes('honeypot') || q.includes('deception')) eventTypes.push('CANARY_TRIGGERED');
  if (q.includes('cross-tenant') || q.includes('cross tenant')) eventTypes.push('CROSS_TENANT_ACCESS_ATTEMPT');
  if (q.includes('export') || q.includes('exfiltrat')) eventTypes.push('BULK_DATA_ACCESS', 'DATA_EXPORT');
  if (eventTypes.length > 0) filter.eventTypes = eventTypes;
  if (q.includes('critical')) filter.severities = ['critical'];
  else if (q.includes('high')) filter.severities = ['high'];
  const hourMatch = q.match(/last (\d+)\s*hour/);
  const dayMatch = q.match(/last (\d+)\s*day|this week|past week/);
  if (hourMatch) filter.sinceHours = Number(hourMatch[1]);
  else if (dayMatch) filter.sinceHours = dayMatch[1] ? Number(dayMatch[1]) * 24 : 168;
  else filter.sinceHours = 24 * 7;
  return filter;
}

async function translateToFilter(question: string): Promise<HuntFilter> {
  const { data } = await callStructured<{ question: string; knownEventTypes: string[] }, HuntFilter>(
    `You translate a security analyst's natural-language question into a JSON search filter over a security event log. ` +
    `Only use these fields, all optional: eventTypes (array, pick only from knownEventTypes), severities (array of low/medium/high/critical), ` +
    `sourceIp (string), userId (string), endpointContains (string substring), sinceHours (number, lookback window — default 168 if the question gives no time hint). ` +
    `Omit any field the question doesn't clearly imply. Never invent an eventType not in knownEventTypes.`,
    { question, knownEventTypes: KNOWN_EVENT_TYPES },
    input => offlineFilter(input.question),
  );
  return data;
}

interface HuntResult {
  filter: HuntFilter;
  matchedCount: number;
  events: ISecurityEvent[];
  summary: string;
  mode: 'model' | 'offline';
}

export async function runThreatHunt(org: string, question: string): Promise<HuntResult> {
  const filterResult = await translateToFilter(question);
  const filter = filterResult;

  const apps = await Application.find({ organizationId: org }).select('_id');
  const mongoFilter: Record<string, unknown> = { applicationId: { $in: apps.map(a => a.id) } };
  if (filter.eventTypes?.length) mongoFilter.eventType = { $in: filter.eventTypes.filter(t => KNOWN_EVENT_TYPES.includes(t)) };
  if (filter.severities?.length) mongoFilter.severity = { $in: filter.severities };
  if (filter.sourceIp) mongoFilter.sourceIp = filter.sourceIp;
  if (filter.userId) mongoFilter.userId = filter.userId;
  if (filter.endpointContains) mongoFilter.endpoint = { $regex: filter.endpointContains.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };
  const sinceHours = filter.sinceHours ?? 24 * 7;
  mongoFilter.timestamp = { $gte: new Date(Date.now() - sinceHours * 60 * 60 * 1000) };

  const matchedCount = await SecurityEvent.countDocuments(mongoFilter);
  const events = await SecurityEvent.find(mongoFilter).sort({ timestamp: -1 }).limit(200);

  const { data: summaryData, mode } = await callStructured<
    { question: string; matchedCount: number; sample: Record<string, unknown>[] },
    { answer: string }
  >(
    `You are a SOC analyst assistant. Answer the question using ONLY the provided real event data (matchedCount and a sample of matching events). ` +
    `Be specific with real numbers/IPs/timestamps from the sample. If matchedCount is 0, say so plainly. Return strict JSON: { "answer": string }.`,
    { question, matchedCount, sample: events.slice(0, 15).map(e => e.toJSON() as unknown as Record<string, unknown>) },
    input => ({
      answer: input.matchedCount === 0
        ? 'No matching events found for that query.'
        : `Found ${input.matchedCount} matching event(s). Most recent: ${input.sample[0]?.eventType ?? 'unknown'} at ${input.sample[0]?.timestamp ?? 'unknown time'}.`,
    }),
  );

  return { filter, matchedCount, events, summary: summaryData.answer, mode };
}
