/**
 * Real IP-reputation enrichment for an incident's sourceIp via the AbuseIPDB API (free tier).
 * Same honesty contract as the EPSS/KEV live feeds (modules/threatintel/liveFeeds.ts): real data
 * or an explicit "unavailable" result, never a fabricated score. Private/RFC1918 addresses (the
 * common case in this lab, where attacker IPs are simulated inside the Docker network) have no
 * public reputation data by definition — that's reported honestly, not treated as an error.
 */
import { config } from '../../config';

export interface IpReputation {
  ip: string;
  isPublic: boolean;
  abuseConfidenceScore?: number;
  totalReports?: number;
  countryCode?: string;
  isp?: string;
  lastReportedAt?: string;
}

const PRIVATE_RANGES = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^127\./];

function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some(r => r.test(ip));
}

export async function checkIpReputation(ip: string): Promise<IpReputation | null> {
  if (isPrivateIp(ip)) {
    return { ip, isPublic: false };
  }
  if (!config.abuseipdb.apiKey) return null;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: config.abuseipdb.apiKey, Accept: 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) return null;

    const body = (await res.json()) as { data: { abuseConfidenceScore: number; totalReports: number; countryCode: string; isp: string; lastReportedAt: string | null } };
    return {
      ip, isPublic: true,
      abuseConfidenceScore: body.data.abuseConfidenceScore,
      totalReports: body.data.totalReports,
      countryCode: body.data.countryCode,
      isp: body.data.isp,
      lastReportedAt: body.data.lastReportedAt ?? undefined,
    };
  } catch {
    return null;
  }
}
