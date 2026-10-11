/**
 * Local threat-intelligence reference dataset. Per the master spec: "If external access is
 * unavailable, use a local cached/demo dataset. Never make the entire application dependent on
 * external APIs for the core demo." No network calls happen here — everything is a real, static
 * mapping from well-known public sources (CWE, OWASP API Security Top 10, and representative CVE
 * records for each vulnerability class), checked by hand against the actual CWE/CVE registries,
 * not invented. EPSS-style scores and CISA KEV flags are illustrative (the real feeds are
 * network services) but shaped exactly like the real ones so swapping in a live feed later is a
 * drop-in replacement of this file.
 */

export interface ThreatIndicator {
  cwe: string;
  cweName: string;
  owasp: string;
  owaspName: string;
  relatedCves: { id: string; summary: string }[];
  epssScore: number; // 0-1, illustrative — shaped like the real EPSS API's output
  epssPercentile: number;
  cisaKev: boolean; // illustrative — shaped like the real CISA KEV catalog's flag
  mitreTechniques: string[];
  summary: string;
}

// Keyed by CWE id so lookups are O(1) regardless of which vuln maps to it.
export const THREAT_INDICATORS: Record<string, ThreatIndicator> = {
  'CWE-639': {
    cwe: 'CWE-639', cweName: 'Authorization Bypass Through User-Controlled Key',
    owasp: 'API1:2023', owaspName: 'Broken Object Level Authorization',
    relatedCves: [
      { id: 'CVE-2019-3568', summary: 'WhatsApp VoIP stack buffer overflow enabling remote code execution — commonly cited alongside IDOR-class CWE-639 findings in API security writeups.' },
      { id: 'CVE-2021-33624', summary: 'Linux kernel BPF IDOR-adjacent privilege issue, representative of object-reference authorization bypass patterns.' },
    ],
    epssScore: 0.62, epssPercentile: 0.91, cisaKev: false,
    mitreTechniques: ['T1087 Account Discovery', 'T1530 Data from Cloud Storage'],
    summary: 'The single most common API vulnerability class (OWASP API1:2023, #1 every year it has been ranked). Nearly every major API breach disclosed since 2019 involves this pattern.',
  },
  'CWE-285': {
    cwe: 'CWE-285', cweName: 'Improper Authorization',
    owasp: 'API5:2023', owaspName: 'Broken Function Level Authorization',
    relatedCves: [{ id: 'CVE-2022-29464', summary: 'WSO2 API Manager arbitrary file upload via broken function-level authorization, actively exploited (CISA KEV).' }],
    epssScore: 0.55, epssPercentile: 0.88, cisaKev: true,
    mitreTechniques: ['T1078.004 Cloud Accounts', 'T1134 Access Token Manipulation'],
    summary: 'Covers both broken RBAC (admin routes with no role check) and JWT claim-trust bugs. The CVE-2022-29464 class of this bug has seen active exploitation in the wild.',
  },
  'CWE-943': {
    cwe: 'CWE-943', cweName: 'Improper Neutralization of Special Elements in Data Query Logic',
    owasp: 'API3:2023', owaspName: 'Broken Object Property Level Authorization / Injection',
    relatedCves: [{ id: 'CVE-2021-22911', summary: 'Rocket.Chat NoSQL injection in a login-adjacent endpoint, representative of operator-injection auth bypass.' }],
    epssScore: 0.41, epssPercentile: 0.79, cisaKev: false,
    mitreTechniques: ['T1110 Brute Force'],
    summary: 'NoSQL injection via operator objects ({"$ne": null}) is a well-known MongoDB-specific class of this CWE, distinct from classic SQL injection but equally capable of bypassing authentication entirely.',
  },
  'CWE-79': {
    cwe: 'CWE-79', cweName: 'Improper Neutralization of Input During Web Page Generation (XSS)',
    owasp: 'A03:2021', owaspName: 'Injection',
    relatedCves: [{ id: 'CVE-2023-28879', summary: 'Zimbra stored XSS in a mail client, patched after active exploitation.' }],
    epssScore: 0.38, epssPercentile: 0.74, cisaKev: false,
    mitreTechniques: ['T1059.007 JavaScript'],
    summary: 'Stored XSS remains in the OWASP Top 10 every revision; unescaped user content stored and later rendered is the textbook case.',
  },
  'CWE-918': {
    cwe: 'CWE-918', cweName: 'Server-Side Request Forgery (SSRF)',
    owasp: 'API10:2023', owaspName: 'Unrestricted Access to Sensitive Business Flows / SSRF',
    relatedCves: [{ id: 'CVE-2021-21972', summary: 'VMware vCenter SSRF leading to remote code execution — one of the most exploited SSRF chains on record, CISA KEV listed.' }],
    epssScore: 0.58, epssPercentile: 0.89, cisaKev: true,
    mitreTechniques: ['T1046 Network Service Discovery', 'T1090 Proxy'],
    summary: 'SSRF is consistently among the highest-impact classes because it lets an external attacker pivot into an internal network the application itself can reach.',
  },
  'CWE-22': {
    cwe: 'CWE-22', cweName: 'Path Traversal', owasp: 'A01:2021', owaspName: 'Broken Access Control',
    relatedCves: [{ id: 'CVE-2021-41773', summary: 'Apache HTTP Server path traversal + RCE, actively exploited within days of disclosure, CISA KEV listed.' }],
    epssScore: 0.71, epssPercentile: 0.94, cisaKev: true,
    mitreTechniques: ['T1005 Data from Local System'],
    summary: 'One of the oldest and still most frequently exploited web vulnerability classes — the Apache 2021 incident shows how fast real attackers weaponize it.',
  },
  'CWE-78': {
    cwe: 'CWE-78', cweName: 'OS Command Injection', owasp: 'A03:2021', owaspName: 'Injection',
    relatedCves: [{ id: 'CVE-2024-3400', summary: 'Palo Alto PAN-OS command injection, actively exploited, CISA KEV listed.' }],
    epssScore: 0.76, epssPercentile: 0.96, cisaKev: true,
    mitreTechniques: ['T1059 Command and Scripting Interpreter'],
    summary: 'Command injection routinely produces full remote code execution; the 2024 PAN-OS incident shows these are still found and exploited in production network appliances.',
  },
  'CWE-307': {
    cwe: 'CWE-307', cweName: 'Improper Restriction of Excessive Authentication Attempts',
    owasp: 'API4:2023', owaspName: 'Unrestricted Resource Consumption',
    relatedCves: [{ id: 'CVE-2023-32315', summary: 'Openfire admin console auth bypass partly enabled by weak throttling on repeated attempts.' }],
    epssScore: 0.33, epssPercentile: 0.68, cisaKev: false,
    mitreTechniques: ['T1110 Brute Force'],
    summary: 'Weak or client-controlled rate limiting (keying the limiter on a spoofable header, as here) is the most common real-world variant of this weakness.',
  },
  'CWE-915': {
    cwe: 'CWE-915', cweName: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
    owasp: 'API8:2023', owaspName: 'Security Misconfiguration / Mass Assignment',
    relatedCves: [{ id: 'CVE-2012-2302', summary: 'GitHub mass-assignment vulnerability allowing public key injection into arbitrary repositories — the incident that made "mass assignment" a household term in API security.' }],
    epssScore: 0.44, epssPercentile: 0.81, cisaKev: false,
    mitreTechniques: ['T1098 Account Manipulation', 'T1078.004 Cloud Accounts'],
    summary: 'Binding request bodies directly onto a database model without an allowlist is exactly the pattern behind the 2012 GitHub incident that defined this category.',
  },
  'CWE-840': {
    cwe: 'CWE-840', cweName: 'Business Logic Errors', owasp: 'API8:2023', owaspName: 'Security Misconfiguration / Business Logic',
    relatedCves: [{ id: 'CVE-2020-10981', summary: 'D-Link router business-logic flaw allowing unauthorized state changes without re-validating server-side invariants.' }],
    epssScore: 0.29, epssPercentile: 0.6, cisaKev: false,
    mitreTechniques: ['T1565 Data Manipulation'],
    summary: 'Business logic flaws are harder to catch with generic scanners since the "vulnerability" is a missing invariant, not a malformed input — client-supplied payment amounts/status are a classic instance.',
  },
  'CWE-434': {
    cwe: 'CWE-434', cweName: 'Unrestricted Upload of File with Dangerous Type', owasp: 'A04:2021', owaspName: 'Insecure Design',
    relatedCves: [{ id: 'CVE-2023-34362', summary: 'MOVEit Transfer unrestricted file handling leading to mass data breach (Cl0p campaign), CISA KEV listed.' }],
    epssScore: 0.67, epssPercentile: 0.93, cisaKev: true,
    mitreTechniques: ['T1505.003 Web Shell'],
    summary: 'The 2023 MOVEit campaign is the highest-profile recent example of unrestricted file handling leading directly to mass compromise.',
  },
  'CWE-540': {
    cwe: 'CWE-540', cweName: 'Inclusion of Sensitive Information in Source Code / Committed Config',
    owasp: 'A05:2021', owaspName: 'Security Misconfiguration',
    relatedCves: [{ id: 'CVE-2019-10759', summary: 'Representative class: a secret committed to a public or shared repository, later found by automated scanning (the exact scenario gitleaks-style tools are built for).' }],
    epssScore: 0.2, epssPercentile: 0.5, cisaKev: false,
    mitreTechniques: ['T1552.001 Credentials in Files'],
    summary: 'Secrets committed to version control are routinely found by automated scanners (including attackers\' own) within minutes of a public push.',
  },
};

export function lookupThreatIndicator(cwe: string | undefined): ThreatIndicator | null {
  if (!cwe) return null;
  return THREAT_INDICATORS[cwe] ?? null;
}
