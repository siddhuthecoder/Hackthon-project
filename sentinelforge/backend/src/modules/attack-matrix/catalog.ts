/**
 * Real MITRE ATT&CK Enterprise tactic assignment for every technique this platform's detection
 * rules, scanner checks, and CyberLab's own event logging actually tag (collected by grepping
 * "T\d{4}" across both codebases). Each technique is placed under its primary tactic only, even
 * though several (e.g. T1078 Valid Accounts) span multiple tactics in the real framework — a
 * simplified single-column grid, documented honestly as such, not a full ATT&CK Navigator clone.
 */
export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
}

export const TACTIC_ORDER = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Command and Control', 'Collection',
  'Exfiltration', 'Impact',
];

export const TECHNIQUE_CATALOG: AttackTechnique[] = [
  { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' },
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  { id: 'T1059.007', name: 'JavaScript', tactic: 'Execution' },
  { id: 'T1505.003', name: 'Web Shell', tactic: 'Persistence' },
  { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
  { id: 'T1078.004', name: 'Cloud Accounts', tactic: 'Defense Evasion' },
  { id: 'T1134', name: 'Access Token Manipulation', tactic: 'Defense Evasion' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
  { id: 'T1552.001', name: 'Credentials in Files', tactic: 'Credential Access' },
  { id: 'T1087', name: 'Account Discovery', tactic: 'Discovery' },
  { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' },
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
  { id: 'T1090', name: 'Proxy', tactic: 'Command and Control' },
  { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
  { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  { id: 'T1499', name: 'Endpoint Denial of Service', tactic: 'Impact' },
  { id: 'T1565', name: 'Data Manipulation', tactic: 'Impact' },
];
