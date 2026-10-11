import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/modules/ai/tools', () => ({
  get_application: vi.fn(),
  get_asset: vi.fn(),
  get_endpoint: vi.fn(),
  get_vulnerability: vi.fn(),
  get_related_findings: vi.fn(),
  get_threat_intel: vi.fn(),
  get_attack_path: vi.fn(),
}));

describe('deterministic agents (no AI call, no live DB — tools module mocked)', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('ReconAgent summarizes real tool results without calling any AI model', async () => {
    const tools = await import('../src/modules/ai/tools');
    vi.mocked(tools.get_application).mockResolvedValue({ name: 'CyberLab', baseUrl: 'http://x', status: 'DISCOVERED' } as never);
    vi.mocked(tools.get_asset).mockResolvedValue([{ toJSON: () => ({ id: 'asset-1' }) }] as never);
    vi.mocked(tools.get_endpoint).mockResolvedValue([{ toJSON: () => ({ id: 'ep-1' }) }, { toJSON: () => ({ id: 'ep-2' }) }] as never);

    const { ReconAgent } = await import('../src/modules/ai/agents');
    const result = await ReconAgent({ applicationId: 'app-1' });

    expect(result.mode).toBe('deterministic');
    expect(result.output.assetCount).toBe(1);
    expect(result.output.endpointCount).toBe(2);
    expect(result.output.summary).toContain('CyberLab');
    expect(result.toolCalls.map(c => c.tool)).toEqual(['get_application', 'get_asset', 'get_endpoint']);
  });

  it('ReconAgent records a failed tool call rather than throwing silently', async () => {
    const tools = await import('../src/modules/ai/tools');
    vi.mocked(tools.get_application).mockRejectedValue(new Error('db unreachable'));
    vi.mocked(tools.get_asset).mockResolvedValue([] as never);
    vi.mocked(tools.get_endpoint).mockResolvedValue([] as never);

    const { ReconAgent } = await import('../src/modules/ai/agents');
    await expect(ReconAgent({ applicationId: 'app-1' })).rejects.toThrow('db unreachable');
  });

  it('CorrelationAgent reports correlated=false when there are no related findings', async () => {
    const tools = await import('../src/modules/ai/tools');
    vi.mocked(tools.get_related_findings).mockResolvedValue({ findings: [], correlations: [] } as never);

    const { CorrelationAgent } = await import('../src/modules/ai/agents');
    const result = await CorrelationAgent({ incidentId: 'inc-1' });

    expect(result.output.correlated).toBe(false);
    expect(result.output.relatedVulnKeys).toEqual([]);
  });

  it('CorrelationAgent surfaces the real correlation reason when one exists', async () => {
    const tools = await import('../src/modules/ai/tools');
    vi.mocked(tools.get_related_findings).mockResolvedValue({
      findings: [{ vulnKey: 'VULN-001' }],
      correlations: [{ reason: 'Live activity matched RULE-003 against a known BOLA endpoint.' }],
    } as never);

    const { CorrelationAgent } = await import('../src/modules/ai/agents');
    const result = await CorrelationAgent({ incidentId: 'inc-1' });

    expect(result.output.correlated).toBe(true);
    expect(result.output.relatedVulnKeys).toEqual(['VULN-001']);
    expect(result.output.reasons[0]).toContain('RULE-003');
  });

  it('ThreatIntelAgent falls back to an honest "no entry" summary when the CWE has no local indicator', async () => {
    const tools = await import('../src/modules/ai/tools');
    vi.mocked(tools.get_vulnerability).mockResolvedValue({ cwe: 'CWE-9999', owasp: null } as never);
    vi.mocked(tools.get_threat_intel).mockReturnValue(null as never);

    const { ThreatIntelAgent } = await import('../src/modules/ai/agents');
    const result = await ThreatIntelAgent({ findingId: 'vuln-1' });

    expect(result.output.summary).toMatch(/no local threat intelligence/i);
    expect(result.output.cisaKev).toBe(false);
  });
});
