/**
 * Decides which agent to invoke and persists the full trail (AgentRun: status, every tool call,
 * final output or error) so an agent's reasoning is auditable after the fact, not just in the
 * HTTP response. One generic `runAgent` wraps all 8 — the "decision" of which agent to use is
 * made by the caller (a route), matching the spec's "orchestrator decides which agent to invoke"
 * at the level that actually matters for a security product: which question is being asked.
 */
import { AgentRun } from '../../db/models';
import { newId } from '../../lib/util';
import { AgentResult } from './agents';

export type AgentName =
  | 'ReconAgent' | 'VulnerabilityAgent' | 'InvestigationAgent' | 'CorrelationAgent'
  | 'AttackPathAgent' | 'ThreatIntelAgent' | 'RemediationAgent' | 'VerificationAgent' | 'RedTeamAgent';

export async function runAgent<TInput, TOutput>(
  agent: AgentName,
  subjectType: string,
  subjectId: string,
  input: TInput,
  fn: (input: TInput) => Promise<AgentResult<TOutput>>,
): Promise<AgentResult<TOutput>> {
  const runId = newId('agentrun');
  await AgentRun.create({
    _id: runId, agent, mode: 'single-call', subjectType, subjectId, status: 'RUNNING', startedAt: new Date(), toolCalls: [],
  });

  try {
    const result = await fn(input);
    await AgentRun.findByIdAndUpdate(runId, {
      status: 'COMPLETED', finishedAt: new Date(), toolCalls: result.toolCalls, output: result.output as Record<string, unknown>,
    });
    return result;
  } catch (err) {
    await AgentRun.findByIdAndUpdate(runId, {
      status: 'FAILED', finishedAt: new Date(), error: err instanceof Error ? err.message : 'agent failed',
    });
    throw err;
  }
}
