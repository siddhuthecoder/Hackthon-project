import Anthropic from '@anthropic-ai/sdk';
import { config } from '../../config';

let anthropicClient: Anthropic | undefined;
function anthropic(): Anthropic {
  if (!anthropicClient) anthropicClient = new Anthropic({ apiKey: config.ai.anthropicApiKey });
  return anthropicClient;
}

export interface AiCallResult<T> {
  data: T;
  mode: 'model' | 'offline';
}

function extractJson(text: string): string {
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) throw new Error('Model response did not contain JSON');
  return match[0];
}

async function callOpenRouter(systemPrompt: string, input: unknown): Promise<string> {
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.ai.openrouterApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: config.ai.openrouterModel,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: JSON.stringify(input) },
      ],
    }),
  });
  const body = await res.json() as { choices?: { message?: { content?: string } }[]; error?: { message?: string } };
  if (!res.ok || body.error) {
    throw new Error(`OpenRouter error: ${body.error?.message ?? res.statusText}`);
  }
  const text = body.choices?.[0]?.message?.content;
  if (!text) throw new Error('OpenRouter response had no content');
  return text;
}

async function callAnthropic(systemPrompt: string, input: unknown): Promise<string> {
  const response = await anthropic().messages.create({
    model: config.ai.anthropicModel,
    max_tokens: 1500,
    system: systemPrompt,
    messages: [{ role: 'user', content: JSON.stringify(input) }],
  });
  const text = response.content.find(block => block.type === 'text');
  if (!text || text.type !== 'text') throw new Error('No text content in model response');
  return text.text;
}

/**
 * Runs one structured-output call. Provider precedence: OpenRouter (if `OPENROUTER_API_KEY` is
 * set — the free-tier option), then Anthropic (if `ANTHROPIC_API_KEY` is set), then the
 * deterministic offline fallback. When a model call succeeds, its text is parsed for the first
 * `{...}` JSON block. When no key is configured, or the model call/parse fails for any reason,
 * falls back to `offlineFn`, which derives the same output shape directly from the real input
 * data — no model, no invented facts. Every caller labels its output with `mode` so the UI can
 * show whether an answer is model-generated or the honest offline summary.
 */
export async function callStructured<TInput, TOutput>(
  systemPrompt: string,
  input: TInput,
  offlineFn: (input: TInput) => TOutput,
): Promise<AiCallResult<TOutput>> {
  const jsonInstruction = `${systemPrompt}\n\nRespond with ONLY a single JSON object matching the described shape. No prose, no markdown fences.`;

  if (config.ai.openrouterApiKey) {
    try {
      const text = await callOpenRouter(jsonInstruction, input);
      return { data: JSON.parse(extractJson(text)) as TOutput, mode: 'model' };
    } catch {
      // fall through to offline below
    }
  } else if (config.ai.anthropicApiKey) {
    try {
      const text = await callAnthropic(jsonInstruction, input);
      return { data: JSON.parse(extractJson(text)) as TOutput, mode: 'model' };
    } catch {
      // fall through to offline below
    }
  }

  // A live demo must never die because the AI call failed (rate limit, network, bad JSON).
  // Fall back to the honest offline summary rather than showing an error on stage.
  return { data: offlineFn(input), mode: 'offline' };
}
