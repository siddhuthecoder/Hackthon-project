import { describe, expect, it } from 'vitest';
import { maxSeverity, newId, normalizeSeverity, unique } from '../src/lib/util';

describe('lib/util', () => {
  it('newId produces a prefixed, unique-looking id each call', () => {
    const a = newId('vuln');
    const b = newId('vuln');
    expect(a).toMatch(/^vuln_[0-9a-f]{12}$/);
    expect(a).not.toBe(b);
  });

  it('normalizeSeverity accepts known severities case-insensitively', () => {
    expect(normalizeSeverity('HIGH')).toBe('high');
    expect(normalizeSeverity('low')).toBe('low');
  });

  it('normalizeSeverity falls back to low for unknown input', () => {
    expect(normalizeSeverity('catastrophic')).toBe('low');
    expect(normalizeSeverity(undefined)).toBe('low');
  });

  it('maxSeverity returns the more severe of two', () => {
    expect(maxSeverity('low', 'critical')).toBe('critical');
    expect(maxSeverity('high', 'medium')).toBe('high');
    expect(maxSeverity('high', 'high')).toBe('high');
  });

  it('unique de-duplicates while preserving first-seen order', () => {
    expect(unique(['a', 'b', 'a', 'c', 'b'])).toEqual(['a', 'b', 'c']);
  });
});
