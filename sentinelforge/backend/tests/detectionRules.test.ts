import { describe, expect, it } from 'vitest';
import { ISecurityEvent } from '../src/db/models';
import { RULES } from '../src/modules/detection/rules';

let seq = 0;
function fakeEvent(partial: Partial<ISecurityEvent>): ISecurityEvent {
  seq += 1;
  return {
    _id: `ev_${seq}`,
    sourceIp: '10.0.0.1',
    timestamp: new Date(),
    metadata: {},
    ...partial,
  } as unknown as ISecurityEvent;
}

function runRules(events: ISecurityEvent[]): { rule: string; subject: string }[] {
  return RULES.flatMap(rule => rule(events)).map(m => ({ rule: m.rule, subject: m.subject }));
}

describe('detection rules', () => {
  it('RULE-001 (brute force): fires on >10 AUTH_FAILURE from one IP, not at the threshold boundary', () => {
    const tenFailures = Array.from({ length: 10 }, () => fakeEvent({ eventType: 'AUTH_FAILURE', sourceIp: '10.0.0.5' }));
    expect(runRules(tenFailures).some(m => m.rule === 'RULE-001')).toBe(false);

    const elevenFailures = Array.from({ length: 11 }, () => fakeEvent({ eventType: 'AUTH_FAILURE', sourceIp: '10.0.0.5' }));
    const matches = runRules(elevenFailures);
    expect(matches).toContainEqual({ rule: 'RULE-001', subject: '10.0.0.5' });
  });

  it('RULE-002 (account takeover): fires only when a success follows the failures, not on failures alone', () => {
    const failuresOnly = Array.from({ length: 6 }, () => fakeEvent({ eventType: 'AUTH_FAILURE', sourceIp: '10.0.0.9' }));
    expect(runRules(failuresOnly).some(m => m.rule === 'RULE-002')).toBe(false);

    const withSuccess = [
      ...Array.from({ length: 6 }, () => fakeEvent({ eventType: 'AUTH_FAILURE', sourceIp: '10.0.0.9' })),
      fakeEvent({ eventType: 'AUTH_SUCCESS', sourceIp: '10.0.0.9', userId: 'user-200' }),
    ];
    const matches = runRules(withSuccess);
    expect(matches).toContainEqual({ rule: 'RULE-002', subject: '10.0.0.9' });
  });

  it('RULE-003 (IDOR enumeration): fires when one user hits >5 distinct resource ids, not fewer', () => {
    const fiveIds = Array.from({ length: 5 }, (_, i) => fakeEvent({
      eventType: 'DATA_ACCESS', userId: 'user-101', metadata: { resourceType: 'user', resourceId: `user-${i}` },
    }));
    expect(runRules(fiveIds).some(m => m.rule === 'RULE-003')).toBe(false);

    const sixIds = Array.from({ length: 6 }, (_, i) => fakeEvent({
      eventType: 'DATA_ACCESS', userId: 'user-101', metadata: { resourceType: 'user', resourceId: `user-${i}` },
    }));
    expect(runRules(sixIds)).toContainEqual({ rule: 'RULE-003', subject: 'user-101' });
  });

  it('RULE-004 (cross-tenant): fires on any CROSS_TENANT_ACCESS_ATTEMPT event', () => {
    const events = [fakeEvent({ eventType: 'CROSS_TENANT_ACCESS_ATTEMPT', userId: 'user-101', endpoint: '/api/orders/order-2' })];
    expect(runRules(events)).toContainEqual({ rule: 'RULE-004', subject: 'user-101' });
  });

  it('RULE-005 (privilege escalation): fires only on a genuine low-to-admin role change, not admin-to-admin', () => {
    const escalation = [fakeEvent({
      eventType: 'PRIVILEGE_CHANGE', userId: 'user-110',
      metadata: { oldRole: 'STAFF', newRole: 'TENANT_ADMIN', actorRole: 'STAFF' },
    })];
    expect(runRules(escalation)).toContainEqual({ rule: 'RULE-005', subject: 'user-110' });

    const adminReassignment = [fakeEvent({
      eventType: 'PRIVILEGE_CHANGE', userId: 'user-110',
      metadata: { oldRole: 'TENANT_ADMIN', newRole: 'SUPER_ADMIN', actorRole: 'SUPER_ADMIN' },
    })];
    expect(runRules(adminReassignment).some(m => m.rule === 'RULE-005')).toBe(false);
  });

  it('no rules fire on ordinary low-volume authenticated traffic', () => {
    const normal = [
      fakeEvent({ eventType: 'AUTH_SUCCESS', userId: 'user-101' }),
      fakeEvent({ eventType: 'API_REQUEST', userId: 'user-101', endpoint: '/api/orders' }),
      fakeEvent({ eventType: 'DATA_ACCESS', userId: 'user-101', metadata: { resourceType: 'user', resourceId: 'user-101' } }),
    ];
    expect(runRules(normal)).toEqual([]);
  });
});
