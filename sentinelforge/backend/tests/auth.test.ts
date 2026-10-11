import { describe, expect, it } from 'vitest';
import { can } from '../src/plugins/auth';

describe('plugins/auth: can()', () => {
  it('admin has every permission', () => {
    for (const perm of ['read', 'scan', 'simulate', 'investigate', 'respond', 'remediate', 'apply_fix', 'approve_action', 'manage_apps', 'reset'] as const) {
      expect(can('admin', perm)).toBe(true);
    }
  });

  it('viewer can only read', () => {
    expect(can('viewer', 'read')).toBe(true);
    expect(can('viewer', 'scan')).toBe(false);
    expect(can('viewer', 'apply_fix')).toBe(false);
  });

  it('analyst can investigate/remediate/manage_apps but not apply_fix/approve_action/reset (admin-only)', () => {
    expect(can('analyst', 'investigate')).toBe(true);
    expect(can('analyst', 'remediate')).toBe(true);
    expect(can('analyst', 'manage_apps')).toBe(true);
    expect(can('analyst', 'apply_fix')).toBe(false);
    expect(can('analyst', 'approve_action')).toBe(false);
    expect(can('analyst', 'reset')).toBe(false);
  });

  it('an unknown role has no permissions', () => {
    // @ts-expect-error intentionally passing an invalid role to prove the matrix fails closed
    expect(can('superuser', 'read')).toBe(false);
  });
});
