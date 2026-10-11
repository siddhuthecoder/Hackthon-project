'use client';

import { useAuth } from '@/lib/auth';

export default function SettingsPage(): React.ReactElement {
  const { user } = useAuth();

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="font-semibold mb-3">Account</h2>
        <dl className="text-sm space-y-1">
          <div className="flex justify-between"><dt className="text-slate-500">Name</dt><dd>{user?.name}</dd></div>
          <div className="flex justify-between"><dt className="text-slate-500">Email</dt><dd>{user?.email}</dd></div>
          <div className="flex justify-between"><dt className="text-slate-500">Role</dt><dd className="uppercase">{user?.role}</dd></div>
        </dl>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="font-semibold mb-3">Roles &amp; Permissions</h2>
        <p className="text-sm text-slate-400 mb-2">Fixed RBAC matrix (see backend <code>src/plugins/auth.ts</code>). Not editable from the UI in this build.</p>
        <table className="w-full text-sm">
          <thead className="text-slate-500 text-left">
            <tr><th className="py-1">Permission</th><th>admin</th><th>analyst</th><th>viewer</th></tr>
          </thead>
          <tbody className="text-slate-300">
            {[
              ['read', true, true, true],
              ['scan', true, true, false],
              ['simulate', true, true, false],
              ['investigate', true, true, false],
              ['respond', true, true, false],
              ['remediate', true, true, false],
              ['apply_fix', true, false, false],
              ['approve_action', true, false, false],
              ['manage_apps', true, true, false],
              ['reset', true, false, false],
            ].map(([perm, a, an, v]) => (
              <tr key={perm as string} className="border-t border-slate-800">
                <td className="py-1">{perm as string}</td>
                <td>{a ? '✓' : '—'}</td>
                <td>{an ? '✓' : '—'}</td>
                <td>{v ? '✓' : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="font-semibold mb-2">About</h2>
        <p className="text-sm text-slate-400">SentinelForge AI — see <code>docs/HACKATHON-PITCH.md</code> and <code>docs/IMPLEMENTATION-STATUS.md</code> in the repository for full architecture and verified status.</p>
      </div>
    </div>
  );
}
