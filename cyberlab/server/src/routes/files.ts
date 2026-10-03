import { Router, Response } from 'express';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import { AuthRequest, authMiddleware } from '../middleware/auth';
import { logSecurityEvent } from '../services/securityLogger';
import { v4 as uuidv4 } from 'uuid';
import { FileMeta } from '../models/File';

export const filesRouter = Router();
export const fetchUrlRouter = Router();
export const toolsRouter = Router();

const DEMO_ROOT = path.resolve(process.env.DEMO_FILES_DIR || path.join(__dirname, '../../demo-files'));
const PUBLIC_DIR = path.join(DEMO_ROOT, 'public');
const UPLOAD_DIR = path.join(DEMO_ROOT, 'uploads');
for (const dir of [PUBLIC_DIR, UPLOAD_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

const SAFE_ALLOWED_EXTENSIONS = /\.(txt|json|csv|png|jpg|jpeg)$/i;
const SAFE_ALLOWED_MIME = ['text/plain', 'application/json', 'text/csv', 'image/png', 'image/jpeg'];
// Lab safety guard: even the vulnerable upload never accepts host-executable binaries or scripts.
const HOST_EXECUTABLE = /\.(exe|dll|bat|cmd|com|scr|msi|sh|ps1|vbs|jar|bin|elf|app)$/i;
const RISKY_WEB_EXT = /\.(html?|svg|xml|php|jsp|aspx?|js)$/i;

// Lab safety guard: SSRF may only reach hosts inside the lab docker network / loopback.
const SSRF_LAB_HOSTS = ['internal-service', 'localhost', '127.0.0.1', 'api', 'frontend', 'nginx'];
const SECURE_FETCH_ALLOWLIST = ['http://internal-service:8080/health'];

function storage(sanitizeName: boolean): multer.StorageEngine {
  return multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const base = path.basename(file.originalname);
      const name = sanitizeName ? base.replace(/[^a-zA-Z0-9._-]/g, '_') : base.replace(/[\\/:*?"<>|]/g, '_');
      cb(null, `${Date.now()}-${name}`);
    },
  });
}

const secureUpload = multer({
  storage: storage(true),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (SAFE_ALLOWED_MIME.includes(file.mimetype) && SAFE_ALLOWED_EXTENSIONS.test(file.originalname)) {
      cb(null, true);
      return;
    }
    cb(new Error('File type not allowed'));
  },
});

// VULN-013: no extension / mimetype validation (only the lab safety guard for host executables)
const vulnerableUpload = multer({
  storage: storage(false),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (HOST_EXECUTABLE.test(file.originalname)) {
      cb(new Error('LAB_SAFETY_GUARD: host-executable uploads are blocked even in the vulnerable lab'));
      return;
    }
    cb(null, true);
  },
});

type EventBase = {
  userId: string;
  tenantId: string;
  sourceIp: string;
  userAgent: string;
  requestId: string;
  method: string;
};

function eventBase(req: AuthRequest): EventBase {
  return {
    userId: req.user!.userId,
    tenantId: req.user!.tenantId,
    sourceIp: req.sourceIp,
    userAgent: req.userAgent,
    requestId: req.requestId,
    method: req.method,
  };
}

function isLabHost(url: string): { ok: boolean; reason?: string } {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return { ok: false, reason: 'protocol_not_allowed' };
    if (!SSRF_LAB_HOSTS.includes(parsed.hostname)) return { ok: false, reason: 'host_outside_lab' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'invalid_url' };
  }
}

// ---------- SSRF (VULN-006) ----------

async function vulnerableFetch(req: AuthRequest, res: Response): Promise<void> {
  const { url } = req.body;
  if (typeof url !== 'string' || !url) {
    res.status(400).json({ error: 'URL required' });
    return;
  }

  const endpoint = req.originalUrl.split('?')[0];
  const guard = isLabHost(url);
  if (!guard.ok) {
    await logSecurityEvent({
      ...eventBase(req),
      eventType: 'SUSPICIOUS_REQUEST',
      severity: 'high',
      endpoint,
      metadata: { vulnerability: 'VULN-006', targetUrl: url, blocked: 'LAB_SAFETY_GUARD', reason: guard.reason },
    });
    res.status(403).json({ error: 'LAB_SAFETY_GUARD: only lab-internal hosts may be fetched', reason: guard.reason, url });
    return;
  }

  try {
    const response = await axios.get(url, { timeout: 5000, maxRedirects: 0, validateStatus: () => true });
    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    await logSecurityEvent({
      ...eventBase(req),
      eventType: 'SUSPICIOUS_REQUEST',
      severity: 'high',
      endpoint,
      mitreTechnique: 'T1046 Network Service Discovery',
      metadata: { vulnerability: 'VULN-006', targetUrl: url, statusCode: response.status, internalTarget: true },
    });
    res.json({ url, status: response.status, data: body.substring(0, 500), warning: 'VULNERABLE_ENDPOINT_SSRF' });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'fetch failed';
    await logSecurityEvent({
      ...eventBase(req),
      eventType: 'SUSPICIOUS_REQUEST',
      severity: 'high',
      endpoint,
      metadata: { vulnerability: 'VULN-006', targetUrl: url, error: message },
    });
    res.status(502).json({ error: 'Fetch failed', url });
  }
}

fetchUrlRouter.post('/secure', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { url } = req.body;
  if (typeof url !== 'string' || !SECURE_FETCH_ALLOWLIST.includes(url)) {
    await logSecurityEvent({
      ...eventBase(req),
      eventType: 'AUTHORIZATION_FAILURE',
      severity: 'medium',
      endpoint: '/api/fetch-url/secure',
      metadata: { vulnerability: 'VULN-006', targetUrl: url, reason: 'not_in_allowlist' },
    });
    res.status(403).json({ error: 'URL not in allowlist' });
    return;
  }
  try {
    const response = await axios.get(url, { timeout: 5000, maxRedirects: 0 });
    res.json({ url, status: response.status, data: JSON.stringify(response.data).substring(0, 500) });
  } catch {
    res.status(502).json({ error: 'Fetch failed' });
  }
});
fetchUrlRouter.post('/vulnerable', authMiddleware, vulnerableFetch);
fetchUrlRouter.post('/', authMiddleware, vulnerableFetch);

// ---------- Path traversal (VULN-007) ----------

async function readDemoFile(req: AuthRequest, res: Response, endpoint: string, resolved: string, requested: string, vulnerable: boolean): Promise<void> {
  if (resolved !== DEMO_ROOT && !resolved.startsWith(DEMO_ROOT + path.sep)) {
    await logSecurityEvent({
      ...eventBase(req),
      eventType: 'SUSPICIOUS_REQUEST',
      severity: 'high',
      endpoint,
      metadata: { vulnerability: 'VULN-007', file: requested, blocked: 'LAB_SAFETY_GUARD' },
    });
    res.status(403).json({ error: 'LAB_SAFETY_GUARD: path escapes the demo-files sandbox' });
    return;
  }
  try {
    const content = fs.readFileSync(resolved, 'utf-8');
    const traversed = path.relative(PUBLIC_DIR, resolved).startsWith('..');
    await logSecurityEvent({
      ...eventBase(req),
      eventType: 'FILE_DOWNLOAD',
      severity: vulnerable && traversed ? 'high' : 'low',
      endpoint,
      mitreTechnique: vulnerable && traversed ? 'T1005 Data from Local System' : null,
      metadata: { vulnerability: 'VULN-007', file: requested, traversed, resolvedPath: path.relative(DEMO_ROOT, resolved) },
    });
    res.json(vulnerable ? { file: requested, content, traversed, warning: 'VULNERABLE_ENDPOINT_PATH_TRAVERSAL' } : { file: requested, content });
  } catch {
    res.status(404).json({ error: 'File not found' });
  }
}

// VULNERABLE: the requested name is joined onto the public directory without validation
async function vulnerableDownload(req: AuthRequest, res: Response): Promise<void> {
  const file = req.query.file;
  if (typeof file !== 'string' || !file) {
    res.status(400).json({ error: 'File parameter required' });
    return;
  }
  const resolved = path.resolve(PUBLIC_DIR, file);
  await readDemoFile(req, res, req.originalUrl.split('?')[0], resolved, file, true);
}

filesRouter.get('/download/secure', authMiddleware, async (req: AuthRequest, res: Response) => {
  const file = req.query.file;
  if (typeof file !== 'string' || file !== path.basename(file) || file !== 'public.txt') {
    await logSecurityEvent({
      ...eventBase(req),
      eventType: 'SUSPICIOUS_REQUEST',
      severity: 'medium',
      endpoint: '/api/files/download/secure',
      metadata: { vulnerability: 'VULN-007', file, reason: 'rejected_by_allowlist' },
    });
    res.status(403).json({ error: 'File not allowed' });
    return;
  }
  await readDemoFile(req, res, '/api/files/download/secure', path.join(PUBLIC_DIR, file), file, false);
});
filesRouter.get('/download/vulnerable', authMiddleware, vulnerableDownload);
filesRouter.get('/download', authMiddleware, vulnerableDownload);

// ---------- File upload (VULN-013) ----------

async function finishUpload(req: AuthRequest, res: Response, validated: boolean): Promise<void> {
  if (!req.file) {
    res.status(400).json({ error: 'File required' });
    return;
  }
  const risky = RISKY_WEB_EXT.test(req.file.originalname);
  const fileMeta = await FileMeta.create({
    id: `file-${uuidv4().slice(0, 8)}`,
    filename: req.file.filename,
    originalName: req.file.originalname,
    tenantId: req.user!.tenantId,
    userId: req.user!.userId,
    mimeType: req.file.mimetype,
    size: req.file.size,
    uploadedAt: new Date(),
    validated,
  });

  await logSecurityEvent({
    ...eventBase(req),
    eventType: 'FILE_UPLOAD',
    severity: !validated && risky ? 'high' : validated ? 'low' : 'medium',
    endpoint: req.originalUrl.split('?')[0],
    mitreTechnique: !validated && risky ? 'T1505.003 Web Shell' : null,
    metadata: { ...(validated ? {} : { vulnerability: 'VULN-013' }), fileId: fileMeta.id, originalName: fileMeta.originalName, validated, riskyExtension: risky },
  });

  const body = { id: fileMeta.id, filename: fileMeta.filename, originalName: fileMeta.originalName, mimeType: fileMeta.mimeType, size: fileMeta.size, validated };
  res.status(201).json(validated ? body : { ...body, riskyExtension: risky, warning: 'VULNERABLE_ENDPOINT_FILE_UPLOAD' });
}

filesRouter.post('/upload/vulnerable', authMiddleware, vulnerableUpload.single('file'), (req: AuthRequest, res: Response) => finishUpload(req, res, false));
filesRouter.post('/upload/secure', authMiddleware, secureUpload.single('file'), (req: AuthRequest, res: Response) => finishUpload(req, res, true));
// Spec path: POST /api/files/upload is the vulnerable implementation
filesRouter.post('/upload', authMiddleware, vulnerableUpload.single('file'), (req: AuthRequest, res: Response) => finishUpload(req, res, false));

filesRouter.get('/', authMiddleware, async (req: AuthRequest, res: Response) => {
  const filter = req.user!.role === 'SUPER_ADMIN' ? {} : { tenantId: req.user!.tenantId };
  const files = await FileMeta.find(filter).sort({ uploadedAt: -1 }).limit(100);
  res.json(files.map(f => f.toJSON()));
});

// ---------- Command injection demo (VULN-008) - simulator only, nothing is executed ----------

const KNOWN_HOSTS: Record<string, string> = {
  localhost: 'PING localhost (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.052 ms',
  mongodb: 'PING mongodb: 56 data bytes\n64 bytes from mongodb: icmp_seq=0 ttl=64 time=0.123 ms',
  redis: 'PING redis: 56 data bytes\n64 bytes from redis: icmp_seq=0 ttl=64 time=0.087 ms',
  'internal-service': 'PING internal-service: 56 data bytes\n64 bytes from internal-service: icmp_seq=0 ttl=64 time=0.091 ms',
  api: 'PING api: 56 data bytes\n64 bytes from api: icmp_seq=0 ttl=64 time=0.045 ms',
};

const SHELL_META = /[$`;|&\n\r]/;

function simulateUnsafeCommand(host: string): string {
  // The naive implementation would build: `ping -c 1 ${host}` and hand it to a shell.
  // Here each segment split on shell metacharacters is "executed" by a lookup table.
  const segments = host.split(/[;|&\n\r]+|\$\(|`/).map(s => s.trim()).filter(Boolean);
  const lines = [`[SIMULATED] sh -c "ping -c 1 ${host}"`];
  segments.forEach((segment, index) => {
    const [command, ...args] = segment.split(/\s+/);
    if (index === 0) {
      lines.push(KNOWN_HOSTS[command] ?? `PING ${command}: Host not found in sandbox (simulated)`);
    } else if (command === 'whoami') {
      lines.push('[SIMULATED] sandbox-user');
    } else if (command === 'id') {
      lines.push('[SIMULATED] uid=1000(sandbox-user) gid=1000(sandbox-user)');
    } else if (command === 'cat' && args[0]) {
      lines.push(`[SIMULATED] cat ${args[0]}: contents hidden - simulator never reads files`);
    } else {
      lines.push(`[SIMULATED] injected command "${segment}" would have executed here (not executed)`);
    }
  });
  return lines.join('\n');
}

async function vulnerablePing(req: AuthRequest, res: Response): Promise<void> {
  const { host } = req.body;
  if (typeof host !== 'string' || !host) {
    res.status(400).json({ error: 'Host required' });
    return;
  }

  const injection = SHELL_META.test(host);
  if (injection) {
    await logSecurityEvent({
      ...eventBase(req),
      eventType: 'SUSPICIOUS_REQUEST',
      severity: 'high',
      endpoint: req.originalUrl.split('?')[0],
      mitreTechnique: 'T1059 Command and Scripting Interpreter',
      metadata: { vulnerability: 'VULN-008', input: host, hasInjection: true, note: 'sandboxed_simulator' },
    });
  }
  const output = injection ? simulateUnsafeCommand(host) : KNOWN_HOSTS[host] ?? `PING ${host}: Host not found in sandbox (simulated)`;
  res.json({ host, output, injectionDetected: injection, warning: 'SANDBOXED_SIMULATOR_VULN-008' });
}

toolsRouter.post('/ping/secure', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { host } = req.body;
  if (typeof host !== 'string' || !/^[a-zA-Z0-9.-]+$/.test(host)) {
    res.status(400).json({ error: 'Invalid host format' });
    return;
  }
  res.json({ host, output: KNOWN_HOSTS[host] ?? `PING ${host}: Host not found (simulated)` });
});
toolsRouter.post('/ping/vulnerable', authMiddleware, vulnerablePing);
toolsRouter.post('/ping', authMiddleware, vulnerablePing);
