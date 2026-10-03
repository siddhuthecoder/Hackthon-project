import mongoose from 'mongoose';
import { connectDB, disconnectDB } from '../services/database';
import { Tenant } from '../models/Tenant';
import { User } from '../models/User';
import { Product } from '../models/Product';
import { Order } from '../models/Order';
import { Payment } from '../models/Payment';
import { SecurityEvent } from '../models/SecurityEvent';
import { AuditLog } from '../models/AuditLog';
import { Vulnerability } from '../models/Vulnerability';
import { Incident } from '../models/Incident';
import { AttackGraph } from '../models/AttackGraph';
import { Customer } from '../models/Customer';
import { Notification } from '../models/Notification';
import { Comment } from '../models/Comment';
import { Session } from '../models/Session';
import { FileMeta } from '../models/File';
import { hashPassword } from '../services/auth';
import { v4 as uuidv4 } from 'uuid';

const tenants = [
  { id: 'tenant-alpha', name: 'Tenant Alpha', plan: 'enterprise', createdAt: new Date('2026-01-15') },
  { id: 'tenant-beta', name: 'Tenant Beta', plan: 'pro', createdAt: new Date('2026-02-20') },
  { id: 'tenant-gamma', name: 'Tenant Gamma', plan: 'free', createdAt: new Date('2026-03-10') },
];

const firstNames = ['Alice', 'Bob', 'Carol', 'David', 'Eve', 'Frank', 'Grace', 'Henry', 'Ivy', 'Jack', 'Karen', 'Leo', 'Mia', 'Noah', 'Olivia', 'Paul', 'Quinn', 'Ruby', 'Sam', 'Tina', 'Uma', 'Victor', 'Wendy', 'Xander', 'Yara', 'Zane', 'Aria', 'Blake', 'Chloe', 'Derek'];
const lastNames = ['Anderson', 'Brown', 'Chen', 'Davis', 'Evans', 'Foster', 'Garcia', 'Hughes', 'Irwin', 'Jones', 'Kim', 'Lopez', 'Morgan', 'Nash', 'Owens', 'Patel', 'Quinn', 'Reed', 'Smith', 'Taylor'];

const productNames = ['Quantum Router', 'Sentinel Gateway', 'Cipher Module', 'Shield Generator', 'Mesh Extender', 'Core Processor', 'Edge Node', 'Fiber Bridge', 'Secure Token', 'Access Key', 'Network Probe', 'Data Vault', 'Signal Booster', 'Protocol Adapter', 'Link Aggregator'];
const categories = ['Networking', 'Security', 'Storage', 'Compute', 'IoT', 'Software'];

const pad = (n: number): string => String(n).padStart(2, '0');

async function seed(): Promise<void> {
  await connectDB();

  console.log('[Seed] Clearing existing data...');
  await Promise.all([
    Tenant.deleteMany({}),
    User.deleteMany({}),
    Product.deleteMany({}),
    Order.deleteMany({}),
    Payment.deleteMany({}),
    SecurityEvent.deleteMany({}),
    AuditLog.deleteMany({}),
    Vulnerability.deleteMany({}),
    Incident.deleteMany({}),
    AttackGraph.deleteMany({}),
    Customer.deleteMany({}),
    Notification.deleteMany({}),
    Comment.deleteMany({}),
    Session.deleteMany({}),
    FileMeta.deleteMany({}),
  ]);

  console.log('[Seed] Creating tenants...');
  await Tenant.insertMany(tenants);

  console.log('[Seed] Creating users...');
  // 30 users: 5 admins (1 SUPER_ADMIN + 4 TENANT_ADMIN), 10 managers, 15 non-privileged (10 STAFF + 5 USER)
  const rolePlan: Record<string, string[]> = {
    'tenant-alpha': ['USER', 'USER', 'STAFF', 'STAFF', 'STAFF', 'MANAGER', 'MANAGER', 'MANAGER', 'TENANT_ADMIN'],
    'tenant-beta': ['USER', 'USER', 'STAFF', 'STAFF', 'STAFF', 'MANAGER', 'MANAGER', 'MANAGER', 'TENANT_ADMIN', 'TENANT_ADMIN'],
    'tenant-gamma': ['USER', 'STAFF', 'STAFF', 'STAFF', 'STAFF', 'MANAGER', 'MANAGER', 'MANAGER', 'MANAGER', 'TENANT_ADMIN'],
  };
  const users: any[] = [];
  let userId = 101;
  const passwordHash = hashPassword('demo_password_123');
  for (const tenant of tenants) {
    for (const role of rolePlan[tenant.id]) {
      const idx = userId - 101;
      const fn = firstNames[idx % firstNames.length];
      const ln = lastNames[idx % lastNames.length];
      users.push({
        id: `user-${userId}`,
        name: `${fn} ${ln}`,
        email: `${fn.toLowerCase()}.${ln.toLowerCase()}@${tenant.id.replace('-', '.')}.com`,
        passwordHash,
        role,
        tenantId: tenant.id,
        active: true,
        isAdmin: role === 'TENANT_ADMIN',
        lastLogin: userId % 3 === 0 ? null : new Date(`2026-09-${String((userId % 27) + 1).padStart(2, '0')}T${String(10 + (userId % 12)).padStart(2, '0')}:00:00Z`),
        createdAt: new Date(`2026-0${(userId % 9) + 1}-15T08:00:00Z`),
        phone: `+1-555-0${100 + userId}`,
      });
      userId++;
    }
  }
  users.push({
    id: 'user-001',
    name: 'System Administrator',
    email: 'admin@sentinelforge.lab',
    passwordHash: hashPassword('admin_demo_123'),
    role: 'SUPER_ADMIN',
    tenantId: 'tenant-alpha',
    active: true,
    isAdmin: true,
    lastLogin: new Date('2026-09-30T08:00:00Z'),
    createdAt: new Date('2026-01-01T08:00:00Z'),
    phone: '+1-555-0001',
  });
  await User.insertMany(users);

  console.log('[Seed] Creating customers...');
  const companies = ['Acme Corp', 'Globex', 'Initech', 'Umbrella Ltd', 'Hooli', 'Stark Industries', 'Wayne Enterprises', 'Soylent', 'Vandelay', 'Cyberdyne'];
  const customers: any[] = Array.from({ length: 100 }, (_, j) => {
    const fn = firstNames[(j * 7) % firstNames.length];
    const ln = lastNames[(j * 3) % lastNames.length];
    return {
      id: `cust-${j + 1}`,
      name: `${fn} ${ln}`,
      email: `${fn.toLowerCase()}.${ln.toLowerCase()}${j}@customer.example.test`,
      company: companies[j % companies.length],
      phone: `+1-555-02${String(j).padStart(2, '0')}`,
      tenantId: tenants[j % 3].id,
      createdAt: new Date(`2026-0${(j % 9) + 1}-10T08:00:00Z`),
    };
  });
  await Customer.insertMany(customers);

  console.log('[Seed] Creating products...');
  const products: any[] = [];
  for (let i = 0; i < 100; i++) {
    const tenant = tenants[i % 3];
    const pn = productNames[i % productNames.length];
    products.push({
      id: `prod-${i + 1}`,
      name: `${pn} v${Math.floor(i / productNames.length) + 1}`,
      description: `High-performance ${pn.toLowerCase()} for enterprise deployments. Model #${1000 + i}.`,
      price: Math.round((49.99 + (i * 17.5)) * 100) / 100,
      category: categories[i % categories.length],
      tenantId: tenant.id,
      stock: (i * 7) % 200,
      createdAt: new Date(`2026-0${(i % 9) + 1}-${pad((i % 28) + 1)}T08:00:00Z`),
    });
  }
  await Product.insertMany(products);

  console.log('[Seed] Creating orders...');
  const orders: any[] = [];
  for (let i = 0; i < 200; i++) {
    const tenant = tenants[i % 3];
    const customer = customers[(i % 3) + 3 * (Math.floor(i / 3) % 33)];
    const itemCount = (i % 3) + 1;
    const items = [];
    for (let j = 0; j < itemCount; j++) {
      const p = products[(i + j) % products.length];
      items.push({ productId: p.id, name: p.name, quantity: (i + j) % 5 + 1, price: p.price });
    }
    const total = items.reduce((s, it) => s + it.price * it.quantity, 0);
    const statuses = ['pending', 'paid', 'shipped', 'delivered', 'cancelled', 'refunded'];
    orders.push({
      id: `order-${i + 1}`,
      orderNumber: `ORD-${String(10000 + i).padStart(5, '0')}`,
      customerId: customer.id,
      customerName: customer.name,
      tenantId: tenant.id,
      items,
      total: Math.round(total * 100) / 100,
      status: statuses[i % statuses.length],
      createdAt: new Date(`2026-0${(i % 9) + 1}-${pad((i % 28) + 1)}T${pad(i % 24)}:00:00Z`),
    });
  }
  await Order.insertMany(orders);

  console.log('[Seed] Creating payments...');
  const payments: any[] = [];
  for (let i = 0; i < 50; i++) {
    const order = orders[i * 4];
    const statuses = ['pending', 'completed', 'failed', 'refunded'];
    const methods = ['card', 'bank', 'wallet'];
    payments.push({
      id: `pay-${i + 1}`,
      orderId: order.id,
      amount: order.total,
      status: statuses[i % statuses.length],
      method: methods[i % methods.length],
      createdAt: order.createdAt,
    });
  }
  await Payment.insertMany(payments);

  console.log('[Seed] Creating vulnerabilities...');
  const vulns = [
    { id: 'VULN-001', type: 'IDOR/BOLA', title: 'Broken Object Level Authorization', description: 'The /api/users/:userId endpoint does not verify that the requesting user owns the requested resource.', severity: 'high', endpoint: '/api/users/:userId', method: 'GET', status: 'OPEN', cwe: 'CWE-639', owasp: 'API1:2023', mitreTactic: 'Initial Access', mitreTechnique: 'T1078 Valid Accounts', attackScenario: 'User changes user ID in URL to access another user data', secureEndpoint: '/api/users/secure/:userId', vulnerableEndpoint: '/api/users/:userId' },
    { id: 'VULN-002', type: 'Cross-Tenant Access', title: 'Cross-Tenant Data Access', description: 'The /api/orders/:orderId endpoint does not verify tenant ownership.', severity: 'critical', endpoint: '/api/orders/:orderId', method: 'GET', status: 'OPEN', cwe: 'CWE-639', owasp: 'API1:2023', mitreTactic: 'Collection', mitreTechnique: 'T1530 Data from Cloud Storage', attackScenario: 'Tenant Alpha user accesses Tenant Beta order', secureEndpoint: '/api/orders/secure/:orderId', vulnerableEndpoint: '/api/orders/:orderId' },
    { id: 'VULN-003', type: 'Broken RBAC', title: 'Broken Function Level Authorization', description: 'Admin endpoints do not properly validate user roles.', severity: 'high', endpoint: '/api/admin/users', method: 'GET', status: 'OPEN', cwe: 'CWE-285', owasp: 'API5:2023', mitreTactic: 'Privilege Escalation', mitreTechnique: 'T1078.004 Cloud Accounts', attackScenario: 'STAFF user calls admin endpoints', secureEndpoint: '/api/admin/users', vulnerableEndpoint: '/api/admin/users/vulnerable' },
    { id: 'VULN-004', type: 'NoSQL Injection', title: 'NoSQL Injection in Login', description: 'Vulnerable login constructs MongoDB queries from user input without sanitization.', severity: 'critical', endpoint: '/api/auth/vulnerable-login', method: 'POST', status: 'OPEN', cwe: 'CWE-943', owasp: 'API3:2023', mitreTactic: 'Credential Access', mitreTechnique: 'T1110 Brute Force', attackScenario: 'Attacker sends {"$ne": null} as password', secureEndpoint: '/api/auth/secure-login', vulnerableEndpoint: '/api/auth/vulnerable-login' },
    { id: 'VULN-005', type: 'Stored XSS', title: 'Stored Cross-Site Scripting', description: 'Comments endpoint stores user input without sanitization.', severity: 'high', endpoint: '/api/comments', method: 'POST', status: 'OPEN', cwe: 'CWE-79', owasp: 'A03:2021', mitreTactic: 'Execution', mitreTechnique: 'T1059.007 JavaScript', attackScenario: 'Attacker posts comment with script tag', secureEndpoint: '/api/comments/safe', vulnerableEndpoint: '/api/comments' },
    { id: 'VULN-006', type: 'SSRF', title: 'Server-Side Request Forgery', description: 'Fetch-url endpoint makes server-side HTTP requests without URL allowlisting.', severity: 'high', endpoint: '/api/fetch-url', method: 'POST', status: 'OPEN', cwe: 'CWE-918', owasp: 'API10:2023', mitreTactic: 'Discovery', mitreTechnique: 'T1046 Network Service Discovery', attackScenario: 'Attacker submits internal service URL', secureEndpoint: '/api/fetch-url/secure', vulnerableEndpoint: '/api/fetch-url' },
    { id: 'VULN-007', type: 'Path Traversal', title: 'Path Traversal in File Download', description: 'File download endpoint does not properly validate file paths.', severity: 'high', endpoint: '/api/files/download', method: 'GET', status: 'OPEN', cwe: 'CWE-22', owasp: 'A01:2021', mitreTactic: 'Collection', mitreTechnique: 'T1005 Data from Local System', attackScenario: 'Attacker uses ../ to access internal files', secureEndpoint: '/api/files/download/secure', vulnerableEndpoint: '/api/files/download' },
    { id: 'VULN-008', type: 'Command Injection', title: 'Command Injection Demo', description: 'Sandboxed ping utility demonstrates unsafe argument handling.', severity: 'medium', endpoint: '/api/tools/ping', method: 'POST', status: 'OPEN', cwe: 'CWE-78', owasp: 'A03:2021', mitreTactic: 'Execution', mitreTechnique: 'T1059 Command and Scripting Interpreter', attackScenario: 'Attacker submits input with shell metacharacters', secureEndpoint: '/api/tools/ping/secure', vulnerableEndpoint: '/api/tools/ping' },
    { id: 'VULN-009', type: 'Weak Rate Limiting', title: 'Weak Rate Limiting on Login', description: 'Login endpoint has intentionally weak rate limiting.', severity: 'medium', endpoint: '/api/auth/login', method: 'POST', status: 'OPEN', cwe: 'CWE-307', owasp: 'API4:2023', mitreTactic: 'Credential Access', mitreTechnique: 'T1110 Brute Force', attackScenario: 'Attacker makes 20+ failed login attempts', secureEndpoint: '/api/auth/login (rate-limited)', vulnerableEndpoint: '/api/auth/login (weak limits)' },
    { id: 'VULN-010', type: 'JWT Authorization', title: 'JWT Authorization Weakness', description: 'Authentication succeeds but authorization trusts the JWT role claim without server-side role verification.', severity: 'high', endpoint: '/api/vulnerable/admin', method: 'GET', status: 'OPEN', cwe: 'CWE-285', owasp: 'API5:2023', mitreTactic: 'Privilege Escalation', mitreTechnique: 'T1134 Access Token Manipulation', attackScenario: 'Server trusts the role claim in a valid token and never re-checks the database; a demoted admin keeps access until token expiry', secureEndpoint: '/api/vulnerable/admin/secure', vulnerableEndpoint: '/api/vulnerable/admin' },
    { id: 'VULN-011', type: 'Mass Assignment', title: 'Mass Assignment Privilege Escalation', description: 'User update endpoint accepts all fields including role and tenantId.', severity: 'high', endpoint: '/api/users/:id', method: 'PATCH', status: 'OPEN', cwe: 'CWE-915', owasp: 'API8:2023', mitreTactic: 'Privilege Escalation', mitreTechnique: 'T1078.004 Cloud Accounts', attackScenario: 'USER sends PATCH with role:TENANT_ADMIN', secureEndpoint: '/api/users/secure/:id', vulnerableEndpoint: '/api/users/:id' },
    { id: 'VULN-012', type: 'Business Logic', title: 'Payment Business Logic Abuse', description: 'Payment workflow allows manipulating order status without state machine validation.', severity: 'high', endpoint: '/api/payments', method: 'POST', status: 'OPEN', cwe: 'CWE-840', owasp: 'API8:2023', mitreTactic: 'Impact', mitreTechnique: 'T1565 Data Manipulation', attackScenario: 'User manipulates payment to mark order as paid', secureEndpoint: '/api/payments/secure', vulnerableEndpoint: '/api/payments' },
    { id: 'VULN-013', type: 'File Upload', title: 'Insecure File Upload', description: 'File upload endpoint accepts any extension or mimetype (host executables stay blocked by the lab safety guard).', severity: 'medium', endpoint: '/api/files/upload', method: 'POST', status: 'OPEN', cwe: 'CWE-434', owasp: 'A04:2021', mitreTactic: 'Persistence', mitreTechnique: 'T1505.003 Web Shell', attackScenario: 'Attacker uploads file with dangerous extension', secureEndpoint: '/api/files/upload/secure', vulnerableEndpoint: '/api/files/upload' },
    { id: 'VULN-014', type: 'Secret Exposure', title: 'Secret Exposure in Configuration', description: 'Fake demo credentials committed in configuration file.', severity: 'medium', endpoint: 'config/demo.env', method: 'GET', status: 'OPEN', cwe: 'CWE-540', owasp: 'A05:2021', mitreTactic: 'Credential Access', mitreTechnique: 'T1552.001 Credentials in Files', attackScenario: 'Scanner finds DEMO_API_KEY in config', secureEndpoint: 'config/secure.env', vulnerableEndpoint: 'config/demo.env' },
  ];
  await Vulnerability.insertMany(vulns);

  console.log('[Seed] Creating attack graph...');
  // Seeded attack chain: Credential Compromise > Authenticated User > IDOR > Cross-Tenant Access > Admin API > Bulk Data Access
  await AttackGraph.create({
    attackPath: ['Credential Compromise', 'Authenticated User', 'IDOR (VULN-001)', 'Cross-Tenant Access (VULN-002)', 'Admin API (VULN-003)', 'Bulk Data Access'],
    nodes: [
      { id: 'ip-172.20.0.5', type: 'IP', label: '172.20.0.5 (credential compromise source)' },
      { id: 'user-101', type: 'USER', label: 'user-101 (Alice Anderson)', metadata: { role: 'USER', tenant: 'tenant-alpha' } },
      { id: 'vuln-VULN-001', type: 'VULNERABILITY', label: 'VULN-001: IDOR', metadata: { cwe: 'CWE-639', severity: 'HIGH' } },
      { id: 'vuln-VULN-002', type: 'VULNERABILITY', label: 'VULN-002: Cross-Tenant Access', metadata: { cwe: 'CWE-639', severity: 'CRITICAL' } },
      { id: 'endpoint-admin', type: 'ENDPOINT', label: '/api/admin/users/vulnerable' },
      { id: 'vuln-VULN-003', type: 'VULNERABILITY', label: 'VULN-003: Broken RBAC', metadata: { cwe: 'CWE-285', severity: 'HIGH' } },
      { id: 'db-users', type: 'DATABASE', label: 'MongoDB: users collection' },
      { id: 'tenant-beta', type: 'TENANT', label: 'Tenant Beta' },
      { id: 'asset-customers', type: 'ASSET', label: 'Customer Data (Tenant Beta)' },
      { id: 'api-orders', type: 'API', label: 'GET /api/orders/export (bulk data access)' },
    ],
    edges: [
      { from: 'ip-172.20.0.5', to: 'user-101', type: 'AUTHENTICATED' },
      { from: 'user-101', to: 'vuln-VULN-001', type: 'EXPLOITED' },
      { from: 'vuln-VULN-001', to: 'db-users', type: 'ACCESSES' },
      { from: 'user-101', to: 'vuln-VULN-002', type: 'EXPLOITED' },
      { from: 'vuln-VULN-002', to: 'tenant-beta', type: 'TARGETED' },
      { from: 'tenant-beta', to: 'asset-customers', type: 'BELONGS_TO' },
      { from: 'vuln-VULN-002', to: 'vuln-VULN-003', type: 'ESCALATED_TO' },
      { from: 'vuln-VULN-003', to: 'endpoint-admin', type: 'ACCESSED' },
      { from: 'endpoint-admin', to: 'api-orders', type: 'ACCESSES' },
      { from: 'api-orders', to: 'asset-customers', type: 'ACCESSES' },
    ],
  });

  console.log('[Seed] Creating historical incidents...');
  const daysAgo = (d: number) => new Date(Date.now() - d * 24 * 60 * 60 * 1000);
  await Incident.insertMany([
    { id: 'INC-seed0001', title: 'Brute Force Attack Detected', severity: 'high', status: 'RESOLVED', detectedAt: daysAgo(2), sourceIp: '172.20.0.5', users: ['user-101'], assets: ['/api/auth/login'], eventIds: [], findings: ['VULN-009'], attackPath: ['Credential Compromise', 'Brute Force Login', 'Successful Authentication', 'Sensitive API Access'], confidence: 0.85, recommendedActions: ['Block source IP', 'Force password reset', 'Enable MFA'], mitreTactic: 'Credential Access', mitreTechnique: 'T1110 Brute Force' },
    { id: 'INC-seed0002', title: 'Cross-Tenant Data Access Attempt', severity: 'critical', status: 'INVESTIGATING', detectedAt: daysAgo(1), sourceIp: '172.20.0.8', users: ['user-105'], assets: ['/api/orders/order-2'], eventIds: [], findings: ['VULN-002'], attackPath: ['Tenant Alpha User', 'Authenticated Access', 'IDOR via Order ID', 'Tenant Beta Data Access'], confidence: 0.92, recommendedActions: ['Revoke session', 'Audit cross-tenant access', 'Patch order authorization'], mitreTactic: 'Collection', mitreTechnique: 'T1530 Data from Cloud Storage' },
    { id: 'INC-seed0003', title: 'Possible IDOR Attack', severity: 'high', status: 'FALSE_POSITIVE', detectedAt: daysAgo(3), sourceIp: '172.20.0.9', users: ['user-110'], assets: ['/api/users/:userId'], eventIds: [], findings: ['VULN-001'], attackPath: ['User Authentication', 'Access Own Resource', 'Change Resource ID', 'Access Another User Data'], confidence: 0.6, recommendedActions: ['Audit user access logs'], mitreTactic: 'Discovery', mitreTechnique: 'T1087 Account Discovery' },
  ]);

  console.log('[Seed] Creating historical security events...');
  const eventPlan: Array<[string, string, string]> = [
    ['AUTH_SUCCESS', 'low', '/api/auth/login'],
    ['API_REQUEST', 'low', '/api/orders'],
    ['DATA_ACCESS', 'low', '/api/orders/order-7'],
    ['AUTH_FAILURE', 'medium', '/api/auth/login'],
    ['SESSION_CREATED', 'low', '/api/auth/login'],
    ['AUTHORIZATION_FAILURE', 'high', '/api/admin/users'],
    ['FILE_DOWNLOAD', 'low', '/api/files/download/secure'],
    ['PAYMENT_UPDATED', 'low', '/api/payments/secure'],
    ['SUSPICIOUS_REQUEST', 'high', '/api/tools/ping'],
    ['PRIVILEGE_CHANGE', 'medium', '/api/admin/users/user-112/promote'],
  ];
  const historicalEvents: any[] = [];
  for (let i = 0; i < 150; i++) {
    const [eventType, severity, endpoint] = eventPlan[i % eventPlan.length];
    const user = users[i % users.length];
    historicalEvents.push({
      timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000 + i * 17 * 60 * 1000 - 3 * 60 * 60 * 1000),
      eventType,
      severity,
      userId: eventType === 'AUTH_FAILURE' ? null : user.id,
      tenantId: user.tenantId,
      sourceIp: `172.20.0.${(i % 9) + 2}`,
      endpoint,
      method: eventType === 'PAYMENT_UPDATED' || eventType === 'AUTH_SUCCESS' ? 'POST' : 'GET',
      userAgent: i % 7 === 0 ? 'curl/8.4.0' : 'Mozilla/5.0 (demo-browser)',
      requestId: `req-seed-${i}`,
      mitreTechnique: eventType === 'AUTH_FAILURE' ? 'T1110 Brute Force' : null,
      metadata: eventType === 'PRIVILEGE_CHANGE' ? { oldRole: 'USER', newRole: 'MANAGER', actorRole: 'SUPER_ADMIN' } : { seeded: true },
    });
  }
  await SecurityEvent.insertMany(historicalEvents);

  console.log('[Seed] Creating comments...');
  await Comment.insertMany([
    { id: 'comment-seed1', productId: 'prod-1', userId: 'user-101', userName: 'Alice Anderson', tenantId: 'tenant-alpha', content: 'Great router, setup took five minutes.', sanitized: false, createdAt: daysAgo(1) },
    { id: 'comment-seed2', productId: 'prod-1', userId: 'user-102', userName: 'Bob Brown', tenantId: 'tenant-alpha', content: 'Firmware update fixed my latency issue.', sanitized: false, createdAt: daysAgo(1) },
    { id: 'comment-seed3', productId: 'prod-1', userId: 'user-103', userName: 'Carol Chen', tenantId: 'tenant-alpha', content: '<img src=x onerror="this.outerHTML=\'<b style=color:#dc2626>[VULN-005 XSS DEMO: script ran in your browser]</b>\'">Looks fine to me', sanitized: false, createdAt: daysAgo(0) },
  ]);

  console.log('[Seed] Creating notifications...');
  await Notification.insertMany([
    { id: 'notif-seed1', type: 'INCIDENT', title: 'Cross-Tenant Data Access Attempt', message: 'CRITICAL incident INC-seed0002 from 172.20.0.8', severity: 'critical', tenantId: null, incidentId: 'INC-seed0002', read: false, createdAt: daysAgo(1) },
    { id: 'notif-seed2', type: 'INCIDENT', title: 'Brute Force Attack Detected', message: 'HIGH incident INC-seed0001 from 172.20.0.5', severity: 'high', tenantId: null, incidentId: 'INC-seed0001', read: true, createdAt: daysAgo(2) },
  ]);

  console.log('[Seed] Creating audit logs...');
  const auditActions = ['LOGIN', 'LOGOUT', 'ROLE_CHANGED', 'USER_UPDATED', 'TENANT_UPDATED', 'ORDER_UPDATED', 'PAYMENT_UPDATED', 'ADMIN_ACTION', 'DATA_EXPORT'];
  const auditEntries: any[] = [];
  for (let i = 0; i < 100; i++) {
    const actor = users[(i + 5) % users.length];
    const target = users[(i + 10) % users.length];
    const action = auditActions[i % auditActions.length];
    auditEntries.push({
      actor: actor.id, actorName: actor.name, action,
      target: action === 'LOGIN' || action === 'LOGOUT' ? null : target.id,
      targetName: action === 'LOGIN' || action === 'LOGOUT' ? null : target.name,
      tenantId: actor.tenantId,
      oldValue: action === 'ROLE_CHANGED' ? 'STAFF' : null,
      newValue: action === 'ROLE_CHANGED' ? 'TENANT_ADMIN' : null,
      timestamp: new Date(`2026-09-${pad((i % 28) + 1)}T${pad(i % 24)}:${pad((i * 5) % 60)}:00Z`),
      details: action === 'DATA_EXPORT' ? 'Exported 500 records' : null,
    });
  }
  await AuditLog.insertMany(auditEntries);

  console.log('[Seed] Complete!');
  console.log(`  Tenants: ${tenants.length}`);
  console.log(`  Users: ${users.length}`);
  console.log(`  Customers: ${customers.length}`);
  console.log(`  Security events: ${historicalEvents.length}`);
  console.log(`  Products: ${products.length}`);
  console.log(`  Orders: ${orders.length}`);
  console.log(`  Payments: ${payments.length}`);
  console.log(`  Vulnerabilities: ${vulns.length}`);
  console.log(`  Audit Logs: ${auditEntries.length}`);

  await disconnectDB();
}

seed().catch(err => {
  console.error('[Seed] Failed:', err);
  process.exit(1);
});
