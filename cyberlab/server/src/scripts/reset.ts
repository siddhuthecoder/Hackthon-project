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
import { Session } from '../models/Session';
import { Comment } from '../models/Comment';
import { Customer } from '../models/Customer';
import { Notification } from '../models/Notification';
import { FileMeta } from '../models/File';

async function reset(): Promise<void> {
  await connectDB();

  console.log('[Reset] Dropping all collections...');
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
    Session.deleteMany({}),
    Customer.deleteMany({}),
    Notification.deleteMany({}),
    FileMeta.deleteMany({}),
    Comment.deleteMany({}),
  ]);

  console.log('[Reset] All data cleared. Run seed to repopulate.');

  await disconnectDB();
}

reset().catch(err => {
  console.error('[Reset] Failed:', err);
  process.exit(1);
});
