import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  BackupSnapshotMeta,
  DataRetentionPolicy,
  UserAccount,
} from '../types/marketplace.ts';
import {
  appendAuditLog,
  getStore,
  saveStore,
  StoreSnapshot,
  upsertSupplier,
  upsertUser,
} from './store.ts';

export const DEFAULT_RETENTION_POLICY: DataRetentionPolicy = {
  auditLogsDays: 2555, // 7 years compliance retention
  ordersAndPaymentsDays: 2555, // 7 years financial & order retention
  notificationsDays: 365,
  activityEventsDays: 180,
  supportTicketsDays: 730,
  backupsKeepCount: 15,
  updatedAt: new Date().toISOString(),
  updatedByEmail: 'system',
};

export const BACKUPS_DIR = path.resolve(process.cwd(), '.mik-data', 'backups');

function ensureBackupsDir(): void {
  if (!fs.existsSync(BACKUPS_DIR)) {
    fs.mkdirSync(BACKUPS_DIR, { recursive: true });
  }
}

export function getEffectiveRetentionPolicy(store: StoreSnapshot): DataRetentionPolicy {
  return {
    ...DEFAULT_RETENTION_POLICY,
    ...(store.retentionPolicy || {}),
  };
}

export async function createStoreBackup(params: {
  actor: Pick<UserAccount, 'uid' | 'email' | 'role'>;
  reason?: string;
}): Promise<{ meta: BackupSnapshotMeta; filePath: string }> {
  ensureBackupsDir();
  const store = await getStore();
  const policy = getEffectiveRetentionPolicy(store);
  const id = `bak_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const fileName = `${id}.json`;
  const filePath = path.join(BACKUPS_DIR, fileName);
  const createdAt = new Date().toISOString();

  // Exclude recursive backup history list from serialized payload if huge, keep clean state
  const snapshotPayload = JSON.stringify(store, null, 2);
  const sha256 = crypto.createHash('sha256').update(snapshotPayload, 'utf-8').digest('hex');

  const wrapper = JSON.stringify(
    {
      backupId: id,
      createdAt,
      createdByEmail: params.actor.email,
      reason: params.reason || 'Manual administrative snapshot',
      sha256,
      snapshot: store,
    },
    null,
    2
  );
  fs.writeFileSync(filePath, wrapper, 'utf-8');

  const stat = fs.statSync(filePath);
  const meta: BackupSnapshotMeta = {
    id,
    fileName,
    createdAt,
    createdByEmail: params.actor.email,
    reason: params.reason || 'Manual administrative snapshot',
    sizeBytes: stat.size,
    sha256,
    counts: {
      users: Object.keys(store.users).length,
      suppliers: Object.keys(store.suppliers).length,
      products: Object.keys(store.products).length,
      orders: Object.keys(store.orders).length,
      notifications: Object.keys(store.notifications).length,
      auditLogs: Object.keys(store.auditLogs).length,
    },
  };

  store.backups = [meta, ...(store.backups || [])];

  // Prune older backup files beyond backupsKeepCount
  const keepCount = Math.max(3, policy.backupsKeepCount || 15);
  if (store.backups.length > keepCount) {
    const dropped = store.backups.slice(keepCount);
    store.backups = store.backups.slice(0, keepCount);
    for (const oldMeta of dropped) {
      const oldPath = path.join(BACKUPS_DIR, oldMeta.fileName);
      if (fs.existsSync(oldPath)) {
        try {
          fs.unlinkSync(oldPath);
        } catch {
          // Ignore file unlink race
        }
      }
    }
  }

  await saveStore(store);
  await appendAuditLog({
    actorUid: params.actor.uid,
    actorEmail: params.actor.email,
    actorRole: params.actor.role,
    action: 'BACKUP_CREATED',
    targetType: 'backup',
    targetId: id,
    newValue: `${meta.counts.orders} orders, ${meta.counts.users} users, ${meta.counts.notifications} notifications`,
    outcome: 'SUCCESS',
    technicalRef: `sha256:${sha256.slice(0, 16)}`,
    details: `Created store snapshot ${fileName} (${meta.reason}).`,
  });

  return { meta, filePath };
}

export function listAvailableBackups(store: StoreSnapshot): BackupSnapshotMeta[] {
  ensureBackupsDir();
  const indexed = (store.backups || []).filter((b) =>
    fs.existsSync(path.join(BACKUPS_DIR, path.basename(b.fileName)))
  );
  return indexed.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function readBackupArchive(backupId: string): {
  meta: BackupSnapshotMeta;
  rawContent: string;
  snapshot: StoreSnapshot;
} | null {
  ensureBackupsDir();
  const safeName = `${backupId.replace(/[^a-zA-Z0-9_-]/g, '')}.json`;
  const filePath = path.join(BACKUPS_DIR, safeName);
  if (!fs.existsSync(filePath)) return null;

  const rawContent = fs.readFileSync(filePath, 'utf-8');
  const parsed = JSON.parse(rawContent) as {
    backupId: string;
    createdAt: string;
    createdByEmail: string;
    reason: string;
    sha256: string;
    snapshot: StoreSnapshot;
  };
  if (!parsed || !parsed.snapshot || !parsed.sha256) return null;

  const computedHash = crypto
    .createHash('sha256')
    .update(JSON.stringify(parsed.snapshot, null, 2), 'utf-8')
    .digest('hex');
  if (computedHash !== parsed.sha256) {
    throw new Error('Backup integrity verification failed (SHA-256 checksum mismatch).');
  }

  const stat = fs.statSync(filePath);
  const meta: BackupSnapshotMeta = {
    id: parsed.backupId,
    fileName: safeName,
    createdAt: parsed.createdAt,
    createdByEmail: parsed.createdByEmail,
    reason: parsed.reason,
    sizeBytes: stat.size,
    sha256: parsed.sha256,
    counts: {
      users: Object.keys(parsed.snapshot.users || {}).length,
      suppliers: Object.keys(parsed.snapshot.suppliers || {}).length,
      products: Object.keys(parsed.snapshot.products || {}).length,
      orders: Object.keys(parsed.snapshot.orders || {}).length,
      notifications: Object.keys(parsed.snapshot.notifications || {}).length,
      auditLogs: Object.keys(parsed.snapshot.auditLogs || {}).length,
    },
  };

  return { meta, rawContent, snapshot: parsed.snapshot };
}

export async function restoreStoreFromBackup(params: {
  backupId: string;
  actor: Pick<UserAccount, 'uid' | 'email' | 'role'>;
}): Promise<{ restoredMeta: BackupSnapshotMeta; safetyBackupId: string }> {
  const archive = readBackupArchive(params.backupId);
  if (!archive) {
    throw new Error('Backup snapshot not found or unreadable.');
  }

  // Always capture a pre-restore safety snapshot before overwriting active state
  const preRestore = await createStoreBackup({
    actor: params.actor,
    reason: `Automatic pre-restore safety snapshot before restoring ${archive.meta.id}`,
  });

  const currentStore = await getStore();
  const existingBackups = currentStore.backups || [];
  const restored = archive.snapshot;

  // Preserve backup catalog + audit trail entries written up to restoration
  const preservedAuditLogs = {
    ...(restored.auditLogs || {}),
    ...(currentStore.auditLogs || {}),
  };

  currentStore.users = restored.users || {};
  currentStore.suppliers = restored.suppliers || {};
  currentStore.products = restored.products || {};
  currentStore.productImages = restored.productImages || {};
  currentStore.orders = restored.orders || {};
  currentStore.suborders = restored.suborders || {};
  currentStore.payments = restored.payments || {};
  currentStore.paymentSubmissions = restored.paymentSubmissions || {};
  currentStore.paymentAuditLogs = restored.paymentAuditLogs || {};
  currentStore.commissionRules = restored.commissionRules || {};
  currentStore.payouts = restored.payouts || {};
  currentStore.refunds = restored.refunds || {};
  currentStore.reviews = restored.reviews || {};
  currentStore.coupons = restored.coupons || {};
  currentStore.shippingZones = restored.shippingZones || {};
  currentStore.tickets = restored.tickets || {};
  currentStore.notifications = restored.notifications || {};
  currentStore.notificationPreferences = restored.notificationPreferences || {};
  currentStore.activityEvents = restored.activityEvents || {};
  currentStore.userPreferences = restored.userPreferences || {};
  currentStore.aiReports = restored.aiReports || {};
  currentStore.newsletterSubscribers = restored.newsletterSubscribers || [];
  currentStore.wishlists = restored.wishlists || {};
  currentStore.settings = restored.settings || currentStore.settings;
  currentStore.retentionPolicy = restored.retentionPolicy || currentStore.retentionPolicy;
  currentStore.auditLogs = preservedAuditLogs;
  currentStore.backups = existingBackups;

  await saveStore(currentStore);

  await appendAuditLog({
    actorUid: params.actor.uid,
    actorEmail: params.actor.email,
    actorRole: params.actor.role,
    action: 'BACKUP_RESTORED',
    targetType: 'backup',
    targetId: archive.meta.id,
    newValue: `Restored ${archive.meta.counts.orders} orders & ${archive.meta.counts.users} users (safety backup: ${preRestore.meta.id})`,
    outcome: 'SUCCESS',
    technicalRef: `sha256:${archive.meta.sha256.slice(0, 16)}`,
    details: `Restored marketplace store from snapshot ${archive.meta.fileName}.`,
  });

  return {
    restoredMeta: archive.meta,
    safetyBackupId: preRestore.meta.id,
  };
}

export async function anonymizeUserForErasure(params: {
  targetUid: string;
  actor: Pick<UserAccount, 'uid' | 'email' | 'role'>;
  reason?: string;
}): Promise<{ user: UserAccount; anonymizedOrdersCount: number }> {
  const store = await getStore();
  const target = store.users[params.targetUid];
  if (!target) {
    throw new Error('Target user account not found.');
  }
  if (target.role === 'super_admin') {
    throw new Error('Super Admin accounts cannot be anonymized.');
  }

  const now = new Date().toISOString();
  const prevEmail = target.email;
  const anonToken = crypto.createHash('sha256').update(target.uid).digest('hex').slice(0, 10);
  const anonEmail = `erased_${anonToken}@redacted.tanzanite.local`;

  const updatedUser: UserAccount = {
    ...target,
    email: anonEmail,
    displayName: `Erased User #${anonToken.slice(0, 6).toUpperCase()}`,
    phone: '',
    addresses: [],
    status: 'suspended',
    personalizationEnabled: false,
    analyticsConsent: false,
    anonymizedAt: now,
    updatedAt: now,
  };
  await upsertUser(updatedUser);

  // Remove wishlist & personalization profile PII
  delete store.wishlists[target.uid];
  delete store.userPreferences[target.uid];

  // Redact customer personal contact info from historical orders while keeping immutable financial totals & suborder audit integrity
  let anonymizedOrdersCount = 0;
  for (const order of Object.values(store.orders)) {
    if (order.customerId === target.uid) {
      anonymizedOrdersCount += 1;
      order.customerEmail = anonEmail;
      order.submittedPayerName = 'Redacted Customer';
      order.submittedPayerPhone = '';
      order.shippingAddress = {
        ...order.shippingAddress,
        fullName: 'Redacted Customer',
        phone: 'Redacted',
        street: 'Redacted per privacy request',
      };
      order.updatedAt = now;
    }
  }
  for (const sub of Object.values(store.suborders)) {
    if (sub.customerId === target.uid) {
      sub.customerShippingName = 'Redacted Customer';
      sub.customerShippingPhone = 'Redacted';
      sub.customerShippingStreet = 'Redacted per privacy request';
      sub.updatedAt = now;
    }
  }
  for (const ps of Object.values(store.paymentSubmissions)) {
    if (ps.customerId === target.uid) {
      ps.customerEmail = anonEmail;
      ps.customerName = 'Redacted Customer';
      ps.senderName = 'Redacted Customer';
      ps.senderPhone = '';
    }
  }
  // Suspend supplier profile contact details if user was a supplier
  for (const sup of Object.values(store.suppliers)) {
    if (sup.ownerUid === target.uid) {
      sup.ownerFullName = 'Redacted Owner';
      sup.email = anonEmail;
      sup.phone = 'Redacted';
      sup.status = 'SUSPENDED';
      sup.updatedAt = now;
      await upsertSupplier(sup);
    }
  }

  await saveStore(store);

  await appendAuditLog({
    actorUid: params.actor.uid,
    actorEmail: params.actor.email,
    actorRole: params.actor.role,
    action: 'USER_PII_ANONYMIZED',
    targetType: 'user',
    targetId: target.uid,
    targetUserId: target.uid,
    previousValue: prevEmail,
    newValue: anonEmail,
    outcome: 'SUCCESS',
    details: `Anonymized personal PII for user ${target.uid} while preserving ${anonymizedOrdersCount} order financial/tax record(s). Reason: ${params.reason || 'Legal erasure request'}.`,
  });

  return { user: updatedUser, anonymizedOrdersCount };
}
