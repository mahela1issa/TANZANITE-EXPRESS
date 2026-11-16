import crypto from 'crypto';
import { EventEmitter } from 'events';
import fs from 'fs';
import path from 'path';
import { adminDb } from './firebase-admin.ts';
import {
  DEV_SEED_PRODUCTS,
  DEV_SEED_SUPPLIERS,
  INITIAL_COMMISSION_RULES,
  INITIAL_COUPONS,
  INITIAL_SETTINGS,
  INITIAL_SHIPPING_ZONES,
} from './seed-data.ts';
import {
  ActivityEvent,
  AiReportRecord,
  AuditLog,
  BackupSnapshotMeta,
  CommissionRule,
  Coupon,
  DataRetentionPolicy,
  MarketplaceSettings,
  NotificationItem,
  NotificationPreferences,
  NotificationPriority,
  NotificationType,
  Order,
  PaymentAuditLog,
  PaymentSubmission,
  PaymentTransaction,
  Product,
  ProductImageMeta,
  RefundRequest,
  Review,
  ShippingZone,
  SupplierPayout,
  SupplierProfile,
  SupplierSuborder,
  SupportTicket,
  UserAccount,
  UserPreferenceProfile,
} from '../types/marketplace.ts';

export interface StoreSnapshot {
  users: Record<string, UserAccount>;
  suppliers: Record<string, SupplierProfile>;
  products: Record<string, Product>;
  productImages: Record<string, ProductImageMeta>;
  orders: Record<string, Order>;
  suborders: Record<string, SupplierSuborder>;
  payments: Record<string, PaymentTransaction>;
  paymentSubmissions: Record<string, PaymentSubmission>;
  paymentAuditLogs: Record<string, PaymentAuditLog>;
  commissionRules: Record<string, CommissionRule>;
  payouts: Record<string, SupplierPayout>;
  refunds: Record<string, RefundRequest>;
  reviews: Record<string, Review>;
  coupons: Record<string, Coupon>;
  shippingZones: Record<string, ShippingZone>;
  tickets: Record<string, SupportTicket>;
  notifications: Record<string, NotificationItem>;
  notificationPreferences: Record<string, NotificationPreferences>;
  auditLogs: Record<string, AuditLog>;
  activityEvents: Record<string, ActivityEvent>;
  userPreferences: Record<string, UserPreferenceProfile>;
  aiReports: Record<string, AiReportRecord>;
  newsletterSubscribers: { email: string; market: string; createdAt: string }[];
  wishlists: Record<string, string[]>;
  settings: MarketplaceSettings;
  retentionPolicy?: DataRetentionPolicy;
  backups?: BackupSnapshotMeta[];
}

export const notificationEvents = new EventEmitter();
notificationEvents.setMaxListeners(500);

const DATA_DIR = path.resolve(process.cwd(), '.mik-data');
const DATA_FILE = path.join(DATA_DIR, 'marketplace-store.json');

function createInitialStore(): StoreSnapshot {
  const isDev = process.env.NODE_ENV !== 'production';
  const suppliers: Record<string, SupplierProfile> = {};
  const products: Record<string, Product> = {};
  const commissionRules: Record<string, CommissionRule> = {};
  const coupons: Record<string, Coupon> = {};
  const shippingZones: Record<string, ShippingZone> = {};

  for (const r of INITIAL_COMMISSION_RULES) commissionRules[r.id] = r;
  for (const c of INITIAL_COUPONS) coupons[c.id] = c;
  for (const z of INITIAL_SHIPPING_ZONES) shippingZones[z.id] = z;

  if (isDev) {
    for (const s of DEV_SEED_SUPPLIERS) suppliers[s.id] = s;
    for (const p of DEV_SEED_PRODUCTS) products[p.id] = p;
  }

  return {
    users: {},
    suppliers,
    products,
    productImages: {},
    orders: {},
    suborders: {},
    payments: {},
    paymentSubmissions: {},
    paymentAuditLogs: {},
    commissionRules,
    payouts: {},
    refunds: {},
    reviews: {},
    coupons,
    shippingZones,
    tickets: {},
    notifications: {},
    notificationPreferences: {},
    auditLogs: {},
    activityEvents: {},
    userPreferences: {},
    aiReports: {},
    newsletterSubscribers: [],
    wishlists: {},
    settings: INITIAL_SETTINGS,
    backups: [],
  };
}

let memoryStore: StoreSnapshot | null = null;
let firestoreAvailable: boolean | null = null;
let firestoreHydrated = false;

function loadLocalStore(): StoreSnapshot {
  if (memoryStore) return memoryStore;
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf-8');
      const parsed = JSON.parse(raw) as StoreSnapshot;
      parsed.productImages = parsed.productImages || {};
      parsed.paymentSubmissions = parsed.paymentSubmissions || {};
      parsed.paymentAuditLogs = parsed.paymentAuditLogs || {};
      parsed.notificationPreferences = parsed.notificationPreferences || {};
      parsed.notifications = parsed.notifications || {};
      parsed.activityEvents = parsed.activityEvents || {};
      parsed.userPreferences = parsed.userPreferences || {};
      parsed.aiReports = parsed.aiReports || {};

      // Normalize legacy notifications missing `type`
      for (const n of Object.values(parsed.notifications)) {
        if (!n.type) n.type = 'system';
      }

      const normalizeRecipient = (val: string | undefined, fallback: string): string => {
        const trimmed = (val || '').trim();
        if (!trimmed || trimmed === 'MIK FASHION HUB') return fallback;
        return trimmed;
      };
      const resolvedOfficialRecipient = normalizeRecipient(
        parsed.settings?.officialRecipientName ??
          parsed.settings?.mpesaAccountHolder ??
          parsed.settings?.manualPaymentAccountName,
        INITIAL_SETTINGS.officialRecipientName
      );

      // Normalize legacy MIK FASHION HUB branding fields cleanly while keeping user-edited custom titles
      const rawBrand = (parsed.settings?.brandName || '').trim();
      const brandName =
        !rawBrand || rawBrand.toUpperCase() === 'MIK FASHION HUB'
          ? INITIAL_SETTINGS.brandName
          : rawBrand;
      const rawSeoTitle = (parsed.settings?.seoTitle || '').trim();
      const seoTitle =
        !rawSeoTitle || rawSeoTitle.includes('MIK FASHION HUB')
          ? INITIAL_SETTINGS.seoTitle
          : rawSeoTitle;
      const rawSeoDesc = (parsed.settings?.seoDescription || '').trim();
      const seoDescription =
        !rawSeoDesc || rawSeoDesc.includes('MIK FASHION HUB')
          ? INITIAL_SETTINGS.seoDescription
          : rawSeoDesc;
      const rawHeroTitle = (parsed.settings?.heroTitle || '').trim();
      const heroTitle =
        !rawHeroTitle || rawHeroTitle.includes('MIK')
          ? INITIAL_SETTINGS.heroTitle
          : rawHeroTitle;

      parsed.settings = {
        ...INITIAL_SETTINGS,
        ...(parsed.settings || {}),
        brandName,
        heroTitle,
        seoTitle,
        seoDescription,
        manualPaymentPhone:
          parsed.settings?.mpesaPhone ??
          parsed.settings?.manualPaymentPhone ??
          INITIAL_SETTINGS.manualPaymentPhone,
        manualPaymentBankName:
          parsed.settings?.manualPaymentBankName || INITIAL_SETTINGS.manualPaymentBankName,
        manualPaymentBankAccount:
          parsed.settings?.nmbAccountNumber ??
          parsed.settings?.manualPaymentBankAccount ??
          INITIAL_SETTINGS.manualPaymentBankAccount,
        officialRecipientName: resolvedOfficialRecipient,
        manualPaymentAccountName: resolvedOfficialRecipient,
        mpesaEnabled: parsed.settings?.mpesaEnabled ?? INITIAL_SETTINGS.mpesaEnabled,
        mpesaPhone:
          parsed.settings?.mpesaPhone ??
          parsed.settings?.manualPaymentPhone ??
          INITIAL_SETTINGS.mpesaPhone,
        mpesaAccountHolder: normalizeRecipient(
          parsed.settings?.mpesaAccountHolder ?? parsed.settings?.manualPaymentAccountName,
          resolvedOfficialRecipient
        ),
        mpesaInstructions:
          parsed.settings?.mpesaInstructions || INITIAL_SETTINGS.mpesaInstructions,
        nmbEnabled: parsed.settings?.nmbEnabled ?? INITIAL_SETTINGS.nmbEnabled,
        nmbAccountName: normalizeRecipient(
          parsed.settings?.nmbAccountName ?? parsed.settings?.manualPaymentAccountName,
          resolvedOfficialRecipient
        ),
        nmbAccountNumber:
          parsed.settings?.nmbAccountNumber ??
          parsed.settings?.manualPaymentBankAccount ??
          INITIAL_SETTINGS.nmbAccountNumber,
        nmbBranch: parsed.settings?.nmbBranch || INITIAL_SETTINGS.nmbBranch,
        nmbInstructions: parsed.settings?.nmbInstructions || INITIAL_SETTINGS.nmbInstructions,
        autoReleaseSubordersOnPaymentConfirm:
          parsed.settings?.autoReleaseSubordersOnPaymentConfirm ??
          INITIAL_SETTINGS.autoReleaseSubordersOnPaymentConfirm,
        announcementTextSw: parsed.settings?.announcementTextSw || INITIAL_SETTINGS.announcementTextSw,
        heroTitleSw: parsed.settings?.heroTitleSw || INITIAL_SETTINGS.heroTitleSw,
        heroSubtitleSw: parsed.settings?.heroSubtitleSw || INITIAL_SETTINGS.heroSubtitleSw,
        heroCtaTextSw: parsed.settings?.heroCtaTextSw || INITIAL_SETTINGS.heroCtaTextSw,
        currencyRates: {
          ...INITIAL_SETTINGS.currencyRates,
          ...(parsed.settings?.currencyRates || {}),
        },
        socialLinks: {
          ...INITIAL_SETTINGS.socialLinks,
          ...(parsed.settings?.socialLinks || {}),
        },
      };

      // Ensure TANZANITE10 coupon is available if not already added
      if (!parsed.coupons) parsed.coupons = {};
      for (const c of INITIAL_COUPONS) {
        if (!parsed.coupons[c.id]) {
          parsed.coupons[c.id] = c;
        }
      }

      memoryStore = parsed;
      return memoryStore;
    }
  } catch {
    // Fall back to fresh snapshot
  }
  memoryStore = createInitialStore();
  persistLocalStore(memoryStore);
  return memoryStore;
}

function persistLocalStore(store: StoreSnapshot) {
  memoryStore = store;
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const tmpFile = `${DATA_FILE}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(store, null, 2), 'utf-8');
    fs.renameSync(tmpFile, DATA_FILE);
  } catch (err) {
    console.warn('Local persistence write skipped:', err);
  }
}

async function syncCollectionToFirestore<T extends object>(
  collectionName: string,
  recordId: string,
  data: T
) {
  if (firestoreAvailable === false) return;
  try {
    await adminDb
      .collection(collectionName)
      .doc(recordId)
      .set(data as Record<string, unknown>, { merge: true });
    firestoreAvailable = true;
  } catch {
    // In headless/local environments without GCP ADC credentials, run reliably on local store
    if (firestoreAvailable === null) {
      firestoreAvailable = false;
    }
  }
}

/**
 * Hydrates store collections from Firestore on startup if Cloud credentials are available,
 * without overwriting or crashing when running locally without GCP ADC.
 */
export async function initializeStoreWithFirestore(): Promise<StoreSnapshot> {
  const store = loadLocalStore();
  if (firestoreHydrated || firestoreAvailable === false) {
    return store;
  }
  firestoreHydrated = true;

  try {
    const collections: [string, keyof StoreSnapshot][] = [
      ['users', 'users'],
      ['suppliers', 'suppliers'],
      ['products', 'products'],
      ['product_images', 'productImages'],
      ['orders', 'orders'],
      ['suborders', 'suborders'],
      ['payments', 'payments'],
      ['payment_submissions', 'paymentSubmissions'],
      ['payment_audit_logs', 'paymentAuditLogs'],
      ['refund_requests', 'refunds'],
      ['support_tickets', 'tickets'],
      ['notifications', 'notifications'],
      ['notification_preferences', 'notificationPreferences'],
      ['audit_logs', 'auditLogs'],
      ['activity_events', 'activityEvents'],
      ['user_preferences', 'userPreferences'],
      ['ai_reports', 'aiReports'],
      ['supplier_payouts', 'payouts'],
    ];

    // Probe settings first to test Firestore connectivity quickly
    const settingsDoc = await adminDb.collection('marketplace_settings').doc('default').get();
    firestoreAvailable = true;
    if (settingsDoc.exists) {
      const remoteSettings = settingsDoc.data() as Partial<MarketplaceSettings>;
      if (remoteSettings && (!store.settings.updatedAt || (remoteSettings.updatedAt && remoteSettings.updatedAt > store.settings.updatedAt))) {
        store.settings = { ...store.settings, ...remoteSettings };
      }
    }

    for (const [colName, key] of collections) {
      const snap = await adminDb.collection(colName).get();
      if (!snap.empty) {
        const target = store[key] as Record<string, any>;
        snap.forEach((doc) => {
          if (!target[doc.id]) {
            target[doc.id] = doc.data();
          }
        });
      }
    }
    persistLocalStore(store);
  } catch {
    firestoreAvailable = false;
  }
  return store;
}

export async function getStore(): Promise<StoreSnapshot> {
  return loadLocalStore();
}

export async function saveStore(store: StoreSnapshot): Promise<void> {
  persistLocalStore(store);
}

export async function upsertUser(user: UserAccount): Promise<UserAccount> {
  const store = await getStore();
  store.users[user.uid] = user;
  await saveStore(store);
  await syncCollectionToFirestore('users', user.uid, {
    uid: user.uid,
    displayName: user.displayName,
    role: user.role,
    status: user.status,
    preferredCurrency: user.preferredCurrency,
    preferredCountry: user.preferredCountry,
    personalizationEnabled: user.personalizationEnabled ?? true,
    analyticsConsent: user.analyticsConsent ?? true,
    lastLoginAt: user.lastLoginAt || null,
    loginCount: user.loginCount || 0,
    erasureRequestedAt: user.erasureRequestedAt || null,
    anonymizedAt: user.anonymizedAt || null,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  });
  await syncCollectionToFirestore(`users/${user.uid}/private`, 'info', {
    uid: user.uid,
    email: user.email,
    phone: user.phone || '',
    addresses: user.addresses || [],
    updatedAt: user.updatedAt,
  });
  return user;
}

export async function upsertSupportTicket(ticket: SupportTicket): Promise<SupportTicket> {
  const store = await getStore();
  store.tickets[ticket.id] = ticket;
  await saveStore(store);
  await syncCollectionToFirestore('support_tickets', ticket.id, ticket);
  return ticket;
}

export async function upsertRefundRequest(refund: RefundRequest): Promise<RefundRequest> {
  const store = await getStore();
  store.refunds[refund.id] = refund;
  await saveStore(store);
  await syncCollectionToFirestore('refund_requests', refund.id, refund);
  return refund;
}

export async function upsertSupplierPayout(payout: SupplierPayout): Promise<SupplierPayout> {
  const store = await getStore();
  store.payouts[payout.id] = payout;
  await saveStore(store);
  await syncCollectionToFirestore('supplier_payouts', payout.id, payout);
  return payout;
}

export async function upsertReviewRecord(review: Review): Promise<Review> {
  const store = await getStore();
  store.reviews[review.id] = review;
  await saveStore(store);
  await syncCollectionToFirestore('reviews', review.id, review);
  return review;
}

export async function syncWishlistForUser(uid: string, productIds: string[]): Promise<void> {
  const store = await getStore();
  store.wishlists[uid] = productIds;
  await saveStore(store);
  await syncCollectionToFirestore('wishlists', uid, {
    uid,
    productIds,
    updatedAt: new Date().toISOString(),
  });
}

export async function upsertRetentionPolicy(
  policy: DataRetentionPolicy
): Promise<DataRetentionPolicy> {
  const store = await getStore();
  store.retentionPolicy = policy;
  await saveStore(store);
  await syncCollectionToFirestore('marketplace_settings', 'retention_policy', policy);
  return policy;
}

export async function upsertActivityEvent(event: ActivityEvent): Promise<ActivityEvent> {
  const store = await getStore();
  store.activityEvents[event.id] = event;
  // Cap local event history to 4000 most recent events to keep JSON store fast
  const keys = Object.keys(store.activityEvents);
  if (keys.length > 4000) {
    const sorted = keys.sort(
      (a, b) =>
        new Date(store.activityEvents[a].createdAt).getTime() -
        new Date(store.activityEvents[b].createdAt).getTime()
    );
    for (const oldKey of sorted.slice(0, keys.length - 4000)) {
      delete store.activityEvents[oldKey];
    }
  }
  await saveStore(store);
  await syncCollectionToFirestore('activity_events', event.id, event);
  return event;
}

export async function upsertUserPreferenceProfile(
  profile: UserPreferenceProfile
): Promise<UserPreferenceProfile> {
  const store = await getStore();
  store.userPreferences[profile.uid] = profile;
  await saveStore(store);
  await syncCollectionToFirestore('user_preferences', profile.uid, profile);
  return profile;
}

export async function upsertAiReport(report: AiReportRecord): Promise<AiReportRecord> {
  const store = await getStore();
  store.aiReports[report.id] = report;
  await saveStore(store);
  await syncCollectionToFirestore('ai_reports', report.id, report);
  return report;
}

export async function upsertMarketplaceSettings(
  settings: MarketplaceSettings
): Promise<MarketplaceSettings> {
  const store = await getStore();
  store.settings = settings;
  await saveStore(store);
  await syncCollectionToFirestore('marketplace_settings', 'default', settings);
  return settings;
}

export async function upsertSupplier(supplier: SupplierProfile): Promise<SupplierProfile> {
  const store = await getStore();
  store.suppliers[supplier.id] = supplier;
  await saveStore(store);
  await syncCollectionToFirestore('suppliers', supplier.id, supplier);
  return supplier;
}

export async function upsertProduct(product: Product): Promise<Product> {
  const store = await getStore();
  store.products[product.id] = product;
  await saveStore(store);
  await syncCollectionToFirestore('products', product.id, product);
  return product;
}

export async function deleteProductRecord(productId: string): Promise<void> {
  const store = await getStore();
  delete store.products[productId];
  await saveStore(store);
  if (firestoreAvailable !== false) {
    try {
      await adminDb.collection('products').doc(productId).delete();
    } catch {
      // Ignore in offline/headless mode
    }
  }
}

export async function upsertProductImage(meta: ProductImageMeta): Promise<ProductImageMeta> {
  const store = await getStore();
  store.productImages[meta.id] = meta;
  await saveStore(store);
  await syncCollectionToFirestore('product_images', meta.id, meta);
  return meta;
}

export async function deleteProductImageRecord(imageId: string): Promise<void> {
  const store = await getStore();
  delete store.productImages[imageId];
  await saveStore(store);
  if (firestoreAvailable !== false) {
    try {
      await adminDb.collection('product_images').doc(imageId).delete();
    } catch {
      // Ignore in offline/headless mode
    }
  }
}

export async function upsertOrder(order: Order): Promise<Order> {
  const store = await getStore();
  store.orders[order.id] = order;
  await saveStore(store);
  await syncCollectionToFirestore('orders', order.id, order);
  return order;
}

export async function upsertSuborder(suborder: SupplierSuborder): Promise<SupplierSuborder> {
  const store = await getStore();
  store.suborders[suborder.id] = suborder;
  await saveStore(store);
  await syncCollectionToFirestore('suborders', suborder.id, suborder);
  return suborder;
}

export async function upsertPayment(payment: PaymentTransaction): Promise<PaymentTransaction> {
  const store = await getStore();
  store.payments[payment.id] = payment;
  await saveStore(store);
  await syncCollectionToFirestore('payments', payment.id, payment);
  return payment;
}

export async function upsertPaymentSubmission(
  submission: PaymentSubmission
): Promise<PaymentSubmission> {
  const store = await getStore();
  store.paymentSubmissions[submission.id] = submission;
  await saveStore(store);
  // Store metadata in Firestore without dumping large raw receipt image blobs in collection queries
  const { receiptImageDataUrl: _omit, ...metadata } = submission;
  await syncCollectionToFirestore('payment_submissions', submission.id, metadata);
  return submission;
}

export async function appendPaymentAuditLog(params: {
  paymentId: string;
  submissionId?: string;
  orderId: string;
  action: PaymentAuditLog['action'];
  previousStatus: string;
  newStatus: string;
  actorUid: string;
  actorEmail: string;
  actorRole: string;
  reason?: string;
  metadata?: Record<string, string | number | boolean>;
}): Promise<PaymentAuditLog> {
  const store = await getStore();
  const id = `pal_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const entry: PaymentAuditLog = {
    id,
    ...params,
    createdAt: new Date().toISOString(),
  };
  store.paymentAuditLogs[id] = entry;
  await saveStore(store);
  await syncCollectionToFirestore('payment_audit_logs', id, entry);
  return entry;
}

export async function appendAuditLog(params: {
  actorUid: string;
  actorEmail: string;
  actorRole: string;
  action: string;
  targetType: string;
  targetId: string;
  targetUserId?: string;
  relatedOrderId?: string;
  previousValue?: string;
  newValue?: string;
  outcome?: 'SUCCESS' | 'FAILURE' | 'BLOCKED';
  technicalRef?: string;
  details: string;
}): Promise<AuditLog> {
  const store = await getStore();
  const id = `log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const entry: AuditLog = {
    id,
    actorUid: params.actorUid,
    actorEmail: params.actorEmail,
    actorRole: params.actorRole,
    action: params.action,
    targetType: params.targetType,
    targetId: params.targetId,
    ...(params.targetUserId ? { targetUserId: params.targetUserId } : {}),
    ...(params.relatedOrderId ? { relatedOrderId: params.relatedOrderId } : {}),
    ...(params.previousValue !== undefined ? { previousValue: params.previousValue } : {}),
    ...(params.newValue !== undefined ? { newValue: params.newValue } : {}),
    ...(params.outcome ? { outcome: params.outcome } : { outcome: 'SUCCESS' }),
    ...(params.technicalRef ? { technicalRef: params.technicalRef } : {}),
    details: params.details,
    createdAt: new Date().toISOString(),
  };
  store.auditLogs[id] = entry;
  await saveStore(store);
  await syncCollectionToFirestore('audit_logs', id, entry);
  return entry;
}

export function getUserNotificationPreferences(
  store: StoreSnapshot,
  uid: string
): NotificationPreferences {
  return (
    store.notificationPreferences[uid] || {
      uid,
      inAppEnabled: true,
      emailEnabled: true,
      mutedTypes: [],
      updatedAt: new Date().toISOString(),
    }
  );
}

export async function upsertNotificationPreferences(
  prefs: NotificationPreferences
): Promise<NotificationPreferences> {
  const store = await getStore();
  store.notificationPreferences[prefs.uid] = prefs;
  await saveStore(store);
  await syncCollectionToFirestore('notification_preferences', prefs.uid, prefs);
  return prefs;
}

export async function createNotification(params: {
  recipientUid: string;
  type?: NotificationType;
  priority?: NotificationPriority;
  dedupeKey?: string;
  title: string;
  message: string;
  channel?: 'in_app' | 'email' | 'whatsapp';
  targetType?: NotificationItem['targetType'];
  targetId?: string;
  link?: string;
  actionLabel?: string;
}): Promise<NotificationItem | null> {
  const store = await getStore();
  const type: NotificationType = params.type || 'system';
  const prefs = getUserNotificationPreferences(store, params.recipientUid);

  // Critical security and payment alerts are always delivered in-app; user mutes apply cleanly to non-security alerts
  if (!prefs.inAppEnabled && type !== 'security' && type !== 'payment') {
    return null;
  }
  if (prefs.mutedTypes.includes(type) && type !== 'security' && type !== 'payment') {
    return null;
  }

  // Event deduplication to avoid duplicate alerts for repeated status polls/retries
  if (params.dedupeKey) {
    const existingDup = Object.values(store.notifications).find(
      (n) =>
        n.recipientUid === params.recipientUid &&
        n.dedupeKey === params.dedupeKey &&
        !n.hiddenByRecipient
    );
    if (existingDup) {
      return existingDup;
    }
  }

  const defaultPriority: NotificationPriority =
    params.priority ||
    (type === 'security' || type === 'return'
      ? 'urgent'
      : type === 'payment' || type === 'order'
      ? 'high'
      : 'normal');

  const id = `ntf_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const item: NotificationItem = {
    id,
    recipientUid: params.recipientUid,
    type,
    priority: defaultPriority,
    ...(params.dedupeKey ? { dedupeKey: params.dedupeKey } : {}),
    title: params.title,
    message: params.message,
    channel: params.channel || 'in_app',
    read: false,
    targetType: params.targetType,
    targetId: params.targetId,
    link: params.link,
    ...(params.actionLabel ? { actionLabel: params.actionLabel } : {}),
    createdAt: new Date().toISOString(),
  };
  store.notifications[id] = item;
  await saveStore(store);
  await syncCollectionToFirestore('notifications', id, item);

  // Emit real-time event for active SSE subscribers
  notificationEvents.emit(`user:${params.recipientUid}`, item);
  return item;
}

export async function markNotificationAsRead(
  uid: string,
  notificationId: string
): Promise<NotificationItem | null> {
  const store = await getStore();
  const item = store.notifications[notificationId];
  if (!item || item.recipientUid !== uid) return null;
  if (!item.read) {
    const readAt = new Date().toISOString();
    item.read = true;
    item.readAt = readAt;
    await saveStore(store);
    await syncCollectionToFirestore('notifications', item.id, { read: true, readAt });
    notificationEvents.emit(`sync:${uid}`, { reason: 'read', notificationId });
  }
  return item;
}

export async function markAllNotificationsAsReadForUser(uid: string): Promise<number> {
  const store = await getStore();
  const readAt = new Date().toISOString();
  let updatedCount = 0;
  for (const n of Object.values(store.notifications)) {
    if (n.recipientUid === uid && !n.read && !n.hiddenByRecipient) {
      n.read = true;
      n.readAt = readAt;
      updatedCount += 1;
      await syncCollectionToFirestore('notifications', n.id, { read: true, readAt });
    }
  }
  if (updatedCount > 0) {
    await saveStore(store);
    notificationEvents.emit(`sync:${uid}`, { reason: 'read_all' });
  }
  return updatedCount;
}

export async function hideNotificationForUser(
  uid: string,
  notificationId: string,
  actor?: { email: string; role: string }
): Promise<NotificationItem | null> {
  const store = await getStore();
  const item = store.notifications[notificationId];
  if (!item || item.recipientUid !== uid) return null;

  const now = new Date().toISOString();
  if (!item.hiddenByRecipient) {
    item.hiddenByRecipient = true;
    item.hiddenAt = now;
    if (!item.read) {
      item.read = true;
      item.readAt = now;
    }
    await saveStore(store);
    await syncCollectionToFirestore('notifications', item.id, {
      hiddenByRecipient: true,
      hiddenAt: now,
      read: true,
      readAt: item.readAt,
    });

    await appendAuditLog({
      actorUid: uid,
      actorEmail: actor?.email || store.users[uid]?.email || uid,
      actorRole: actor?.role || store.users[uid]?.role || 'customer',
      action: 'NOTIFICATION_HIDDEN_BY_USER',
      targetType: 'notification',
      targetId: item.id,
      targetUserId: uid,
      relatedOrderId: item.targetType === 'order' ? item.targetId : undefined,
      details: `User hid notification "${item.title}" (${item.type}) from personal inbox; underlying record & audit trail preserved.`,
    });

    notificationEvents.emit(`sync:${uid}`, { reason: 'hidden', notificationId });
  }
  return item;
}

export async function clearVisibleNotificationsForUser(
  uid: string,
  actor?: { email: string; role: string }
): Promise<number> {
  const store = await getStore();
  const now = new Date().toISOString();
  let clearedCount = 0;

  for (const item of Object.values(store.notifications)) {
    if (item.recipientUid === uid && !item.hiddenByRecipient) {
      item.hiddenByRecipient = true;
      item.hiddenAt = now;
      if (!item.read) {
        item.read = true;
        item.readAt = now;
      }
      clearedCount += 1;
      await syncCollectionToFirestore('notifications', item.id, {
        hiddenByRecipient: true,
        hiddenAt: now,
        read: true,
        readAt: item.readAt,
      });
    }
  }

  if (clearedCount > 0) {
    await saveStore(store);
    await appendAuditLog({
      actorUid: uid,
      actorEmail: actor?.email || store.users[uid]?.email || uid,
      actorRole: actor?.role || store.users[uid]?.role || 'customer',
      action: 'NOTIFICATION_CLEARED_BY_USER',
      targetType: 'notification',
      targetId: uid,
      targetUserId: uid,
      details: `User cleared ${clearedCount} notification(s) from personal inbox view; underlying records & audit logs preserved.`,
    });
    notificationEvents.emit(`sync:${uid}`, { reason: 'cleared', clearedCount });
  }
  return clearedCount;
}

export function generateId(prefix: string): string {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
}
