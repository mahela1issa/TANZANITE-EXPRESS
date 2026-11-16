import 'dotenv/config';
import express from 'express';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import http from 'http';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { z } from 'zod';
import {
  computeAdminAnalytics,
  computeSupplierAnalytics,
  getRecommendationsForUser,
  rebuildUserPreferenceProfile,
  recordActivityEvent,
} from './src/server/analytics-engine.ts';
import {
  AuthRequest,
  hasPaymentVerificationAccess,
  optionalAuth,
  requireAuth,
  requirePaymentVerifier,
  requireRoles,
  resolveUserFromToken,
} from './src/server/auth-middleware.ts';
import { bootstrapSuperAdmin, getAdminBootstrapStatus } from './src/server/bootstrap-admin.ts';
import {
  getPaymentGatewaysStatus,
  getSupplierIntegrationsStatus,
} from './src/server/gateways.ts';
import {
  generateAdminAiReport,
  generateSupplierAiReport,
  generateSupportAssistantReply,
  isGeminiConfigured,
} from './src/server/gemini-service.ts';
import {
  calculateSupplierEarningsSummary,
  computeOverallOrderStatus,
  isProductLiveOnStorefront,
  parseCsvProducts,
  resolveCommissionRatePct,
  round2,
  toCsv,
  UploadedCsvImageRef,
  validateAndPreviewCsvProducts,
} from './src/server/marketplace-engine.ts';
import {
  AllowedImageMime,
  deleteProductImageFile,
  detectImageMimeFromBuffer,
  extractMediaIdFromUrl,
  findOrphanedMediaIds,
  MAX_PRODUCT_IMAGE_BYTES,
  readProductImageFile,
  sanitizeFileName,
  saveProductImageFile,
} from './src/server/media-storage.ts';
import {
  getAdminUids,
  getAllStaffAndAdminUids,
  reviewPaymentSubmission,
  sanitizeSubmissionForClient,
  submitManualPaymentProof,
} from './src/server/payment-verification.ts';
import {
  anonymizeUserForErasure,
  createStoreBackup,
  getEffectiveRetentionPolicy,
  listAvailableBackups,
  readBackupArchive,
  restoreStoreFromBackup,
} from './src/server/retention-backup.ts';
import { MEN_CATEGORIES, WOMEN_CATEGORIES } from './src/server/seed-data.ts';
import {
  appendAuditLog,
  appendPaymentAuditLog,
  clearVisibleNotificationsForUser,
  createNotification,
  deleteProductImageRecord,
  deleteProductRecord,
  generateId,
  getStore,
  getUserNotificationPreferences,
  hideNotificationForUser,
  initializeStoreWithFirestore,
  markAllNotificationsAsReadForUser,
  markNotificationAsRead,
  notificationEvents,
  saveStore,
  syncWishlistForUser,
  upsertAiReport,
  upsertMarketplaceSettings,
  upsertNotificationPreferences,
  upsertOrder,
  upsertPayment,
  upsertProduct,
  upsertProductImage,
  upsertRefundRequest,
  upsertRetentionPolicy,
  upsertReviewRecord,
  upsertSuborder,
  upsertSupplier,
  upsertSupplierPayout,
  upsertSupportTicket,
  upsertUser,
} from './src/server/store.ts';
import {
  ActivityEventType,
  AiReportRecord,
  NotificationItem,
  NotificationType,
  Order,
  OrderStatus,
  PaymentTransaction,
  Product,
  ProductImageMeta,
  ProductStatus,
  RefundRequest,
  Review,
  SupplierPayout,
  SupplierProfile,
  SupplierSuborder,
  SupportTicket,
} from './src/types/marketplace.ts';

const PORT = 3000;

function extractClientIp(req: express.Request): string {
  const forwarded = req.headers.forwarded;
  if (typeof forwarded === 'string') {
    const match = forwarded.match(/for=(?:"\[?([^;"\]]+)\]?"|([^;,\s]+))/i);
    const rawFor = (match?.[1] || match?.[2] || '').trim();
    if (rawFor && rawFor.toLowerCase() !== 'unknown' && !rawFor.startsWith('_')) {
      return rawFor.replace(/^(\d+\.\d+\.\d+\.\d+):\d+$/, '$1');
    }
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

async function startServer() {
  await initializeStoreWithFirestore();
  await bootstrapSuperAdmin();

  const app = express();
  // Trust the first reverse-proxy hop (e.g., Cloud Run load balancer)
  app.set('trust proxy', 1);

  // Security headers & JSON parsing
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  app.use(express.json({ limit: '4mb' }));

  const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 180,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(extractClientIp(req)),
  });
  app.use('/api/', apiLimiter);

  // ------------------------------------------------------------------
  // 1. PUBLIC STOREFRONT & CATALOG API
  // ------------------------------------------------------------------
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'TANZANITE EXPRESS API',
      environment: process.env.NODE_ENV || 'development',
    });
  });

  app.get('/api/storefront/bootstrap', async (_req, res) => {
    const store = await getStore();
    const approvedSuppliers = Object.values(store.suppliers)
      .filter((s) => s.status === 'APPROVED')
      .map((s) => ({
        id: s.id,
        businessName: s.businessName,
        country: s.country,
        category: s.category,
        description: s.description,
        shippingOrigin: s.shippingOrigin,
        subscriptionPlan: s.subscriptionPlan,
        isDevelopmentSeed: s.isDevelopmentSeed,
      }));

    const approvedProducts = Object.values(store.products).filter((p) =>
      isProductLiveOnStorefront(p)
    );

    const reviews = Object.values(store.reviews);

    res.json({
      isDevelopmentMode: process.env.NODE_ENV !== 'production',
      settings: store.settings,
      categories: {
        MEN: MEN_CATEGORIES,
        WOMEN: WOMEN_CATEGORIES,
      },
      suppliers: approvedSuppliers,
      products: approvedProducts,
      reviews,
      shippingZones: Object.values(store.shippingZones),
      paymentGateways: getPaymentGatewaysStatus(store.settings),
    });
  });

  app.get('/api/products/:idOrSlug', optionalAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const key = req.params.idOrSlug;
    const product =
      store.products[key] ||
      Object.values(store.products).find((p) => p.slug === key);

    if (!product || !isProductLiveOnStorefront(product)) {
      return res.status(404).json({ error: 'Product not found' });
    }

    await recordActivityEvent(store, {
      userId: req.authUser?.uid,
      type: 'product_view',
      productId: product.id,
      supplierId: product.supplierId,
      category: product.category,
      gender: product.gender,
      priceUsd: product.sellingPriceUsd,
      source: 'product_detail_api',
    });

    const productReviews = Object.values(store.reviews).filter(
      (r) => r.productId === product.id
    );
    const related = Object.values(store.products)
      .filter(
        (p) =>
          isProductLiveOnStorefront(p) &&
          p.id !== product.id &&
          (p.category === product.category || p.gender === product.gender)
      )
      .slice(0, 4);

    res.json({ product, reviews: productReviews, related });
  });

  // Activity Tracking & Real Personalized Recommendations
  app.post('/api/analytics/event', optionalAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      sessionId: z.string().max(120).optional(),
      type: z.enum([
        'product_view',
        'search',
        'category_visit',
        'wishlist_add',
        'cart_add',
        'cart_remove',
        'checkout_start',
        'purchase',
        'review',
        'recommendation_click',
        'fulfillment_event',
      ]),
      productId: z.string().max(128).optional(),
      supplierId: z.string().max(128).optional(),
      category: z.string().max(80).optional(),
      gender: z.enum(['MEN', 'WOMEN', 'UNISEX']).optional(),
      query: z.string().max(140).optional(),
      priceUsd: z.number().nonnegative().optional(),
      size: z.string().max(32).optional(),
      color: z.string().max(32).optional(),
      source: z.string().max(64).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid analytics event payload' });
    }
    const store = await getStore();
    const product = parsed.data.productId ? store.products[parsed.data.productId] : undefined;
    const recorded = await recordActivityEvent(store, {
      userId: req.authUser?.uid,
      sessionId: parsed.data.sessionId,
      type: parsed.data.type as ActivityEventType,
      productId: parsed.data.productId,
      supplierId: parsed.data.supplierId || product?.supplierId,
      category: parsed.data.category || product?.category,
      gender: parsed.data.gender || product?.gender,
      query: parsed.data.query,
      priceUsd: parsed.data.priceUsd ?? product?.sellingPriceUsd,
      size: parsed.data.size,
      color: parsed.data.color,
      source: parsed.data.source,
    });
    res.json({ recorded: Boolean(recorded), eventId: recorded?.id });
  });

  app.get('/api/recommendations', optionalAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const anchorProductId =
      typeof req.query.productId === 'string' ? req.query.productId.trim() : undefined;
    const recentRaw =
      typeof req.query.recentIds === 'string' ? req.query.recentIds : '';
    const sessionViewedIds = recentRaw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 12);

    const recs = await getRecommendationsForUser(store, {
      userId: req.authUser?.uid,
      anchorProductId,
      sessionViewedIds,
    });
    res.json(recs);
  });

  const supportAssistantLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 25,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(extractClientIp(req)),
    message: {
      error: 'Too many chat requests. Please wait a moment before sending another message.',
    },
  });

  // Customer Support AI Assistant (strictly separated from support ticket validation)
  app.post(
    '/api/support/assistant',
    supportAssistantLimiter,
    optionalAuth,
    async (req: AuthRequest, res) => {
      const questionSchema = z.object({
        question: z.string().trim().min(1).max(600),
        language: z.enum(['en', 'sw']).default('en'),
      });
      const parsedQuestion = questionSchema.safeParse({
        question: req.body?.question,
        language: req.body?.language,
      });
      if (!parsedQuestion.success) {
        return res.status(400).json({
          error:
            req.body?.language === 'sw'
              ? 'Tafadhali andika ujumbe wenye herufi 1 hadi 600.'
              : 'Please enter a valid chat message (1–600 characters).',
          isValidationError: true,
        });
      }

      // Safely normalize conversation history without ever failing a valid conversational turn if an AI turn exceeded 800 chars
      const rawHistory = Array.isArray(req.body?.history) ? req.body.history : [];
      const sanitizedHistory: { role: 'user' | 'assistant'; text: string }[] = rawHistory
        .slice(-12)
        .filter(
          (item: any) =>
            item &&
            (item.role === 'user' || item.role === 'assistant') &&
            typeof item.text === 'string' &&
            item.text.trim().length > 0
        )
        .map((item: any) => ({
          role: item.role as 'user' | 'assistant',
          text: String(item.text).trim().slice(0, 2000),
        }));
      const parsed = {
        data: {
          question: parsedQuestion.data.question,
          language: parsedQuestion.data.language,
          history: sanitizedHistory,
        },
      };

      const store = await getStore();
      const tzsRate = store.settings.currencyRates?.TZS || 2650;
      const liveProducts = Object.values(store.products).filter(
        (p) => isProductLiveOnStorefront(p) && p.totalStock > 0
      );

      // Keyword search against live published catalog
      const queryTokens = parsed.data.question
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, ' ')
        .split(/\s+/)
        .filter((w) => w.length >= 3);

      const scoredProducts = liveProducts
        .map((p) => {
          const haystack = `${p.title} ${p.category} ${p.gender} ${p.brand} ${p.description}`.toLowerCase();
          const score = queryTokens.reduce((acc, tok) => (haystack.includes(tok) ? acc + 1 : acc), 0);
          return { p, score };
        })
        .sort((a, b) => b.score - a.score || (b.p.featured ? 1 : 0) - (a.p.featured ? 1 : 0));

      const matchedProducts = scoredProducts.filter((x) => x.score > 0).slice(0, 6);
      const catalogHighlight = (matchedProducts.length > 0 ? matchedProducts : scoredProducts.slice(0, 5))
        .map(({ p }) => {
          const tzsPrice = Math.round(p.sellingPriceUsd * tzsRate).toLocaleString('en-US');
          const sizes = Array.from(new Set(p.variants.map((v) => v.size))).join(', ');
          const colors = Array.from(new Set(p.variants.map((v) => v.color))).join(', ');
          return `- ${p.title} (${p.gender} / ${p.category}): $${p.sellingPriceUsd} USD (~TZS ${tzsPrice}), Stock=${p.totalStock}, Sizes=[${sizes}], Colors=[${colors}], Delivery=${p.estimatedDaysMin}-${p.estimatedDaysMax} days`;
        })
        .join('\n');

      const categoryCounts = liveProducts.reduce<Record<string, number>>((acc, p) => {
        const key = `${p.gender}:${p.category}`;
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {});

      const activeGateways = getPaymentGatewaysStatus(store.settings)
        .filter((g) => g.enabledForCheckout)
        .map((g) => {
          if (g.id === 'manual_mobile') {
            return `M-Pesa Tanzania: Number=${g.accountDetails?.phone}, Account Holder=${g.accountDetails?.accountName}`;
          }
          return `NMB Bank Transfer: Account=${g.accountDetails?.bankAccount}, Branch=${g.accountDetails?.bankBranch || 'Main'}, Account Name=${g.accountDetails?.accountName}`;
        })
        .join(' | ');

      let roleScopedContext = 'Customer is browsing as guest (no personal order details available).';
      if (req.authUser) {
        if (req.authUser.role === 'customer') {
          const userOrdersSummary = Object.values(store.orders)
            .filter((o) => o.customerId === req.authUser!.uid)
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
            .slice(0, 5)
            .map(
              (o) =>
                `Order ${o.id}: Status=${o.overallStatus}, Payment=${o.paymentStatus}, Total=${o.currency} ${o.totalDisplay}, Provider=${o.paymentProvider}`
            );
          roleScopedContext = `Signed-in Customer Own Orders (${req.authUser.email}): ${
            userOrdersSummary.length ? userOrdersSummary.join(' | ') : 'No orders placed yet.'
          }`;
        } else if (req.authUser.role === 'supplier') {
          const sup = Object.values(store.suppliers).find((s) => s.ownerUid === req.authUser!.uid);
          const ownCount = sup
            ? Object.values(store.products).filter((p) => p.supplierId === sup.id).length
            : 0;
          roleScopedContext = sup
            ? `Signed-in Supplier (${sup.businessName}): ProfileStatus=${sup.status}, OwnProducts=${ownCount}.`
            : 'Signed-in Supplier account: KYC profile not submitted yet in Supplier Portal.';
        } else {
          roleScopedContext = `Signed-in ${req.authUser.role} (${req.authUser.email}).`;
        }
      }

      const groundedContext = [
        `Brand: TANZANITE EXPRESS — "Fashion You Love, Delivered to You".`,
        `Supported Currencies: TZS, USD, GBP, EUR, KES (1 USD ≈ TZS ${tzsRate.toLocaleString('en-US')}).`,
        `Account Registration & Sign-In: Click "Sign In" in header -> choose "Create Account" -> select Customer or Supplier (Free) -> enter Full Name, Email, Password (min 8 chars), accept Terms, or use "Continue with Google". Password reset is via "Forgot Password?".`,
        `How to Order & Checkout: Browse products -> select Size/Color -> "Add to Bag" -> open Bag -> "Proceed to Checkout" -> enter delivery address & choose M-Pesa or NMB Bank Transfer -> "Create Order & View Payment Details" -> pay and submit your Transaction/Reference ID (+ optional receipt screenshot) for Admin verification.`,
        `Active Payment Channels: ${activeGateways || 'M-Pesa and NMB Bank Transfer (Tanzania)'}`,
        `Payment Verification Rule: Submitting a Transaction ID sets payment to PENDING VERIFICATION. Admin verifies funds manually before releasing the order to suppliers for shipping.`,
        `Order Tracking: Click "Track Order" in the navigation bar and enter your Order ID (e.g., ord_...) and Checkout Email, or sign in to Customer Dashboard -> Orders & Tracking.`,
        `Free Supplier Registration: Supplier registration is 100% FREE (TZS 0). Sign up as "Supplier (Free)" or click "Sell With Us" / "Become a Supplier (Free)" -> complete Supplier KYC application -> Admin verifies and approves -> upload products manually or via CSV -> Admin sets final retail markup & publishes live.`,
        `Returns & Refunds: Customers can file return/refund claims in Customer Dashboard within 7–14 days of delivery for damaged, wrong, or missing items (unworn with tags).`,
        `Shipping Zones: ${Object.values(store.shippingZones)
          .map((z) => `${z.name} (${z.estimatedDaysMin}-${z.estimatedDaysMax} business days)`)
          .join('; ')}`,
        `Live Catalog Categories (${liveProducts.length} in-stock products total): ${Object.entries(categoryCounts)
          .map(([k, n]) => `${k} (${n})`)
          .join(', ') || 'Catalog updating'}`,
        `Relevant Published Products:\n${catalogHighlight || 'No matching published products currently in stock.'}`,
        roleScopedContext,
      ].join('\n');

      const result = await generateSupportAssistantReply({
        question: parsed.data.question,
        history: parsed.data.history,
        groundedContext,
        language: parsed.data.language,
      });

      if (result.unavailable) {
        return res.status(503).json({
          error: result.reply,
          reply: result.reply,
          aiPowered: false,
          unavailable: true,
          suggestEscalation: true,
          replyLanguage: result.replyLanguage,
          errorCode: result.errorCode,
        });
      }

      res.json(result);
    }
  );

  // Secure Backend Media Endpoint for Uploaded Product Images
  app.get('/api/media/products/:imageId', optionalAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const meta = store.productImages[req.params.imageId];
    if (!meta) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const mediaUrl = `/api/media/products/${meta.id}`;
    const referencingProducts = Object.values(store.products).filter((p) =>
      (p.images || []).some((u) => u.split('?')[0] === mediaUrl)
    );
    const isPubliclyLive = referencingProducts.some((p) => isProductLiveOnStorefront(p));

    if (!isPubliclyLive) {
      const user = req.authUser;
      const isAuthorized =
        Boolean(user) &&
        (user!.role === 'super_admin' ||
          user!.role === 'staff' ||
          meta.supplierOwnerUid === user!.uid);
      if (!isAuthorized) {
        return res.status(403).json({
          error: 'Authentication and ownership or admin privileges required for unpublished product media.',
        });
      }
    }

    const buf = readProductImageFile(meta);
    if (!buf) {
      return res.status(404).json({ error: 'Image binary missing from storage.' });
    }

    res.setHeader('Content-Type', meta.mimeType);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader(
      'Cache-Control',
      isPubliclyLive ? 'public, max-age=3600' : 'private, no-store'
    );
    res.send(buf);
  });

  app.get('/api/orders/track/:orderId', optionalAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const order = store.orders[req.params.orderId];
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const emailParam = String(req.query.email || '').trim().toLowerCase();
    const isOwner = req.authUser && order.customerId === req.authUser.uid;
    const isAdmin =
      req.authUser && (req.authUser.role === 'super_admin' || req.authUser.role === 'staff');
    const matchesEmail = emailParam && order.customerEmail.toLowerCase() === emailParam;

    if (!isOwner && !isAdmin && !matchesEmail) {
      return res.status(403).json({
        error: 'Provide the order email address or sign in as the order owner to view tracking.',
      });
    }

    const suborders = order.suborderIds
      .map((id) => store.suborders[id])
      .filter(Boolean)
      .map((sub) => ({
        id: sub.id,
        supplierName: sub.supplierName,
        supplierCountry: sub.supplierCountry,
        items: sub.items.map((i) => ({
          title: i.title,
          size: i.size,
          color: i.color,
          quantity: i.quantity,
          lineTotalUsd: i.lineTotalUsd,
        })),
        status: sub.status,
        carrierName: sub.carrierName,
        trackingNumber: sub.trackingNumber,
        trackingUrl: sub.trackingUrl,
        statusHistory: sub.statusHistory,
      }));

    res.json({
      order: {
        id: order.id,
        currency: order.currency,
        totalDisplay: order.totalDisplay,
        totalUsd: order.totalUsd,
        paymentProvider: order.paymentProvider,
        paymentStatus: order.paymentStatus,
        submittedTransactionId: order.submittedTransactionId,
        paymentRejectionReason: order.paymentRejectionReason,
        overallStatus: order.overallStatus,
        isInternational: order.isInternational,
        createdAt: order.createdAt,
        shippingCity: order.shippingAddress.city,
        shippingCountry: order.shippingAddress.country,
      },
      suborders,
    });
  });

  app.post('/api/newsletter/subscribe', async (req, res) => {
    const schema = z.object({
      email: z.string().email().max(180),
      market: z.string().max(60).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    const store = await getStore();
    const email = parsed.data.email.toLowerCase();
    if (!store.newsletterSubscribers.some((s) => s.email === email)) {
      store.newsletterSubscribers.push({
        email,
        market: parsed.data.market || 'Global',
        createdAt: new Date().toISOString(),
      });
      await saveStore(store);
    }
    res.json({ subscribed: true, email });
  });

  app.post('/api/coupons/validate', async (req, res) => {
    const schema = z.object({
      code: z.string().min(2).max(40),
      subtotalUsd: z.number().nonnegative(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid coupon request' });
    }
    const store = await getStore();
    const coupon = Object.values(store.coupons).find(
      (c) => c.active && c.code.toUpperCase() === parsed.data.code.trim().toUpperCase()
    );
    if (!coupon) {
      return res.status(404).json({ error: 'Coupon code is invalid or expired.' });
    }
    if (parsed.data.subtotalUsd < coupon.minOrderUsd) {
      return res.status(400).json({
        error: `Minimum order of $${coupon.minOrderUsd} USD required for ${coupon.code}.`,
      });
    }
    const discountUsd =
      coupon.type === 'percentage'
        ? round2((parsed.data.subtotalUsd * coupon.value) / 100)
        : round2(Math.min(parsed.data.subtotalUsd, coupon.value));

    res.json({ coupon, discountUsd });
  });

  // ------------------------------------------------------------------
  // 2. CUSTOMER PROFILE, WISHLIST, REVIEWS, REFUNDS & TICKETS
  // ------------------------------------------------------------------
  app.get('/api/me', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const user = req.authUser!;
    const supplier = Object.values(store.suppliers).find((s) => s.ownerUid === user.uid);
    const notifications = Object.values(store.notifications)
      .filter((n) => n.recipientUid === user.uid && !n.hiddenByRecipient)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    res.json({
      user,
      supplier: supplier || null,
      wishlist: store.wishlists[user.uid] || [],
      notifications,
      adminEmailUnverified: Boolean(req.adminEmailUnverified),
    });
  });

  app.get('/api/auth/admin-status', async (_req, res) => {
    const status = await getAdminBootstrapStatus();
    res.json({
      adminEmail: status.adminEmail,
      bootstrapSecretConfigured: status.configured,
      firebaseAdminAvailable: status.firebaseAdminAvailable,
      storeProfileExists: status.storeProfileExists,
      errorCode: status.errorCode,
      message: status.message,
    });
  });

  const failedAuthLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 25,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(extractClientIp(req)),
  });

  app.post('/api/auth/failed-attempt', failedAuthLimiter, async (req, res) => {
    const schema = z.object({
      email: z.string().trim().max(160).optional(),
      errorCode: z.string().trim().max(80).default('unknown'),
      provider: z.enum(['password', 'google']).default('password'),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid diagnostic payload' });
    }
    const rawEmail = (parsed.data.email || '').toLowerCase();
    const maskedEmail = rawEmail.includes('@')
      ? `${rawEmail.slice(0, 2)}***@${rawEmail.split('@')[1]}`
      : 'unspecified';
    const isAdminAttempt = rawEmail === 'mahelaissa1@gmail.com';
    const safeCode = parsed.data.errorCode.replace(/[^a-zA-Z0-9/_-]/g, '');

    console.info(
      `[Auth] Failed ${parsed.data.provider} sign-in attempt (target=${isAdminAttempt ? 'super_admin_email' : maskedEmail}, code=${safeCode})`
    );

    await appendAuditLog({
      actorUid: 'anonymous',
      actorEmail: isAdminAttempt ? 'mahelaissa1@gmail.com' : maskedEmail,
      actorRole: isAdminAttempt ? 'super_admin_candidate' : 'guest',
      action: 'USER_LOGIN_FAILED',
      targetType: 'auth',
      targetId: parsed.data.provider,
      details: `Sign-in failed with Firebase code "${safeCode}" via ${parsed.data.provider}.`,
    });

    res.json({ ok: true });
  });

  // Auth registration & password lifecycle endpoints
  app.post('/api/auth/register-profile', requireAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      displayName: z.string().trim().min(2).max(120),
      phone: z.string().trim().max(40).optional(),
      accountType: z.enum(['customer', 'supplier']).default('customer'),
      acceptedTerms: z.literal(true),
      authProvider: z.enum(['password', 'google']).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Valid full name and Terms & Conditions acceptance are required.' });
    }
    const store = await getStore();
    const user = req.authUser!;
    const now = new Date().toISOString();

    // Prevent arbitrary post-registration role flips unless user has not completed registration yet or already owns a supplier profile
    const isInitialOnboarding = !user.acceptedTermsAt;
    let resolvedRole = user.role;
    if (user.role !== 'super_admin' && user.role !== 'staff') {
      if (isInitialOnboarding) {
        resolvedRole = parsed.data.accountType === 'supplier' ? 'supplier' : 'customer';
      }
    }

    const updatedUser = {
      ...user,
      displayName: parsed.data.displayName,
      phone: parsed.data.phone || user.phone,
      role: resolvedRole,
      status: user.status || 'active',
      acceptedTermsAt: user.acceptedTermsAt || now,
      authProvider: parsed.data.authProvider || user.authProvider || 'password',
      updatedAt: now,
    };
    await upsertUser(updatedUser);

    await appendAuditLog({
      actorUid: updatedUser.uid,
      actorEmail: updatedUser.email,
      actorRole: updatedUser.role,
      action: 'USER_REGISTERED',
      targetType: 'user',
      targetId: updatedUser.uid,
      details: `Account registered as ${updatedUser.role} via ${updatedUser.authProvider}.`,
    });

    await createNotification({
      recipientUid: updatedUser.uid,
      type: 'security',
      priority: 'high',
      dedupeKey: `welcome:${updatedUser.uid}`,
      title: 'Welcome to TANZANITE EXPRESS',
      message:
        updatedUser.role === 'supplier'
          ? 'Your account is ready. Complete your free Supplier KYC profile in the Supplier Portal to list products.'
          : 'Your TANZANITE EXPRESS account was created. Check your inbox for email verification if signing up with email.',
      targetType: 'order',
    });

    for (const adminUid of getAllStaffAndAdminUids(store)) {
      await createNotification({
        recipientUid: adminUid,
        type: updatedUser.role === 'supplier' ? 'supplier' : 'system',
        dedupeKey: `new_user_admin:${updatedUser.uid}`,
        title:
          updatedUser.role === 'supplier'
            ? `New Supplier Account Registered`
            : `New Customer Registered`,
        message: `${updatedUser.displayName} (${updatedUser.email}) registered as ${updatedUser.role}.`,
        targetType: updatedUser.role === 'supplier' ? 'supplier' : undefined,
      });
    }

    res.json({ user: updatedUser });
  });

  app.post('/api/auth/audit-event', requireAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      action: z.enum(['USER_LOGIN', 'PASSWORD_RESET_COMPLETED', 'PASSWORD_CHANGED', 'EMAIL_VERIFICATION_SENT']),
      details: z.string().max(240).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid auth audit event' });
    }
    const now = new Date().toISOString();
    if (parsed.data.action === 'USER_LOGIN') {
      const updatedUser = {
        ...req.authUser!,
        lastLoginAt: now,
        loginCount: (req.authUser!.loginCount || 0) + 1,
        updatedAt: now,
      };
      await upsertUser(updatedUser);
    }
    await appendAuditLog({
      actorUid: req.authUser!.uid,
      actorEmail: req.authUser!.email,
      actorRole: req.authUser!.role,
      action: parsed.data.action,
      targetType: 'user',
      targetId: req.authUser!.uid,
      targetUserId: req.authUser!.uid,
      outcome: 'SUCCESS',
      details: parsed.data.details || parsed.data.action,
    });
    res.json({ ok: true });
  });

  app.post('/api/me/confirm-password-change', requireAuth, async (req: AuthRequest, res) => {
    const user = req.authUser!;
    const updated = {
      ...user,
      mustChangePassword: false,
      updatedAt: new Date().toISOString(),
    };
    await upsertUser(updated);
    await appendAuditLog({
      actorUid: updated.uid,
      actorEmail: updated.email,
      actorRole: updated.role,
      action: 'SECURITY_PASSWORD_CHANGED',
      targetType: 'user',
      targetId: updated.uid,
      targetUserId: updated.uid,
      details: 'Account password updated and mandatory rotation cleared.',
    });
    await createNotification({
      recipientUid: updated.uid,
      type: 'security',
      priority: 'urgent',
      title: 'Password Updated Successfully',
      message: 'Your TANZANITE EXPRESS account password has been changed securely.',
    });
    res.json({ user: updated });
  });

  app.patch('/api/me', requireAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      displayName: z.string().min(1).max(120).optional(),
      phone: z.string().max(40).optional(),
      preferredCurrency: z.enum(['TZS', 'USD', 'GBP', 'EUR', 'KES']).optional(),
      preferredCountry: z.string().min(2).max(64).optional(),
      personalizationEnabled: z.boolean().optional(),
      analyticsConsent: z.boolean().optional(),
      addresses: z
        .array(
          z.object({
            id: z.string(),
            label: z.string().max(40),
            fullName: z.string().max(120),
            phone: z.string().max(40),
            country: z.string().max(64),
            city: z.string().max(64),
            street: z.string().max(200),
            postalCode: z.string().max(24).optional(),
            isDefault: z.boolean().optional(),
          })
        )
        .max(10)
        .optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid profile update payload' });
    }
    const prev = req.authUser!;
    const user = { ...prev, ...parsed.data, updatedAt: new Date().toISOString() };
    await upsertUser(user);

    const changedKeys = Object.keys(parsed.data).filter(
      (k) => (parsed.data as Record<string, unknown>)[k] !== undefined
    );
    if (changedKeys.length > 0) {
      await appendAuditLog({
        actorUid: user.uid,
        actorEmail: user.email,
        actorRole: user.role,
        action: parsed.data.addresses ? 'ADDRESS_UPDATED' : 'USER_PROFILE_UPDATED',
        targetType: 'user',
        targetId: user.uid,
        targetUserId: user.uid,
        details: `Updated profile fields: ${changedKeys.join(', ')}.`,
      });
    }

    if (
      typeof parsed.data.personalizationEnabled === 'boolean' ||
      typeof parsed.data.analyticsConsent === 'boolean'
    ) {
      const store = await getStore();
      await rebuildUserPreferenceProfile(store, user.uid);
    }
    res.json({ user });
  });

  app.get('/api/me/account-history', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const uid = req.authUser!.uid;
    const page = Math.max(1, Number(req.query.page || 1) || 1);
    const limit = Math.min(50, Math.max(5, Number(req.query.limit || 20) || 20));

    const securityLogs = Object.values(store.auditLogs)
      .filter((l) => l.actorUid === uid || l.targetUserId === uid || l.targetId === uid)
      .map((l) => ({
        id: l.id,
        source: 'security_audit' as const,
        action: l.action,
        details: l.details,
        relatedOrderId: l.relatedOrderId,
        createdAt: l.createdAt,
      }));

    const userOrders = Object.values(store.orders).filter((o) => o.customerId === uid);
    const userTickets = Object.values(store.tickets).filter((t) => t.userId === uid);

    const timeline = securityLogs.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const total = timeline.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const slice = timeline.slice((page - 1) * limit, page * limit);

    res.json({
      events: slice,
      pagination: { page, pageSize: limit, total, totalPages, hasMore: page < totalPages },
      summary: {
        createdAt: req.authUser!.createdAt,
        lastLoginAt: req.authUser!.lastLoginAt || req.authUser!.updatedAt,
        loginCount: req.authUser!.loginCount || 0,
        totalOrders: userOrders.length,
        totalTickets: userTickets.length,
        wishlistCount: (store.wishlists[uid] || []).length,
        addressesCount: (req.authUser!.addresses || []).length,
        erasureRequestedAt: req.authUser!.erasureRequestedAt || null,
      },
    });
  });

  app.get('/api/me/export', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const user = req.authUser!;
    const uid = user.uid;
    const format = String(req.query.format || 'json').toLowerCase();

    const orders = Object.values(store.orders)
      .filter((o) => o.customerId === uid)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const orderIds = new Set(orders.map((o) => o.id));
    const suborders = Object.values(store.suborders).filter((s) => orderIds.has(s.orderId));
    const paymentSubmissions = Object.values(store.paymentSubmissions)
      .filter((ps) => ps.customerId === uid || orderIds.has(ps.orderId))
      .map((ps) => {
        const { receiptImageDataUrl: _img, adminNotes: _adminNotes, ...safe } = ps;
        return safe;
      });
    const tickets = Object.values(store.tickets).filter((t) => t.userId === uid);
    const reviews = Object.values(store.reviews).filter((r) => r.customerId === uid);
    const notifications = Object.values(store.notifications)
      .filter((n) => n.recipientUid === uid && !n.hiddenByRecipient)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    await appendAuditLog({
      actorUid: uid,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'USER_DATA_EXPORTED',
      targetType: 'user',
      targetId: uid,
      targetUserId: uid,
      details: `User exported own account data package (${format.toUpperCase()}; ${orders.length} orders, ${tickets.length} tickets).`,
    });

    const safeProfile = {
      uid: user.uid,
      email: user.email,
      displayName: user.displayName,
      phone: user.phone || '',
      role: user.role,
      preferredCurrency: user.preferredCurrency,
      preferredCountry: user.preferredCountry,
      addresses: user.addresses || [],
      lastLoginAt: user.lastLoginAt || null,
      loginCount: user.loginCount || 0,
      createdAt: user.createdAt,
    };

    if (format === 'csv') {
      const rows: Record<string, unknown>[] = [
        ...orders.map((o) => ({
          recordType: 'ORDER',
          id: o.id,
          date: o.createdAt,
          status: o.overallStatus,
          paymentStatus: o.paymentStatus,
          amount: `${o.currency} ${o.totalDisplay}`,
          summary: `${o.shippingAddress.city}, ${o.shippingAddress.country}`,
        })),
        ...tickets.map((t) => ({
          recordType: 'SUPPORT_TICKET',
          id: t.id,
          date: t.createdAt,
          status: t.status,
          paymentStatus: t.priority,
          amount: '',
          summary: t.subject,
        })),
        ...notifications.map((n) => ({
          recordType: 'NOTIFICATION',
          id: n.id,
          date: n.createdAt,
          status: n.read ? 'READ' : 'UNREAD',
          paymentStatus: n.type,
          amount: '',
          summary: n.title,
        })),
      ];
      if (rows.length === 0) {
        rows.push({
          recordType: 'PROFILE',
          id: user.uid,
          date: user.createdAt,
          status: user.status,
          paymentStatus: user.role,
          amount: user.preferredCurrency,
          summary: `${user.displayName} (${user.email})`,
        });
      }
      const csv = toCsv(rows);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="tanzanite-my-data-${uid.slice(0, 8)}.csv"`);
      return res.send(csv);
    }

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="tanzanite-my-data-${uid.slice(0, 8)}.json"`);
    res.json({
      exportedAt: new Date().toISOString(),
      marketplace: 'TANZANITE EXPRESS',
      profile: safeProfile,
      wishlistProductIds: store.wishlists[uid] || [],
      orders,
      suborders,
      paymentSubmissions,
      tickets,
      reviews,
      notifications,
      notificationPreferences: getUserNotificationPreferences(store, uid),
    });
  });

  app.post('/api/me/erasure-request', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const user = req.authUser!;
    const now = new Date().toISOString();
    const reason = String(req.body?.reason || '').trim().slice(0, 400);

    const updated = {
      ...user,
      erasureRequestedAt: user.erasureRequestedAt || now,
      updatedAt: now,
    };
    await upsertUser(updated);

    await appendAuditLog({
      actorUid: user.uid,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'PRIVACY_ERASURE_REQUESTED',
      targetType: 'user',
      targetId: user.uid,
      targetUserId: user.uid,
      details: `User requested personal data erasure/anonymization. Reason: ${reason || 'Not specified'}`,
    });

    for (const adminUid of getAllStaffAndAdminUids(store)) {
      await createNotification({
        recipientUid: adminUid,
        type: 'security',
        priority: 'urgent',
        dedupeKey: `erasure_req:${user.uid}`,
        title: `Privacy Erasure Request: ${user.email}`,
        message: `${user.displayName} (${user.email}) requested personal data anonymization. Review in Admin Governance & Audit.`,
      });
    }

    res.json({ user: updated });
  });

  app.post('/api/me/wishlist', requireAuth, async (req: AuthRequest, res) => {
    const productId = String(req.body?.productId || '');
    const store = await getStore();
    const product = store.products[productId];
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    const current = new Set(store.wishlists[req.authUser!.uid] || []);
    let added = false;
    if (current.has(productId)) {
      current.delete(productId);
    } else {
      current.add(productId);
      added = true;
    }
    const nextWishlist = Array.from(current);
    await syncWishlistForUser(req.authUser!.uid, nextWishlist);
    if (added) {
      await recordActivityEvent(store, {
        userId: req.authUser!.uid,
        type: 'wishlist_add',
        productId: product.id,
        supplierId: product.supplierId,
        category: product.category,
        gender: product.gender,
        priceUsd: product.sellingPriceUsd,
      });
    }
    res.json({ wishlist: store.wishlists[req.authUser!.uid] });
  });

  app.post('/api/me/notifications/read', requireAuth, async (req: AuthRequest, res) => {
    const updatedCount = await markAllNotificationsAsReadForUser(req.authUser!.uid);
    res.json({ ok: true, updatedCount });
  });

  app.get('/api/notifications', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const uid = req.authUser!.uid;
    const typeFilter = String(req.query.type || 'all');
    const unreadOnly = String(req.query.unreadOnly || '') === 'true';
    const page = Math.max(1, Number(req.query.page || 1) || 1);
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 100) || 100));

    let list = Object.values(store.notifications)
      .filter((n) => n.recipientUid === uid && !n.hiddenByRecipient)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    const unreadCount = list.filter((n) => !n.read).length;
    if (typeFilter && typeFilter !== 'all') {
      list = list.filter((n) => n.type === typeFilter);
    }
    if (unreadOnly) {
      list = list.filter((n) => !n.read);
    }

    const total = list.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const paged = list.slice((page - 1) * limit, page * limit);
    const preferences = getUserNotificationPreferences(store, uid);
    res.json({
      notifications: paged,
      total,
      page,
      pageSize: limit,
      totalPages,
      hasMore: page < totalPages,
      unreadCount,
      preferences,
    });
  });

  app.get('/api/notifications/stream', async (req, res) => {
    const queryToken = String(req.query.token || '');
    const authHeader = req.headers.authorization;
    const bearerToken =
      authHeader && authHeader.startsWith('Bearer ') ? authHeader.split('Bearer ')[1] : '';
    const token = bearerToken || queryToken;
    if (!token) {
      return res.status(401).json({ error: 'Authentication token required for notification stream' });
    }

    let user;
    try {
      user = await resolveUserFromToken(token);
    } catch {
      return res.status(401).json({ error: 'Invalid stream token' });
    }
    if (!user || user.status === 'suspended') {
      return res.status(403).json({ error: 'Unauthorized stream access' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    res.write(`event: connected\ndata: ${JSON.stringify({ uid: user.uid, connectedAt: new Date().toISOString() })}\n\n`);

    const listener = (item: NotificationItem) => {
      res.write(`event: notification\ndata: ${JSON.stringify(item)}\n\n`);
    };
    const syncListener = (payload: Record<string, unknown>) => {
      res.write(`event: notifications_sync\ndata: ${JSON.stringify(payload)}\n\n`);
    };

    const eventName = `user:${user.uid}`;
    const syncEventName = `sync:${user.uid}`;
    notificationEvents.on(eventName, listener);
    notificationEvents.on(syncEventName, syncListener);

    const keepAlive = setInterval(() => {
      res.write(': keepalive\n\n');
    }, 25000);

    req.on('close', () => {
      clearInterval(keepAlive);
      notificationEvents.off(eventName, listener);
      notificationEvents.off(syncEventName, syncListener);
    });
  });

  app.patch('/api/notifications/:id/read', requireAuth, async (req: AuthRequest, res) => {
    const updated = await markNotificationAsRead(req.authUser!.uid, req.params.id);
    if (!updated) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    res.json({ notification: updated });
  });

  app.post('/api/notifications/read-all', requireAuth, async (req: AuthRequest, res) => {
    const updatedCount = await markAllNotificationsAsReadForUser(req.authUser!.uid);
    res.json({ ok: true, updatedCount });
  });

  // Soft-hide individual notification for the user (preserves underlying record & Admin audit trail)
  const hideOneHandler = async (req: AuthRequest, res: express.Response) => {
    const hidden = await hideNotificationForUser(req.authUser!.uid, req.params.id, {
      email: req.authUser!.email,
      role: req.authUser!.role,
    });
    if (!hidden) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    res.json({ ok: true, notification: hidden });
  };
  app.delete('/api/notifications/:id', requireAuth, hideOneHandler);
  app.patch('/api/notifications/:id/hide', requireAuth, hideOneHandler);

  // Soft-clear all visible notifications for the user (preserves underlying records & Admin audit trail)
  app.post('/api/notifications/clear-visible', requireAuth, async (req: AuthRequest, res) => {
    const clearedCount = await clearVisibleNotificationsForUser(req.authUser!.uid, {
      email: req.authUser!.email,
      role: req.authUser!.role,
    });
    res.json({ ok: true, clearedCount });
  });

  app.get('/api/notification-preferences', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    res.json({ preferences: getUserNotificationPreferences(store, req.authUser!.uid) });
  });

  app.patch('/api/notification-preferences', requireAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      inAppEnabled: z.boolean().optional(),
      emailEnabled: z.boolean().optional(),
      mutedTypes: z
        .array(z.enum(['order', 'payment', 'fulfillment', 'return', 'supplier', 'product', 'security', 'system']))
        .optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid notification preferences payload' });
    }
    const store = await getStore();
    const current = getUserNotificationPreferences(store, req.authUser!.uid);
    const updated = await upsertNotificationPreferences({
      uid: req.authUser!.uid,
      inAppEnabled: parsed.data.inAppEnabled ?? current.inAppEnabled,
      emailEnabled: parsed.data.emailEnabled ?? current.emailEnabled,
      mutedTypes: (parsed.data.mutedTypes ?? current.mutedTypes) as NotificationType[],
      updatedAt: new Date().toISOString(),
    });
    res.json({ preferences: updated });
  });

  app.get('/api/me/orders', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const uid = req.authUser!.uid;
    const statusFilter = String(req.query.status || 'ALL').trim();
    const qFilter = String(req.query.q || '').trim().toLowerCase();
    const page = Math.max(1, Number(req.query.page || 1) || 1);
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 200) || 200));

    let orders = Object.values(store.orders)
      .filter((o) => o.customerId === uid)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    const allSuborders = Object.values(store.suborders).filter((s) => s.customerId === uid);

    if (statusFilter && statusFilter !== 'ALL') {
      orders = orders.filter(
        (o) =>
          o.overallStatus === statusFilter ||
          o.paymentStatus === statusFilter ||
          (statusFilter === 'Completed' && (o.overallStatus === 'Delivered' || o.overallStatus === 'Completed')) ||
          (statusFilter === 'Refunded' && (o.overallStatus === 'Refunded' || o.paymentStatus === 'REFUNDED'))
      );
    }
    if (qFilter) {
      orders = orders.filter((o) => {
        const subs = allSuborders.filter((s) => s.orderId === o.id);
        return (
          o.id.toLowerCase().includes(qFilter) ||
          (o.submittedTransactionId || '').toLowerCase().includes(qFilter) ||
          (o.paymentReference || '').toLowerCase().includes(qFilter) ||
          subs.some(
            (s) =>
              s.supplierName.toLowerCase().includes(qFilter) ||
              s.items.some((it) => it.title.toLowerCase().includes(qFilter) || it.sku.toLowerCase().includes(qFilter))
          )
        );
      });
    }

    const total = orders.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const pagedOrders = orders.slice((page - 1) * limit, page * limit);
    const orderIds = new Set(pagedOrders.map((o) => o.id));
    const suborders = allSuborders.filter((s) => orderIds.has(s.orderId));
    const payments = Object.values(store.payments).filter((p) => orderIds.has(p.orderId));
    const paymentSubmissions = Object.values(store.paymentSubmissions)
      .filter((s) => orderIds.has(s.orderId))
      .map(sanitizeSubmissionForClient)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const refunds = Object.values(store.refunds).filter((r) => r.customerId === uid);

    res.json({
      orders: pagedOrders,
      suborders,
      payments,
      paymentSubmissions,
      refunds,
      pagination: { page, pageSize: limit, total, totalPages, hasMore: page < totalPages },
    });
  });

  app.post('/api/reviews', requireAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      productId: z.string().min(1),
      rating: z.number().int().min(1).max(5),
      comment: z.string().min(3).max(1200),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Rating (1-5) and comment (3+ chars) are required.' });
    }
    const store = await getStore();
    const product = store.products[parsed.data.productId];
    if (!product || !isProductLiveOnStorefront(product)) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const userOrders = Object.values(store.orders).filter(
      (o) => o.customerId === req.authUser!.uid && o.paymentStatus === 'CONFIRMED'
    );
    const verifiedOrder = userOrders.find((o) =>
      o.suborderIds.some((sid) =>
        store.suborders[sid]?.items.some((i) => i.productId === product.id)
      )
    );

    const review: Review = {
      id: generateId('rev'),
      productId: product.id,
      customerId: req.authUser!.uid,
      customerName: req.authUser!.displayName,
      orderId: verifiedOrder?.id,
      rating: parsed.data.rating,
      comment: parsed.data.comment.trim(),
      verifiedPurchase: Boolean(verifiedOrder),
      createdAt: new Date().toISOString(),
    };
    await upsertReviewRecord(review);

    const allForProduct = Object.values(store.reviews).filter(
      (r) => r.productId === product.id
    );
    product.ratingCount = allForProduct.length;
    product.ratingAvg = round2(
      allForProduct.reduce((sum, r) => sum + r.rating, 0) / allForProduct.length
    );
    await upsertProduct(product);
    await saveStore(store);
    await recordActivityEvent(store, {
      userId: req.authUser!.uid,
      type: 'review',
      productId: product.id,
      supplierId: product.supplierId,
      category: product.category,
      gender: product.gender,
      priceUsd: product.sellingPriceUsd,
    });
    res.json({ review, product });
  });

  app.post('/api/refunds', requireAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      orderId: z.string().min(1),
      suborderId: z.string().min(1),
      reason: z.string().min(8).max(1000),
      evidenceImages: z.array(z.string().max(500000)).max(4).default([]),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Provide a clear return/refund reason (min 8 chars).' });
    }
    const store = await getStore();
    const order = store.orders[parsed.data.orderId];
    const suborder = store.suborders[parsed.data.suborderId];
    if (!order || !suborder || order.customerId !== req.authUser!.uid) {
      return res.status(404).json({ error: 'Matching order suborder not found' });
    }
    if (order.paymentStatus !== 'CONFIRMED') {
      return res.status(400).json({ error: 'Refunds can only be requested for confirmed payments.' });
    }
    const now = new Date().toISOString();
    const refund: RefundRequest = {
      id: generateId('ref'),
      orderId: order.id,
      suborderId: suborder.id,
      customerId: req.authUser!.uid,
      customerEmail: req.authUser!.email,
      supplierId: suborder.supplierId,
      reason: parsed.data.reason.trim(),
      evidenceImages: parsed.data.evidenceImages,
      requestedAmountUsd: round2(suborder.supplierSubtotalUsd + suborder.shippingFeeUsd),
      status: 'SUBMITTED',
      createdAt: now,
      updatedAt: now,
    };
    await upsertRefundRequest(refund);
    suborder.status = 'Refund Requested';
    suborder.updatedAt = now;
    suborder.statusHistory.push({
      status: 'Refund Requested',
      timestamp: now,
      actor: req.authUser!.email,
      note: 'Customer submitted refund/return request.',
    });
    await upsertSuborder(suborder);
    await appendAuditLog({
      actorUid: req.authUser!.uid,
      actorEmail: req.authUser!.email,
      actorRole: req.authUser!.role,
      action: 'REFUND_REQUESTED',
      targetType: 'refund',
      targetId: refund.id,
      targetUserId: req.authUser!.uid,
      relatedOrderId: order.id,
      details: `Customer requested refund on suborder ${suborder.id}: "${refund.reason}".`,
    });

    await createNotification({
      recipientUid: suborder.supplierOwnerUid,
      type: 'return',
      priority: 'urgent',
      dedupeKey: `refund_sup:${refund.id}`,
      title: `Return / Refund Requested (${suborder.id})`,
      message: `A customer submitted a return/refund claim for order ${order.id}: "${refund.reason}".`,
      targetType: 'refund',
      targetId: refund.id,
    });
    for (const adminUid of getAllStaffAndAdminUids(store)) {
      await createNotification({
        recipientUid: adminUid,
        type: 'return',
        priority: 'urgent',
        dedupeKey: `refund_adm:${refund.id}`,
        title: `Customer Return Claim (${order.id})`,
        message: `${req.authUser!.email} requested a refund on suborder ${suborder.id} ($${refund.requestedAmountUsd} USD).`,
        targetType: 'refund',
        targetId: refund.id,
      });
    }

    res.json({ refund });
  });

  app.post('/api/support/tickets', optionalAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      email: z.string().email().max(180).optional(),
      orderId: z.string().max(128).optional(),
      supplierId: z.string().max(128).optional(),
      category: z.enum(['order', 'supplier', 'payment', 'general']),
      priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
      subject: z.string().trim().min(1).max(160),
      message: z.string().trim().min(1).max(600),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Please enter a valid support question (1–600 characters).' });
    }
    const email = req.authUser?.email || parsed.data.email;
    if (!email) {
      return res.status(400).json({ error: 'Email is required for support inquiries.' });
    }
    const store = await getStore();
    const now = new Date().toISOString();
    const ticket: SupportTicket = {
      id: generateId('tkt'),
      userId: req.authUser?.uid || `guest_${email}`,
      userEmail: email,
      orderId: parsed.data.orderId,
      supplierId: parsed.data.supplierId,
      category: parsed.data.category,
      priority: parsed.data.priority,
      subject: parsed.data.subject.trim(),
      message: parsed.data.message.trim(),
      status: 'OPEN',
      responses: [],
      createdAt: now,
      updatedAt: now,
    };
    await upsertSupportTicket(ticket);
    await appendAuditLog({
      actorUid: ticket.userId,
      actorEmail: email,
      actorRole: req.authUser?.role || 'guest',
      action: 'SUPPORT_TICKET_CREATED',
      targetType: 'ticket',
      targetId: ticket.id,
      targetUserId: req.authUser?.uid,
      relatedOrderId: ticket.orderId,
      details: `Support ticket submitted [${ticket.category}/${ticket.priority}]: ${ticket.subject}`,
    });

    for (const adminUid of getAllStaffAndAdminUids(store)) {
      await createNotification({
        recipientUid: adminUid,
        type: 'system',
        priority: ticket.priority === 'urgent' ? 'urgent' : 'high',
        dedupeKey: `ticket_new:${ticket.id}`,
        title: `New Support Ticket (${ticket.priority.toUpperCase()})`,
        message: `${email}: ${ticket.subject}`,
        targetType: 'ticket',
        targetId: ticket.id,
      });
    }

    res.json({ ticket });
  });

  app.get('/api/me/tickets', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const tickets = Object.values(store.tickets)
      .filter((t) => t.userId === req.authUser!.uid)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    res.json({ tickets });
  });

  // ------------------------------------------------------------------
  // 3. MULTI-VENDOR CHECKOUT, ORDER SPLITTING & PAYMENT WEBHOOKS
  // ------------------------------------------------------------------
  app.post('/api/checkout/create-order', optionalAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      idempotencyKey: z.string().min(8).max(128),
      customerEmail: z.string().email().max(180),
      currency: z.enum(['TZS', 'USD', 'GBP', 'EUR', 'KES']),
      couponCode: z.string().max(40).optional(),
      paymentProvider: z.enum(['manual_mobile', 'manual_nmb']),
      customsDisclaimerAccepted: z.boolean(),
      shippingAddress: z.object({
        id: z.string().default('checkout_addr'),
        label: z.string().default('Shipping Address'),
        fullName: z.string().min(2).max(120),
        phone: z.string().min(6).max(40),
        country: z.string().min(2).max(64),
        city: z.string().min(2).max(64),
        street: z.string().min(3).max(200),
        postalCode: z.string().max(24).optional(),
      }),
      items: z
        .array(
          z.object({
            productId: z.string().min(1),
            sku: z.string().min(1),
            quantity: z.number().int().min(1).max(25),
          })
        )
        .min(1),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid checkout details.', details: parsed.error.issues });
    }

    const store = await getStore();
    const data = parsed.data;

    if (!req.authUser && !store.settings.allowGuestCheckout) {
      return res.status(401).json({ error: 'Guest checkout is disabled. Please sign in.' });
    }

    // Duplicate payment / order prevention via idempotency key
    const existingPayment = Object.values(store.payments).find(
      (p) => p.idempotencyKey === data.idempotencyKey
    );
    if (existingPayment) {
      const existingOrder = store.orders[existingPayment.orderId];
      return res.json({ order: existingOrder, payment: existingPayment, deduplicated: true });
    }

    // Validate manual payment method availability from Admin settings
    const gateways = getPaymentGatewaysStatus(store.settings);
    const selectedGateway = gateways.find((g) => g.id === data.paymentProvider);
    if (!selectedGateway) {
      return res.status(400).json({ error: 'Unsupported payment method.' });
    }
    if (!selectedGateway.enabledForCheckout) {
      return res.status(400).json({
        error: `${selectedGateway.name} is currently disabled by marketplace administration. Please choose another active payment method.`,
      });
    }

    const isInternational = data.shippingAddress.country.trim().toLowerCase() !== 'tanzania';
    if (isInternational && !data.customsDisclaimerAccepted) {
      return res.status(400).json({
        error: 'Please acknowledge the international customs and import duties disclaimer.',
      });
    }

    // Validate items & group by supplierId
    const bySupplier = new Map<
      string,
      { product: Product; sku: string; size: string; color: string; quantity: number }[]
    >();

    for (const line of data.items) {
      const product = store.products[line.productId];
      if (!product || !isProductLiveOnStorefront(product)) {
        return res.status(400).json({ error: `Product ${line.productId} is unavailable.` });
      }
      const variant = product.variants.find((v) => v.sku === line.sku);
      if (!variant) {
        return res.status(400).json({ error: `Variant ${line.sku} not found for ${product.title}.` });
      }
      if (variant.stock < line.quantity) {
        return res.status(400).json({
          error: `Insufficient stock for ${product.title} (${variant.size}/${variant.color}). Available: ${variant.stock}.`,
        });
      }
      const arr = bySupplier.get(product.supplierId) || [];
      arr.push({
        product,
        sku: variant.sku,
        size: variant.size,
        color: variant.color,
        quantity: line.quantity,
      });
      bySupplier.set(product.supplierId, arr);
    }

    // Decrement variant stock
    for (const [, lines] of bySupplier) {
      for (const l of lines) {
        const variant = l.product.variants.find((v) => v.sku === l.sku)!;
        variant.stock -= l.quantity;
        l.product.totalStock = l.product.variants.reduce((acc, v) => acc + v.stock, 0);
        l.product.updatedAt = new Date().toISOString();
        await upsertProduct(l.product);
        if (variant.stock <= 3) {
          await createNotification({
            recipientUid: l.product.supplierOwnerUid,
            title: `Low Stock Alert: ${l.product.title}`,
            message: `Variant ${variant.sku} (${variant.size}/${variant.color}) has ${variant.stock} unit(s) remaining.`,
          });
        }
      }
    }

    const now = new Date().toISOString();
    const orderId = generateId('ord');
    const deadlineMs = store.settings.supplierResponseDeadlineHours * 3600 * 1000;
    const responseDeadlineAt = new Date(Date.now() + deadlineMs).toISOString();

    let subtotalUsd = 0;
    let shippingUsd = 0;
    const suborders: SupplierSuborder[] = [];

    for (const [supplierId, lines] of bySupplier) {
      const supplier = store.suppliers[supplierId];
      const subItems = lines.map((l) => {
        const lineTotal = round2(l.product.sellingPriceUsd * l.quantity);
        return {
          productId: l.product.id,
          title: l.product.title,
          image: l.product.images?.[0] || '',
          sku: l.sku,
          size: l.size,
          color: l.color,
          quantity: l.quantity,
          unitSellingPriceUsd: l.product.sellingPriceUsd,
          unitWholesalePriceUsd: l.product.wholesalePriceUsd,
          lineTotalUsd: lineTotal,
        };
      });

      const subSubtotal = round2(subItems.reduce((acc, item) => acc + item.lineTotalUsd, 0));
      const supplierBaseCostUsd = round2(
        subItems.reduce((acc, item) => acc + item.unitWholesalePriceUsd * item.quantity, 0)
      );
      const adminMarkupUsd = round2(Math.max(0, subSubtotal - supplierBaseCostUsd));
      const baseShip = Math.max(...lines.map((l) => l.product.shippingFeeUsd));
      const zoneMultiplier = isInternational ? 1.5 : 1;
      const subShipping = round2(baseShip * zoneMultiplier);

      // Admin markup profit model + optional percentage rule if configured
      const ratePct = resolveCommissionRatePct(store, supplierId, lines[0].product.category);
      const extraRateUsd = round2((supplierBaseCostUsd * ratePct) / 100);
      const commissionUsd = round2(adminMarkupUsd + extraRateUsd);
      const netSupplierUsd = round2(Math.max(0, subSubtotal - commissionUsd) + subShipping);

      subtotalUsd += subSubtotal;
      shippingUsd += subShipping;

      const subId = generateId('sub');
      const suborder: SupplierSuborder = {
        id: subId,
        orderId,
        supplierId,
        supplierOwnerUid: supplier?.ownerUid || lines[0].product.supplierOwnerUid,
        supplierName: supplier?.businessName || lines[0].product.supplierName,
        supplierCountry: supplier?.country || lines[0].product.supplierCountry,
        customerId: req.authUser?.uid || `guest_${data.customerEmail.toLowerCase()}`,
        customerShippingName: data.shippingAddress.fullName,
        customerShippingCity: data.shippingAddress.city,
        customerShippingCountry: data.shippingAddress.country,
        customerShippingStreet: data.shippingAddress.street,
        customerShippingPhone: data.shippingAddress.phone,
        items: subItems,
        supplierSubtotalUsd: subSubtotal,
        supplierBaseCostUsd,
        adminMarkupUsd,
        shippingFeeUsd: subShipping,
        marketplaceCommissionRatePct: ratePct,
        marketplaceCommissionUsd: commissionUsd,
        supplierNetEarningsUsd: netSupplierUsd,
        supplierSettlementStatus: 'PENDING_ADMIN_TRANSFER',
        fulfillmentReleased: false,
        status: 'Pending Payment',
        paymentStatus: 'PENDING',
        responseDeadlineAt,
        statusHistory: [
          {
            status: 'Pending Payment',
            timestamp: now,
            actor: data.customerEmail,
            note: 'Order created. Awaiting manual payment submission & Admin verification.',
          },
        ],
        createdAt: now,
        updatedAt: now,
      };
      suborders.push(suborder);
      await upsertSuborder(suborder);
    }

    // Apply valid coupon
    let discountUsd = 0;
    let appliedCoupon: string | undefined;
    if (data.couponCode) {
      const coupon = Object.values(store.coupons).find(
        (c) => c.active && c.code.toUpperCase() === data.couponCode!.trim().toUpperCase()
      );
      if (coupon && subtotalUsd >= coupon.minOrderUsd) {
        discountUsd =
          coupon.type === 'percentage'
            ? round2((subtotalUsd * coupon.value) / 100)
            : round2(Math.min(subtotalUsd, coupon.value));
        coupon.usageCount += 1;
        appliedCoupon = coupon.code;
      }
    }

    const taxPct = isInternational
      ? store.settings.taxRateIntlPct
      : store.settings.taxRateTzPct;
    const taxUsd = round2(((subtotalUsd - discountUsd) * taxPct) / 100);
    const totalUsd = round2(Math.max(0, subtotalUsd - discountUsd + shippingUsd + taxUsd));
    const fxRate = store.settings.currencyRates[data.currency] ?? 1;
    const totalDisplay =
      data.currency === 'TZS' || data.currency === 'KES'
        ? Math.round((totalUsd * fxRate) / 100) * 100
        : round2(totalUsd * fxRate);

    const order: Order = {
      id: orderId,
      customerId: req.authUser?.uid || `guest_${data.customerEmail.toLowerCase()}`,
      customerEmail: data.customerEmail.toLowerCase(),
      isGuestCheckout: !req.authUser,
      currency: data.currency,
      fxRate,
      subtotalUsd: round2(subtotalUsd),
      shippingUsd: round2(shippingUsd),
      discountUsd,
      taxUsd,
      totalUsd,
      totalDisplay,
      couponCode: appliedCoupon,
      shippingAddress: data.shippingAddress,
      isInternational,
      customsDisclaimerAccepted: data.customsDisclaimerAccepted,
      paymentProvider: data.paymentProvider,
      paymentStatus: 'PENDING',
      suborderIds: suborders.map((s) => s.id),
      overallStatus: 'Pending Payment',
      createdAt: now,
      updatedAt: now,
    };

    const paymentRef = `MIK-${data.paymentProvider.toUpperCase()}-${Date.now()}`;
    const payment: PaymentTransaction = {
      id: generateId('pay'),
      orderId,
      provider: data.paymentProvider,
      mode: selectedGateway.mode,
      reference: paymentRef,
      idempotencyKey: data.idempotencyKey,
      amountUsd: totalUsd,
      currency: data.currency,
      amountDisplay: totalDisplay,
      status: 'PENDING',
      webhookVerified: false,
      createdAt: now,
      updatedAt: now,
    };

    order.paymentReference = paymentRef;
    await upsertOrder(order);
    await upsertPayment(payment);
    await saveStore(store);
    await appendAuditLog({
      actorUid: order.customerId,
      actorEmail: order.customerEmail,
      actorRole: req.authUser?.role || 'guest',
      action: 'ORDER_CREATED',
      targetType: 'order',
      targetId: order.id,
      targetUserId: req.authUser?.uid,
      relatedOrderId: order.id,
      newValue: `${order.overallStatus} (${order.currency} ${order.totalDisplay})`,
      details: `Created multi-vendor order ${order.id} with ${suborders.length} supplier suborder(s) via ${selectedGateway.name}.`,
    });

    // Notify Customer & Admins about new order creation (Suppliers are NOT notified until Admin verifies payment!)
    await createNotification({
      recipientUid: order.customerId,
      type: 'order',
      priority: 'high',
      dedupeKey: `order_created_cust:${order.id}`,
      title: `Order Created (${order.id})`,
      message: `Your order totaling ${order.currency} ${order.totalDisplay.toLocaleString()} was created. Complete manual payment via ${selectedGateway.name} and submit your transaction reference.`,
      targetType: 'order',
      targetId: order.id,
    });
    for (const adminUid of getAdminUids(store)) {
      await createNotification({
        recipientUid: adminUid,
        type: 'order',
        priority: 'high',
        dedupeKey: `order_created_adm:${order.id}`,
        title: `New Customer Order (${order.id})`,
        message: `${order.customerEmail} placed order ${order.id} (${order.currency} ${order.totalDisplay.toLocaleString()}) via ${selectedGateway.name}.`,
        targetType: 'order',
        targetId: order.id,
      });
    }

    for (const line of data.items) {
      const prod = store.products[line.productId];
      if (prod) {
        const variant = prod.variants.find((v) => v.sku === line.sku);
        await recordActivityEvent(store, {
          userId: req.authUser?.uid,
          type: 'purchase',
          productId: prod.id,
          supplierId: prod.supplierId,
          category: prod.category,
          gender: prod.gender,
          priceUsd: prod.sellingPriceUsd,
          size: variant?.size,
          color: variant?.color,
        });
      }
    }

    res.json({
      order,
      suborders,
      payment,
      gateway: selectedGateway,
    });
  });

  // Customer manual payment submission handler (supports M-Pesa & NMB Bank Transfer + optional receipt screenshot)
  const submitPaymentHandler = async (req: AuthRequest, res: express.Response) => {
    const schema = z.object({
      paymentMethod: z.enum(['manual_mobile', 'manual_nmb']).optional(),
      transactionId: z
        .string()
        .trim()
        .min(4, 'Enter the Transaction / Reference ID from your M-Pesa SMS or NMB receipt.')
        .max(120),
      amountSent: z.preprocess(
        (v) => (v === undefined || v === '' ? undefined : Number(v)),
        z.number().positive('Amount sent must be greater than zero.').optional()
      ),
      senderName: z.string().trim().min(2, 'Enter the sender full name.').max(120).optional(),
      senderPhone: z.string().trim().max(40).optional(),
      payerPhone: z.string().trim().max(40).optional(),
      payerName: z.string().trim().max(120).optional(),
      transactionDate: z.string().trim().max(40).optional(),
      receiptImageDataUrl: z
        .string()
        .max(2500000, 'Receipt screenshot must be under 1.8 MB.')
        .regex(
          /^data:image\/(png|jpeg|jpg|webp);base64,/i,
          'Receipt must be a valid PNG, JPG, or WEBP image.'
        )
        .optional(),
      receiptFileName: z.string().max(160).optional(),
      email: z.string().email().max(180).optional(),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: parsed.error.issues[0]?.message || 'Valid payment submission fields are required.',
      });
    }

    const store = await getStore();
    const order = store.orders[req.params.orderId];
    if (!order) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    const isOwner = req.authUser && order.customerId === req.authUser.uid;
    const isVerifier = hasPaymentVerificationAccess(req.authUser);
    const matchesEmail =
      parsed.data.email && order.customerEmail.toLowerCase() === parsed.data.email.trim().toLowerCase();

    if (!isOwner && !isVerifier && !matchesEmail) {
      return res.status(403).json({
        error: 'Provide the order email or sign in as the order owner to submit payment proof.',
      });
    }

    const result = await submitManualPaymentProof({
      orderId: order.id,
      paymentMethod: parsed.data.paymentMethod,
      transactionId: parsed.data.transactionId,
      amountSent: parsed.data.amountSent,
      senderName: parsed.data.senderName || parsed.data.payerName,
      senderPhone: parsed.data.senderPhone || parsed.data.payerPhone,
      transactionDate: parsed.data.transactionDate,
      receiptImageDataUrl: parsed.data.receiptImageDataUrl,
      receiptFileName: parsed.data.receiptFileName,
      actorUid: req.authUser?.uid,
      actorEmail: req.authUser?.email,
      actorRole: req.authUser?.role,
    });

    if ('error' in result) {
      return res.status(result.status).json({
        error: result.error,
        duplicateOfSubmissionId: result.duplicateOfSubmissionId,
      });
    }

    res.json(result);
  };

  app.post('/api/orders/:orderId/submit-payment', optionalAuth, submitPaymentHandler);
  app.post('/api/orders/:orderId/submit-transaction', optionalAuth, submitPaymentHandler);

  // Private Receipt Image endpoint — NEVER publicly accessible; restricted to submission owner or authorized payment admin
  app.get('/api/payment-submissions/:submissionId/receipt', requireAuth, async (req: AuthRequest, res) => {
    const store = await getStore();
    const sub = store.paymentSubmissions[req.params.submissionId];
    if (!sub) {
      return res.status(404).json({ error: 'Payment submission not found.' });
    }
    const isOwner = sub.customerId === req.authUser!.uid;
    const isVerifier = hasPaymentVerificationAccess(req.authUser);
    if (!isOwner && !isVerifier) {
      return res.status(403).json({ error: 'Unauthorized receipt access blocked.' });
    }
    if (!sub.receiptImageDataUrl) {
      return res.status(404).json({ error: 'No receipt screenshot was attached to this submission.' });
    }
    res.json({
      submissionId: sub.id,
      receiptFileName: sub.receiptFileName || 'receipt-image',
      receiptImageDataUrl: sub.receiptImageDataUrl,
    });
  });

  // ------------------------------------------------------------------
  // 4. SUPPLIER ONBOARDING & STRICTLY ISOLATED SUPPLIER PORTAL
  // ------------------------------------------------------------------
  app.post('/api/suppliers/register', requireAuth, async (req: AuthRequest, res) => {
    const schema = z.object({
      businessName: z.string().min(2).max(140),
      ownerFullName: z.string().min(2).max(120),
      email: z.string().email().max(180),
      phone: z.string().min(6).max(40),
      country: z.string().min(2).max(80),
      businessAddress: z.string().min(4).max(240),
      category: z.string().min(2).max(80),
      description: z.string().min(10).max(1200),
      registrationNumber: z.string().max(80).optional(),
      preferredPayoutMethod: z.string().min(2).max(100),
      payoutAccountMasked: z.string().max(100).optional(),
      verificationDocRef: z.string().max(240).optional(),
      shippingOrigin: z.string().min(2).max(120),
    });

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Complete all required supplier onboarding fields.' });
    }

    const store = await getStore();
    const existing = Object.values(store.suppliers).find(
      (s) => s.ownerUid === req.authUser!.uid
    );
    if (existing) {
      return res.status(409).json({ error: 'You already have a supplier profile registered.' });
    }

    const now = new Date().toISOString();
    const supplier: SupplierProfile = {
      id: generateId('sup'),
      ownerUid: req.authUser!.uid,
      ...parsed.data,
      documentsVerified: false,
      status: store.settings.requireSupplierApproval ? 'PENDING_REVIEW' : 'APPROVED',
      subscriptionPlan: 'free_standard',
      createdAt: now,
      updatedAt: now,
    };

    await upsertSupplier(supplier);

    if (req.authUser!.role === 'customer') {
      const updatedUser = { ...req.authUser!, role: 'supplier' as const, updatedAt: now };
      await upsertUser(updatedUser);
    }

    await appendAuditLog({
      actorUid: req.authUser!.uid,
      actorEmail: req.authUser!.email,
      actorRole: req.authUser!.role,
      action: 'SUPPLIER_REGISTERED',
      targetType: 'supplier',
      targetId: supplier.id,
      details: `${supplier.businessName} (${supplier.country}) submitted application.`,
    });

    for (const adminUid of getAllStaffAndAdminUids(store)) {
      await createNotification({
        recipientUid: adminUid,
        type: 'supplier',
        title: `New Supplier Registration: ${supplier.businessName}`,
        message: `${supplier.ownerFullName} (${supplier.country}) registered and awaits KYC verification.`,
        targetType: 'supplier',
        targetId: supplier.id,
      });
    }

    res.json({ supplier });
  });

  app.get(
    '/api/supplier/workspace',
    requireAuth,
    requireRoles('supplier', 'super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) {
        return res.status(404).json({ error: 'No supplier profile linked to this account.' });
      }

      // Check fulfillment SLA deadline reminders for released suborders
      const nowMs = Date.now();
      for (const s of Object.values(store.suborders)) {
        if (
          s.supplierId === supplier.id &&
          ((s.paymentStatus === 'CONFIRMED' && s.fulfillmentReleased !== false) ||
            s.adminExceptionReleased === true) &&
          s.status === 'Awaiting Supplier Confirmation' &&
          !s.delayedAlertTriggered &&
          new Date(s.responseDeadlineAt).getTime() < nowMs
        ) {
          s.delayedAlertTriggered = true;
          await upsertSuborder(s);
          await createNotification({
            recipientUid: supplier.ownerUid,
            type: 'fulfillment',
            title: `Fulfillment Deadline Reminder (${s.id})`,
            message: `Suborder ${s.id} has passed its confirmation SLA deadline. Please confirm stock and dispatch promptly.`,
            targetType: 'suborder',
            targetId: s.id,
          });
          for (const adminUid of getAllStaffAndAdminUids(store)) {
            await createNotification({
              recipientUid: adminUid,
              type: 'fulfillment',
              title: `Delayed Supplier Fulfillment (${s.id})`,
              message: `${s.supplierName} exceeded confirmation deadline on suborder ${s.id}.`,
              targetType: 'suborder',
              targetId: s.id,
            });
          }
        }
      }

      // Strict data isolation & Payment Verification Gate:
      // Suppliers ONLY see suborders whose payment was verified/released OR explicit documented Admin exception.
      // Once released to the supplier, completed/cancelled/refunded historical suborders MUST remain permanently visible.
      const products = Object.values(store.products).filter(
        (p) => p.supplierId === supplier.id
      );
      const suborders = Object.values(store.suborders)
        .filter(
          (s) =>
            s.supplierId === supplier.id &&
            s.supplierOwnerUid === supplier.ownerUid &&
            (s.fulfillmentReleased === true ||
              s.paymentStatus === 'CONFIRMED' ||
              s.paymentStatus === 'REFUNDED' ||
              s.paymentStatus === 'PARTIALLY_REFUNDED' ||
              s.adminExceptionReleased === true)
        )
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const payouts = Object.values(store.payouts)
        .filter((p) => p.supplierId === supplier.id)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const refunds = Object.values(store.refunds).filter(
        (r) => r.supplierId === supplier.id
      );
      const productIds = new Set(products.map((p) => p.id));
      const reviews = Object.values(store.reviews).filter((r) => productIds.has(r.productId));
      const earnings = calculateSupplierEarningsSummary(store, supplier.id);

      res.json({
        supplier,
        products,
        suborders,
        payouts,
        refunds,
        reviews,
        earnings,
        integrations: getSupplierIntegrationsStatus(),
      });
    }
  );

  // Dedicated paginated & filterable Supplier Order History Center with strict owner isolation
  app.get(
    '/api/supplier/orders',
    requireAuth,
    requireRoles('supplier', 'super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) {
        return res.status(404).json({ error: 'No supplier profile linked to this account.' });
      }

      const statusGroup = String(req.query.statusGroup || 'ALL');
      const q = String(req.query.q || '').trim().toLowerCase();
      const page = Math.max(1, Number(req.query.page || 1) || 1);
      const limit = Math.min(100, Math.max(1, Number(req.query.limit || 25) || 25));

      let list = Object.values(store.suborders)
        .filter(
          (s) =>
            s.supplierId === supplier.id &&
            s.supplierOwnerUid === supplier.ownerUid &&
            (s.fulfillmentReleased === true ||
              s.paymentStatus === 'CONFIRMED' ||
              s.paymentStatus === 'REFUNDED' ||
              s.paymentStatus === 'PARTIALLY_REFUNDED' ||
              s.adminExceptionReleased === true)
        )
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

      if (statusGroup === 'AWAITING_ACTION') {
        list = list.filter(
          (s) =>
            s.status === 'Payment Confirmed' ||
            s.status === 'Awaiting Supplier Confirmation' ||
            s.status === 'Supplier Confirmed'
        );
      } else if (statusGroup === 'PROCESSING') {
        list = list.filter((s) => s.status === 'Processing' || s.status === 'Ready for Shipping');
      } else if (statusGroup === 'SHIPPED') {
        list = list.filter((s) => s.status === 'Shipped' || s.status === 'In Transit');
      } else if (statusGroup === 'COMPLETED') {
        list = list.filter((s) => s.status === 'Delivered' || s.status === 'Completed');
      } else if (statusGroup === 'CANCELLED_REFUNDED') {
        list = list.filter(
          (s) =>
            s.status === 'Cancelled' ||
            s.status === 'Cancellation Requested' ||
            s.status === 'Refund Requested' ||
            s.status === 'Partially Refunded' ||
            s.status === 'Refunded'
        );
      } else if (statusGroup !== 'ALL') {
        list = list.filter((s) => s.status === statusGroup);
      }

      if (q) {
        list = list.filter(
          (s) =>
            s.id.toLowerCase().includes(q) ||
            s.orderId.toLowerCase().includes(q) ||
            s.customerShippingName.toLowerCase().includes(q) ||
            s.customerShippingCity.toLowerCase().includes(q) ||
            (s.trackingNumber || '').toLowerCase().includes(q) ||
            s.items.some((it) => it.title.toLowerCase().includes(q) || it.sku.toLowerCase().includes(q))
        );
      }

      const total = list.length;
      const totalPages = Math.max(1, Math.ceil(total / limit));
      const suborders = list.slice((page - 1) * limit, page * limit);

      res.json({
        suborders,
        pagination: { page, pageSize: limit, total, totalPages, hasMore: page < totalPages },
      });
    }
  );

  app.patch(
    '/api/supplier/profile',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) return res.status(404).json({ error: 'Supplier not found' });

      const schema = z.object({
        businessName: z.string().min(2).max(140).optional(),
        phone: z.string().min(6).max(40).optional(),
        businessAddress: z.string().min(4).max(240).optional(),
        description: z.string().min(10).max(1200).optional(),
        preferredPayoutMethod: z.string().min(2).max(100).optional(),
        payoutAccountMasked: z.string().max(100).optional(),
        shippingOrigin: z.string().min(2).max(120).optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid supplier profile fields' });

      const updated: SupplierProfile = {
        ...supplier,
        ...parsed.data,
        updatedAt: new Date().toISOString(),
      };
      await upsertSupplier(updated);
      res.json({ supplier: updated });
    }
  );

  // Helper to validate product image URLs (rejects temporary browser blob:/data: URIs and enforces ownership on internal media)
  function validateProductImageUrls(
    images: string[],
    supplierOwnerUid: string,
    isAdminActor: boolean,
    store: Awaited<ReturnType<typeof getStore>>
  ): string | null {
    for (const rawUrl of images) {
      const url = rawUrl.trim();
      if (!url) return 'Empty image URL is not allowed.';
      if (url.startsWith('blob:') || url.startsWith('data:')) {
        return 'Temporary browser preview URLs cannot be saved as permanent product images. Please upload image files through the uploader.';
      }
      const mediaId = extractMediaIdFromUrl(url);
      if (mediaId) {
        const meta = store.productImages[mediaId];
        if (!meta) return `Uploaded image ${mediaId} could not be found in storage.`;
        if (!isAdminActor && meta.supplierOwnerUid !== supplierOwnerUid) {
          return 'Access denied: cannot attach another supplier’s uploaded image.';
        }
        continue;
      }
      if (url.startsWith('/src/assets/images/')) continue;
      if (/^https?:\/\//i.test(url)) {
        try {
          const parsedUrl = new URL(url);
          if (parsedUrl.pathname.toLowerCase().endsWith('.svg')) {
            return 'SVG image URLs are not permitted.';
          }
          continue;
        } catch {
          return `Invalid image URL: ${url}`;
        }
      }
      return `Unsupported image URL format: ${url}`;
    }
    return null;
  }

  async function cleanupOrphanedImages(store: Awaited<ReturnType<typeof getStore>>, candidateUrls: string[]) {
    const orphanIds = findOrphanedMediaIds(store, candidateUrls);
    for (const imgId of orphanIds) {
      const meta = store.productImages[imgId];
      if (meta) {
        deleteProductImageFile(meta);
        await deleteProductImageRecord(imgId);
      }
    }
  }

  // Supplier Product Image Upload Endpoint (Binary upload with strict magic-byte & size checks)
  app.post(
    '/api/supplier/product-images',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    express.raw({
      type: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'application/octet-stream'],
      limit: '6mb',
    }),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) {
        return res.status(404).json({ error: 'Supplier profile required before uploading images.' });
      }
      if (supplier.status === 'SUSPENDED' || supplier.status === 'REJECTED') {
        return res.status(403).json({
          error: `Supplier account (${supplier.status}) cannot upload product images.`,
        });
      }

      const buffer = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      if (buffer.length === 0) {
        return res.status(400).json({ error: 'No image binary received.' });
      }
      if (buffer.length > MAX_PRODUCT_IMAGE_BYTES) {
        return res.status(400).json({ error: 'Image exceeds the 5 MB maximum upload size.' });
      }

      const detectedMime = detectImageMimeFromBuffer(buffer);
      if (!detectedMime) {
        return res.status(400).json({
          error: 'Unsupported or corrupted image file. Only valid JPG, JPEG, PNG, and WEBP images are allowed.',
        });
      }

      const declaredType = String(req.headers['content-type'] || '').toLowerCase();
      const normalizedDeclared =
        declaredType === 'image/jpg' ? 'image/jpeg' : declaredType.split(';')[0].trim();
      if (
        normalizedDeclared &&
        normalizedDeclared !== 'application/octet-stream' &&
        normalizedDeclared !== detectedMime
      ) {
        return res.status(400).json({
          error: `File content (${detectedMime}) does not match declared MIME type (${normalizedDeclared}).`,
        });
      }

      const rawName = String(req.headers['x-file-name'] || 'product-image');
      let decodedName = rawName;
      try {
        decodedName = decodeURIComponent(rawName);
      } catch {
        // Use raw header if not URI-encoded
      }
      const fileName = sanitizeFileName(decodedName);
      const productIdHeader = String(req.headers['x-product-id'] || '').trim();
      if (productIdHeader) {
        const existingProd = store.products[productIdHeader];
        if (!existingProd || (existingProd.supplierOwnerUid !== req.authUser!.uid && req.authUser!.role !== 'super_admin')) {
          return res.status(403).json({ error: 'Cannot attach image to another supplier’s product.' });
        }
      }

      const imageId = generateId('img');
      saveProductImageFile(supplier.id, imageId, detectedMime as AllowedImageMime, buffer);

      const meta: ProductImageMeta = {
        id: imageId,
        productId: productIdHeader || undefined,
        supplierId: supplier.id,
        supplierOwnerUid: supplier.ownerUid,
        url: `/api/media/products/${imageId}`,
        fileName,
        mimeType: detectedMime,
        sizeBytes: buffer.length,
        storageProvider: 'local_media',
        createdAt: new Date().toISOString(),
      };
      await upsertProductImage(meta);
      res.json({ image: meta });
    }
  );

  app.delete(
    '/api/supplier/product-images/:imageId',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const meta = store.productImages[req.params.imageId];
      if (!meta) return res.status(404).json({ error: 'Image not found' });
      if (meta.supplierOwnerUid !== req.authUser!.uid && req.authUser!.role !== 'super_admin') {
        return res.status(403).json({ error: 'Access denied to another supplier’s image.' });
      }

      // Remove reference from owning product if requested explicitly, unless it would leave 0 images on a published product
      const mediaUrl = `/api/media/products/${meta.id}`;
      const usingProds = Object.values(store.products).filter((p) =>
        (p.images || []).includes(mediaUrl)
      );
      if (usingProds.length > 0) {
        return res.status(409).json({
          error: 'Image is currently attached to a saved product. Remove it from the product first and save changes.',
        });
      }

      deleteProductImageFile(meta);
      await deleteProductImageRecord(meta.id);
      res.json({ deleted: true, imageId: meta.id });
    }
  );

  app.post(
    '/api/supplier/products',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) return res.status(404).json({ error: 'Supplier profile required.' });
      if (supplier.status === 'SUSPENDED' || supplier.status === 'REJECTED') {
        return res.status(403).json({
          error: `Your supplier account (${supplier.status}) cannot submit products.`,
        });
      }

      const submitMode = req.body?.submitMode === 'DRAFT' ? 'DRAFT' : 'PENDING_APPROVAL';
      if (submitMode === 'PENDING_APPROVAL' && supplier.status !== 'APPROVED') {
        return res.status(403).json({
          error: 'Only APPROVED suppliers may submit products for Admin approval. You may save as DRAFT meanwhile.',
        });
      }

      const schema = z.object({
        title: z.string().min(2).max(160),
        brand: z.string().max(80).optional(),
        material: z.string().max(100).optional(),
        weightKg: z.number().nonnegative().max(100).optional(),
        gender: z.enum(['MEN', 'WOMEN', 'UNISEX']),
        category: z.string().min(2).max(64),
        description: z.string().min(10).max(2000),
        images: z
          .array(z.string().min(1).max(2000))
          .min(submitMode === 'DRAFT' ? 0 : 1, 'At least one product image is required before submission.')
          .max(8),
        videoUrl: z.string().max(400).optional(),
        wholesalePriceUsd: z.number().positive(),
        shippingOriginCountry: z.string().min(2).max(80).optional(),
        shippingDestinations: z.array(z.string()).min(1).optional(),
        estimatedDaysMin: z.number().int().min(1).max(60),
        estimatedDaysMax: z.number().int().min(1).max(90),
        shippingFeeUsd: z.number().nonnegative(),
        shippingNotes: z.string().max(400).optional(),
        returnPolicySummary: z.string().min(5).max(300),
        submitMode: z.enum(['DRAFT', 'PENDING_APPROVAL']).optional(),
        variants: z
          .array(
            z.object({
              sku: z.string().min(2).max(60),
              size: z.string().min(1).max(30),
              color: z.string().min(1).max(40),
              stock: z.number().int().nonnegative(),
            })
          )
          .min(1),
      });

      const parsed = schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          error: parsed.error.issues[0]?.message || 'Invalid product fields',
          details: parsed.error.issues,
        });
      }

      const imgErr = validateProductImageUrls(
        parsed.data.images,
        supplier.ownerUid,
        req.authUser!.role === 'super_admin',
        store
      );
      if (imgErr) {
        return res.status(400).json({ error: imgErr });
      }

      const now = new Date().toISOString();
      const id = generateId('prd');
      const totalStock = parsed.data.variants.reduce((a, v) => a + v.stock, 0);
      const baseWholesale = round2(parsed.data.wholesalePriceUsd);

      const attachedMeta: ProductImageMeta[] = [];
      for (let idx = 0; idx < parsed.data.images.length; idx++) {
        const url = parsed.data.images[idx];
        const mId = extractMediaIdFromUrl(url);
        if (mId && store.productImages[mId]) {
          const meta = store.productImages[mId];
          meta.productId = id;
          meta.isPrimary = idx === 0;
          meta.sortOrder = idx;
          await upsertProductImage(meta);
          attachedMeta.push(meta);
        }
      }

      const { submitMode: _ignoreMode, ...cleanData } = parsed.data;
      const product: Product = {
        ...cleanData,
        id,
        supplierId: supplier.id,
        supplierOwnerUid: supplier.ownerUid,
        supplierName: supplier.businessName,
        supplierCountry: supplier.country,
        brand: cleanData.brand?.trim() || supplier.businessName,
        shippingOriginCountry: cleanData.shippingOriginCountry?.trim() || supplier.country,
        shippingDestinations: cleanData.shippingDestinations || [
          'Tanzania',
          'Kenya',
          'United Kingdom',
          'United States',
          'International',
        ],
        imageMetadata: attachedMeta,
        wholesalePriceUsd: baseWholesale,
        // Supplier never sets selling markup or publishes directly; starts at base cost until Admin sets markup
        sellingPriceUsd: baseWholesale,
        slug: `${cleanData.title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${id.slice(-5)}`,
        totalStock,
        status: submitMode,
        isPublished: false,
        featured: false,
        isNewArrival: true,
        isBestSeller: false,
        ratingAvg: 0,
        ratingCount: 0,
        createdAt: now,
        updatedAt: now,
      };
      await upsertProduct(product);

      if (submitMode === 'PENDING_APPROVAL') {
        for (const adminUid of getAllStaffAndAdminUids(store)) {
          await createNotification({
            recipientUid: adminUid,
            type: 'product',
            title: `Product Awaiting Approval: ${product.title}`,
            message: `${supplier.businessName} submitted "${product.title}" with ${product.images.length} photo(s) (supplier price $${product.wholesalePriceUsd} USD) for Admin pricing & approval.`,
            targetType: 'product',
            targetId: product.id,
          });
        }
      }
      res.json({ product });
    }
  );

  app.put(
    '/api/supplier/products/:productId',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const product = store.products[req.params.productId];
      if (!product) return res.status(404).json({ error: 'Product not found' });

      const isAdminActor = req.authUser!.role === 'super_admin';
      if (product.supplierOwnerUid !== req.authUser!.uid && !isAdminActor) {
        return res.status(403).json({ error: 'Access denied to another supplier product.' });
      }

      const supplier = Object.values(store.suppliers).find((s) => s.id === product.supplierId);
      const schema = z.object({
        title: z.string().min(2).max(160).optional(),
        brand: z.string().max(80).optional(),
        material: z.string().max(100).optional().nullable(),
        weightKg: z.number().nonnegative().max(100).optional().nullable(),
        gender: z.enum(['MEN', 'WOMEN', 'UNISEX']).optional(),
        category: z.string().min(2).max(64).optional(),
        description: z.string().min(10).max(2000).optional(),
        images: z.array(z.string().min(1).max(2000)).max(8).optional(),
        wholesalePriceUsd: z.number().positive().optional(),
        sellingPriceUsd: z.number().positive().optional(),
        shippingFeeUsd: z.number().nonnegative().optional(),
        shippingOriginCountry: z.string().min(2).max(80).optional(),
        shippingDestinations: z.array(z.string()).min(1).optional(),
        estimatedDaysMin: z.number().int().min(1).max(60).optional(),
        estimatedDaysMax: z.number().int().min(1).max(90).optional(),
        shippingNotes: z.string().max(400).optional().nullable(),
        returnPolicySummary: z.string().min(5).max(300).optional(),
        action: z.enum(['SAVE_DRAFT', 'SUBMIT_FOR_APPROVAL']).optional(),
        variants: z
          .array(
            z.object({
              sku: z.string().min(2).max(60),
              size: z.string().min(1).max(30),
              color: z.string().min(1).max(40),
              stock: z.number().int().nonnegative(),
            })
          )
          .min(1)
          .optional(),
      });

      const parsed = schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          error: parsed.error.issues[0]?.message || 'Invalid product update payload.',
        });
      }

      const updates = parsed.data;
      const nextImages = updates.images ?? product.images;
      const targetAction = updates.action;

      if (targetAction === 'SUBMIT_FOR_APPROVAL') {
        if (supplier && supplier.status !== 'APPROVED' && !isAdminActor) {
          return res.status(403).json({
            error: 'Only APPROVED suppliers may submit products for Admin approval.',
          });
        }
        if (nextImages.length < 1) {
          return res.status(400).json({
            error: 'At least one product image is required before submitting for approval.',
          });
        }
      }

      if (updates.images) {
        const imgErr = validateProductImageUrls(
          updates.images,
          product.supplierOwnerUid,
          isAdminActor,
          store
        );
        if (imgErr) return res.status(400).json({ error: imgErr });
      }

      const prevImages = [...(product.images || [])];
      const removedImages = prevImages.filter((url) => !nextImages.includes(url));

      const variants = updates.variants ?? product.variants;
      const newWholesale =
        typeof updates.wholesalePriceUsd === 'number'
          ? round2(updates.wholesalePriceUsd)
          : product.wholesalePriceUsd;
      const wholesaleChanged = newWholesale !== product.wholesalePriceUsd;
      const coreChanged =
        wholesaleChanged ||
        Boolean(updates.title && updates.title !== product.title) ||
        Boolean(updates.images && JSON.stringify(updates.images) !== JSON.stringify(product.images));

      let nextStatus: ProductStatus = product.status;
      let nextPublished = Boolean(product.isPublished);

      if (targetAction === 'SAVE_DRAFT') {
        if (isProductLiveOnStorefront(product) && !isAdminActor) {
          nextPublished = false;
        }
        nextStatus = 'DRAFT';
      } else if (targetAction === 'SUBMIT_FOR_APPROVAL') {
        nextStatus = 'PENDING_APPROVAL';
        nextPublished = false;
      } else if (!isAdminActor && coreChanged && (product.status === 'APPROVED' || product.status === 'PUBLISHED')) {
        // Edits to published/approved price/title/images require fresh Admin approval
        nextStatus = 'PENDING_APPROVAL';
        nextPublished = false;
      }

      const attachedMeta: ProductImageMeta[] = [];
      for (let idx = 0; idx < nextImages.length; idx++) {
        const url = nextImages[idx];
        const mId = extractMediaIdFromUrl(url);
        if (mId && store.productImages[mId]) {
          const meta = store.productImages[mId];
          meta.productId = product.id;
          meta.isPrimary = idx === 0;
          meta.sortOrder = idx;
          await upsertProductImage(meta);
          attachedMeta.push(meta);
        }
      }

      const updated: Product = {
        ...product,
        title: updates.title ?? product.title,
        brand: updates.brand ?? product.brand,
        material: updates.material === null ? undefined : (updates.material ?? product.material),
        weightKg: updates.weightKg === null ? undefined : (updates.weightKg ?? product.weightKg),
        gender: updates.gender ?? product.gender,
        category: updates.category ?? product.category,
        description: updates.description ?? product.description,
        images: nextImages,
        imageMetadata: attachedMeta.length > 0 ? attachedMeta : product.imageMetadata,
        shippingOriginCountry: updates.shippingOriginCountry ?? product.shippingOriginCountry,
        shippingDestinations: updates.shippingDestinations ?? product.shippingDestinations,
        estimatedDaysMin: updates.estimatedDaysMin ?? product.estimatedDaysMin,
        estimatedDaysMax: updates.estimatedDaysMax ?? product.estimatedDaysMax,
        shippingNotes: updates.shippingNotes === null ? undefined : (updates.shippingNotes ?? product.shippingNotes),
        returnPolicySummary: updates.returnPolicySummary ?? product.returnPolicySummary,
        sellingPriceUsd:
          isAdminActor && typeof updates.sellingPriceUsd === 'number'
            ? round2(updates.sellingPriceUsd)
            : wholesaleChanged
              ? Math.max(product.sellingPriceUsd, newWholesale)
              : product.sellingPriceUsd,
        wholesalePriceUsd: newWholesale,
        shippingFeeUsd:
          typeof updates.shippingFeeUsd === 'number'
            ? round2(updates.shippingFeeUsd)
            : product.shippingFeeUsd,
        status: nextStatus,
        isPublished: nextPublished,
        adminRejectionReason:
          nextStatus === 'PENDING_APPROVAL' ? undefined : product.adminRejectionReason,
        adminChangeRequestMessage:
          nextStatus === 'PENDING_APPROVAL' ? undefined : product.adminChangeRequestMessage,
        variants,
        totalStock: variants.reduce((a, v) => a + v.stock, 0),
        updatedAt: new Date().toISOString(),
      };
      await upsertProduct(updated);

      if (removedImages.length > 0) {
        await cleanupOrphanedImages(store, removedImages);
      }

      if (nextStatus === 'PENDING_APPROVAL' && (targetAction === 'SUBMIT_FOR_APPROVAL' || coreChanged)) {
        for (const adminUid of getAllStaffAndAdminUids(store)) {
          await createNotification({
            recipientUid: adminUid,
            type: 'product',
            title: `Product Resubmitted for Approval: ${updated.title}`,
            message: `${updated.supplierName} submitted updates to "${updated.title}" for Admin review & pricing.`,
            targetType: 'product',
            targetId: updated.id,
          });
        }
      }

      res.json({ product: updated });
    }
  );

  app.patch(
    '/api/supplier/products/:productId/reorder-images',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const product = store.products[req.params.productId];
      if (!product) return res.status(404).json({ error: 'Product not found' });
      const isAdminActor = req.authUser!.role === 'super_admin';
      if (product.supplierOwnerUid !== req.authUser!.uid && !isAdminActor) {
        return res.status(403).json({ error: 'Access denied to another supplier product.' });
      }
      const schema = z.object({
        images: z.array(z.string().min(1).max(2000)).min(1).max(8),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Provide ordered list of product image URLs.' });
      }
      const imgErr = validateProductImageUrls(
        parsed.data.images,
        product.supplierOwnerUid,
        isAdminActor,
        store
      );
      if (imgErr) return res.status(400).json({ error: imgErr });

      const removed = (product.images || []).filter((u) => !parsed.data.images.includes(u));
      const attachedMeta: ProductImageMeta[] = [];
      for (let idx = 0; idx < parsed.data.images.length; idx++) {
        const mId = extractMediaIdFromUrl(parsed.data.images[idx]);
        if (mId && store.productImages[mId]) {
          const meta = store.productImages[mId];
          meta.productId = product.id;
          meta.isPrimary = idx === 0;
          meta.sortOrder = idx;
          await upsertProductImage(meta);
          attachedMeta.push(meta);
        }
      }
      product.images = parsed.data.images;
      if (attachedMeta.length > 0) product.imageMetadata = attachedMeta;
      product.updatedAt = new Date().toISOString();
      await upsertProduct(product);
      if (removed.length > 0) {
        await cleanupOrphanedImages(store, removed);
      }
      res.json({ product });
    }
  );

  app.get(
    '/api/supplier/analytics',
    requireAuth,
    requireRoles('supplier', 'super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) {
        return res.status(404).json({ error: 'No supplier profile linked to this account.' });
      }
      const range = typeof req.query.range === 'string' ? req.query.range : '30d';
      const from = typeof req.query.from === 'string' ? req.query.from : undefined;
      const to = typeof req.query.to === 'string' ? req.query.to : undefined;
      const metrics = computeSupplierAnalytics(store, supplier.id, range, from, to);
      const reports = Object.values(store.aiReports)
        .filter((r) => r.scope === 'supplier' && r.supplierId === supplier.id)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .slice(0, 12);

      res.json({
        metrics,
        reports,
        geminiConfigured: isGeminiConfigured(),
      });
    }
  );

  app.post(
    '/api/supplier/ai-report',
    requireAuth,
    requireRoles('supplier', 'super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) {
        return res.status(404).json({ error: 'No supplier profile linked to this account.' });
      }
      const range = typeof req.body?.range === 'string' ? req.body.range : '30d';
      const from = typeof req.body?.from === 'string' ? req.body.from : undefined;
      const to = typeof req.body?.to === 'string' ? req.body.to : undefined;

      const metrics = computeSupplierAnalytics(store, supplier.id, range, from, to);
      const aiContent = await generateSupplierAiReport(metrics, supplier.businessName);
      const report: AiReportRecord = {
        id: generateId('rep'),
        scope: 'supplier',
        supplierId: supplier.id,
        requestedByUid: req.authUser!.uid,
        rangeLabel: metrics.rangeLabel,
        aiGenerated: aiContent.aiGenerated,
        model: aiContent.model,
        statusMessage: aiContent.statusMessage,
        executiveSummary: aiContent.executiveSummary,
        highlights: aiContent.highlights,
        actionableRecommendations: aiContent.actionableRecommendations,
        risksAndAlerts: aiContent.risksAndAlerts,
        metricsSnapshot: {
          totalProductViews: metrics.totalProductViews,
          totalOrders: metrics.totalOrders,
          grossSalesUsd: metrics.grossSalesUsd,
          netEarningsUsd: metrics.netEarningsUsd,
          slaOnTimePct: metrics.slaOnTimePct,
        },
        createdAt: new Date().toISOString(),
      };
      await upsertAiReport(report);
      res.json({ report, metrics });
    }
  );

  app.delete(
    '/api/supplier/products/:productId',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const product = store.products[req.params.productId];
      if (!product) return res.status(404).json({ error: 'Product not found' });
      if (product.supplierOwnerUid !== req.authUser!.uid && req.authUser!.role !== 'super_admin') {
        return res.status(403).json({ error: 'Access denied to another supplier product.' });
      }

      const hasSuborderHistory = Object.values(store.suborders).some((s) =>
        s.items.some((i) => i.productId === product.id)
      );
      if (hasSuborderHistory) {
        return res.status(409).json({
          error: 'Products referenced by existing customer orders cannot be permanently deleted. Contact Admin to archive it instead.',
        });
      }

      const candidateUrls = [...(product.images || [])];
      await deleteProductRecord(product.id);
      await cleanupOrphanedImages(store, candidateUrls);

      res.json({ deleted: true, productId: product.id });
    }
  );

  app.post(
    '/api/supplier/products/csv-preview',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) {
        return res.status(404).json({ error: 'Supplier profile required.' });
      }

      const csvText = String(req.body?.csvText || '');
      const localImages = Array.isArray(req.body?.localImages)
        ? (req.body.localImages as UploadedCsvImageRef[]).filter((img) => {
            const mediaId = extractMediaIdFromUrl(img.url || '');
            if (!mediaId) return true;
            const meta = store.productImages[mediaId];
            return Boolean(meta && (meta.supplierOwnerUid === supplier.ownerUid || req.authUser!.role === 'super_admin'));
          })
        : [];

      try {
        const preview = validateAndPreviewCsvProducts(
          csvText,
          supplier.id,
          supplier.ownerUid,
          supplier.businessName,
          supplier.country,
          localImages
        );
        res.json({
          rows: preview.rows.map(({ product: _omit, ...row }) => row),
          validCount: preview.validCount,
          errorCount: preview.errorCount,
        });
      } catch (err: any) {
        res.status(400).json({ error: err.message || 'Invalid CSV format' });
      }
    }
  );

  app.post(
    '/api/supplier/products/csv-import',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier || supplier.status !== 'APPROVED') {
        return res.status(403).json({ error: 'Approved supplier profile required to import products.' });
      }
      const csvText = String(req.body?.csvText || '');
      const localImages = Array.isArray(req.body?.localImages)
        ? (req.body.localImages as UploadedCsvImageRef[]).filter((img) => {
            const mediaId = extractMediaIdFromUrl(img.url || '');
            if (!mediaId) return true;
            const meta = store.productImages[mediaId];
            return Boolean(meta && (meta.supplierOwnerUid === supplier.ownerUid || req.authUser!.role === 'super_admin'));
          })
        : [];

      try {
        const imported = parseCsvProducts(
          csvText,
          supplier.id,
          supplier.ownerUid,
          supplier.businessName,
          supplier.country,
          store.settings.requireProductApproval,
          localImages
        );
        for (const prod of imported) {
          for (let idx = 0; idx < prod.images.length; idx++) {
            const mId = extractMediaIdFromUrl(prod.images[idx]);
            if (mId && store.productImages[mId]) {
              const meta = store.productImages[mId];
              meta.productId = prod.id;
              meta.isPrimary = idx === 0;
              meta.sortOrder = idx;
              await upsertProductImage(meta);
            }
          }
          await upsertProduct(prod);
        }
        if (imported.length > 0) {
          for (const adminUid of getAllStaffAndAdminUids(store)) {
            await createNotification({
              recipientUid: adminUid,
              type: 'product',
              title: `${imported.length} CSV Product(s) Awaiting Approval`,
              message: `${supplier.businessName} imported ${imported.length} product(s) awaiting Admin pricing & approval.`,
              targetType: 'product',
              targetId: imported[0].id,
            });
          }
        }
        res.json({ importedCount: imported.length, products: imported });
      } catch (err: any) {
        res.status(400).json({ error: err.message || 'Invalid CSV format' });
      }
    }
  );

  app.patch(
    '/api/supplier/suborders/:suborderId/status',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const sub = store.suborders[req.params.suborderId];
      if (!sub) return res.status(404).json({ error: 'Suborder not found' });
      if (sub.supplierOwnerUid !== req.authUser!.uid && req.authUser!.role !== 'super_admin') {
        return res.status(403).json({ error: 'Supplier data isolation violation blocked.' });
      }
      if (sub.paymentStatus !== 'CONFIRMED' && sub.adminExceptionReleased !== true) {
        return res.status(400).json({
          error: 'Cannot fulfill an order before Admin verifies customer payment.',
        });
      }
      if (sub.fulfillmentReleased === false && sub.adminExceptionReleased !== true) {
        return res.status(400).json({
          error: 'This order is awaiting Admin release to your store for fulfillment.',
        });
      }

      const schema = z.object({
        status: z.enum([
          'Supplier Confirmed',
          'Processing',
          'Ready for Shipping',
          'Shipped',
          'In Transit',
          'Delivered',
        ]),
        carrierName: z.string().max(80).optional(),
        trackingNumber: z.string().max(120).optional(),
        trackingUrl: z.string().max(300).optional(),
        note: z.string().max(300).optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid fulfillment update' });

      if (
        (parsed.data.status === 'Shipped' || parsed.data.status === 'In Transit') &&
        !parsed.data.trackingNumber &&
        !sub.trackingNumber
      ) {
        return res.status(400).json({
          error: 'Carrier tracking number is required when marking an order Shipped.',
        });
      }

      const prevStatus = sub.status;
      const now = new Date().toISOString();
      sub.status = parsed.data.status;
      if (parsed.data.carrierName) sub.carrierName = parsed.data.carrierName;
      if (parsed.data.trackingNumber) sub.trackingNumber = parsed.data.trackingNumber;
      if (parsed.data.trackingUrl) sub.trackingUrl = parsed.data.trackingUrl;
      sub.updatedAt = now;
      sub.statusHistory.push({
        status: parsed.data.status,
        timestamp: now,
        actor: req.authUser!.email,
        note: parsed.data.note || `Updated to ${parsed.data.status}`,
      });
      await upsertSuborder(sub);

      const order = store.orders[sub.orderId];
      if (order) {
        const siblings = order.suborderIds.map((id) => store.suborders[id]).filter(Boolean);
        order.overallStatus = computeOverallOrderStatus(siblings);
        order.updatedAt = now;
        await upsertOrder(order);
      }

      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'SUBORDER_STATUS_UPDATED',
        targetType: 'suborder',
        targetId: sub.id,
        targetUserId: sub.customerId,
        relatedOrderId: sub.orderId,
        previousValue: prevStatus,
        newValue: sub.status,
        technicalRef: sub.trackingNumber,
        details: `${sub.supplierName} updated suborder ${sub.id} (Order ${sub.orderId}) from ${prevStatus} -> ${sub.status}.`,
      });

      await createNotification({
        recipientUid: sub.customerId,
        type: 'fulfillment',
        priority: 'high',
        dedupeKey: `sub_status:${sub.id}:${sub.status}`,
        title: `Order ${sub.status} (${sub.orderId})`,
        message: sub.trackingNumber
          ? `${sub.supplierName} updated your shipment to ${sub.status} (${sub.carrierName || 'Carrier'}: ${sub.trackingNumber}).`
          : `${sub.supplierName} updated your order status to ${sub.status}.`,
        targetType: 'order',
        targetId: sub.orderId,
      });

      if (sub.status === 'Delivered') {
        for (const adminUid of getAllStaffAndAdminUids(store)) {
          await createNotification({
            recipientUid: adminUid,
            type: 'fulfillment',
            dedupeKey: `sub_delivered_adm:${sub.id}`,
            title: `Order Delivered (${sub.id})`,
            message: `${sub.supplierName} marked suborder ${sub.id} (Order ${sub.orderId}) as Delivered.`,
            targetType: 'order',
            targetId: sub.orderId,
          });
        }
      }

      res.json({ suborder: sub });
    }
  );

  app.post(
    '/api/supplier/payouts',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      if (!supplier) return res.status(404).json({ error: 'Supplier not found' });

      const schema = z.object({
        amountUsd: z.number().positive(),
        currency: z.enum(['TZS', 'USD', 'GBP', 'EUR', 'KES']).default('USD'),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid payout amount' });

      const earnings = calculateSupplierEarningsSummary(store, supplier.id);
      if (parsed.data.amountUsd > earnings.availableEarningsUsd) {
        return res.status(400).json({
          error: `Requested $${parsed.data.amountUsd} exceeds available settled balance ($${earnings.availableEarningsUsd}). Pending earnings cannot be withdrawn.`,
        });
      }

      const now = new Date().toISOString();
      const payout: SupplierPayout = {
        id: generateId('payreq'),
        supplierId: supplier.id,
        supplierName: supplier.businessName,
        amountUsd: round2(parsed.data.amountUsd),
        currency: parsed.data.currency,
        payoutMethod: supplier.preferredPayoutMethod,
        accountSummary: supplier.payoutAccountMasked || 'On file',
        status: 'REQUESTED',
        createdAt: now,
        updatedAt: now,
      };
      store.payouts[payout.id] = payout;
      await saveStore(store);
      res.json({ payout, earnings: calculateSupplierEarningsSummary(store, supplier.id) });
    }
  );

  app.post(
    '/api/supplier/refunds/:refundId/respond',
    requireAuth,
    requireRoles('supplier', 'super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = Object.values(store.suppliers).find(
        (s) => s.ownerUid === req.authUser!.uid
      );
      const refund = store.refunds[req.params.refundId];
      if (!refund || !supplier || refund.supplierId !== supplier.id) {
        return res.status(404).json({ error: 'Refund claim not found for your store.' });
      }
      const responseText = String(req.body?.supplierResponse || '').trim();
      if (responseText.length < 4) {
        return res.status(400).json({ error: 'Provide a substantive supplier response.' });
      }
      refund.supplierResponse = responseText;
      refund.status = 'SUPPLIER_RESPONDED';
      refund.updatedAt = new Date().toISOString();
      await saveStore(store);
      res.json({ refund });
    }
  );

  // ------------------------------------------------------------------
  // 5. SUPER ADMIN & STAFF CONTROL CENTER
  // ------------------------------------------------------------------
  app.get(
    '/api/admin/dashboard',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (_req, res) => {
      const store = await getStore();
      const users = Object.values(store.users);
      const suppliers = Object.values(store.suppliers);
      const products = Object.values(store.products);
      const orders = Object.values(store.orders);
      const suborders = Object.values(store.suborders);
      const payments = Object.values(store.payments);
      const paymentSubmissions = Object.values(store.paymentSubmissions)
        .map(sanitizeSubmissionForClient)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      const paymentAuditLogs = Object.values(store.paymentAuditLogs).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt)
      );
      const payouts = Object.values(store.payouts);
      const refunds = Object.values(store.refunds);
      const tickets = Object.values(store.tickets);
      const auditLogs = Object.values(store.auditLogs).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt)
      );

      const confirmedOrders = orders.filter((o) => o.paymentStatus === 'CONFIRMED');
      const confirmedSuborders = suborders.filter((s) => s.paymentStatus === 'CONFIRMED');

      const grossSalesUsd = round2(confirmedOrders.reduce((a, o) => a + o.totalUsd, 0));
      const commissionEarningsUsd = round2(
        confirmedSuborders.reduce((a, s) => a + s.marketplaceCommissionUsd, 0)
      );
      const supplierEarningsUsd = round2(
        confirmedSuborders.reduce((a, s) => a + s.supplierNetEarningsUsd, 0)
      );

      const nowMs = Date.now();
      const sevenDaysAgoMs = nowMs - 7 * 24 * 3600 * 1000;
      const delayedSuborders = suborders.filter(
        (s) =>
          s.status === 'Awaiting Supplier Confirmation' &&
          new Date(s.responseDeadlineAt).getTime() < nowMs
      );
      const lowStockProducts = products.filter((p) => p.totalStock <= 5);
      const verifiedSubmissions = paymentSubmissions.filter((s) => s.status === 'VERIFIED');
      const totalSupplierPayoutsUsd = round2(
        payouts
          .filter((p) => p.status === 'PAID')
          .reduce((a, p) => a + p.amountUsd, 0) +
          suborders
            .filter((s) => s.supplierSettlementStatus === 'SENT_TO_SUPPLIER')
            .reduce((a, s) => a + s.supplierNetEarningsUsd, 0)
      );
      const adminUidsSet = new Set(getAllStaffAndAdminUids(store));
      const unreadAdminNotifications = Object.values(store.notifications).filter(
        (n) => adminUidsSet.has(n.recipientUid) && !n.read && !n.hiddenByRecipient
      ).length;

      res.json({
        kpis: {
          totalRegisteredUsers: users.length,
          totalCustomers: users.filter((u) => u.role === 'customer').length,
          activeCustomersCount: users.filter((u) => u.role === 'customer' && u.status === 'active').length,
          registeredSuppliersCount: suppliers.length,
          approvedSuppliers: suppliers.filter((s) => s.status === 'APPROVED').length,
          pendingSuppliers: suppliers.filter((s) => s.status === 'PENDING_REVIEW').length,
          newRegistrations7d: users.filter((u) => new Date(u.createdAt).getTime() >= sevenDaysAgoMs).length,
          totalProducts: products.length,
          pendingProducts: products.filter(
            (p) => p.status === 'PENDING_APPROVAL' || p.status === 'CHANGES_REQUESTED'
          ).length,
          publishedProducts: products.filter((p) => isProductLiveOnStorefront(p)).length,
          totalOrders: orders.length,
          pendingOrdersCount: orders.filter(
            (o) =>
              o.overallStatus === 'Pending Payment' ||
              o.overallStatus === 'Awaiting Payment Verification' ||
              o.overallStatus === 'Awaiting Supplier Confirmation'
          ).length,
          awaitingFulfillment: suborders.filter(
            (s) =>
              s.status === 'Awaiting Supplier Confirmation' ||
              s.status === 'Supplier Confirmed' ||
              s.status === 'Processing'
          ).length,
          completedOrders: orders.filter(
            (o) => o.overallStatus === 'Delivered' || o.overallStatus === 'Completed'
          ).length,
          cancelledOrders: orders.filter((o) => o.overallStatus === 'Cancelled').length,
          refundRequests: refunds.filter(
            (r) => r.status !== 'REJECTED' && r.status !== 'REFUNDED'
          ).length,
          grossSalesUsd,
          commissionEarningsUsd,
          supplierEarningsUsd,
          verifiedPaymentsCount: verifiedSubmissions.length,
          totalVerifiedPaymentsUsd: grossSalesUsd,
          totalSupplierPayoutsUsd,
          unreadAdminNotifications,
          awaitingPaymentVerification: paymentSubmissions.filter(
            (s) => s.status === 'PENDING_VERIFICATION' || s.status === 'INFO_REQUESTED'
          ).length,
          delayedSubordersCount: delayedSuborders.length,
          lowStockCount: lowStockProducts.length,
        },
        users,
        suppliers,
        products,
        orders: orders.sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
        suborders: suborders.sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
        payments: payments.sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
        paymentSubmissions,
        paymentAuditLogs: paymentAuditLogs.slice(0, 150),
        payouts: payouts.sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
        refunds: refunds.sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
        tickets: tickets.sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
        commissionRules: Object.values(store.commissionRules),
        coupons: Object.values(store.coupons),
        shippingZones: Object.values(store.shippingZones),
        settings: store.settings,
        retentionPolicy: getEffectiveRetentionPolicy(store),
        paymentGateways: getPaymentGatewaysStatus(store.settings),
        supplierIntegrations: getSupplierIntegrationsStatus(),
        delayedSuborders,
        lowStockProducts,
        auditLogs: auditLogs.slice(0, 150),
      });
    }
  );

  // Dedicated Admin Payment Verification Endpoints
  app.get(
    '/api/admin/payment-submissions',
    requireAuth,
    requirePaymentVerifier,
    async (req, res) => {
      const store = await getStore();
      const statusFilter = String(req.query.status || 'ALL');
      const methodFilter = String(req.query.method || 'ALL');
      const queryText = String(req.query.q || '').trim().toLowerCase();
      const dateFrom = String(req.query.dateFrom || '').trim();
      const dateTo = String(req.query.dateTo || '').trim();

      let list = Object.values(store.paymentSubmissions).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt)
      );

      if (statusFilter !== 'ALL') {
        list = list.filter((s) => s.status === statusFilter);
      }
      if (methodFilter !== 'ALL') {
        list = list.filter((s) => s.paymentMethod === methodFilter);
      }
      if (queryText) {
        list = list.filter(
          (s) =>
            s.orderId.toLowerCase().includes(queryText) ||
            s.customerEmail.toLowerCase().includes(queryText) ||
            s.customerName.toLowerCase().includes(queryText) ||
            s.senderName.toLowerCase().includes(queryText) ||
            s.transactionId.toLowerCase().includes(queryText)
        );
      }
      if (dateFrom) {
        list = list.filter((s) => s.transactionDate >= dateFrom || s.createdAt.slice(0, 10) >= dateFrom);
      }
      if (dateTo) {
        list = list.filter((s) => s.transactionDate <= dateTo && s.createdAt.slice(0, 10) <= dateTo);
      }

      const paymentAuditLogs = Object.values(store.paymentAuditLogs)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .slice(0, 150);

      res.json({
        submissions: list.map(sanitizeSubmissionForClient),
        paymentAuditLogs,
      });
    }
  );

  app.patch(
    '/api/admin/payment-submissions/:submissionId/verify',
    requireAuth,
    requirePaymentVerifier,
    async (req: AuthRequest, res) => {
      const schema = z.object({
        action: z.enum(['APPROVE', 'REJECT', 'REQUEST_INFO']),
        reason: z.string().max(600).optional(),
        adminNotes: z.string().max(600).optional(),
      });
      const parsed = schema.safeParse(req.body || {});
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid verification action payload.' });
      }
      const result = await reviewPaymentSubmission({
        submissionId: req.params.submissionId,
        action: parsed.data.action,
        reason: parsed.data.reason,
        adminNotes: parsed.data.adminNotes,
        actor: req.authUser!,
      });
      if ('error' in result) {
        return res.status(result.status).json({ error: result.error });
      }
      res.json(result);
    }
  );

  app.patch(
    '/api/admin/suppliers/:supplierId',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const supplier = store.suppliers[req.params.supplierId];
      if (!supplier) return res.status(404).json({ error: 'Supplier not found' });

      const schema = z.object({
        status: z
          .enum(['REGISTERED', 'PENDING_REVIEW', 'APPROVED', 'REJECTED', 'SUSPENDED'])
          .optional(),
        documentsVerified: z.boolean().optional(),
        commissionRatePct: z.number().min(0).max(60).nullable().optional(),
      subscriptionPlan: z
          .enum(['free_standard', 'commission_standard', 'growth_featured', 'enterprise'])
          .optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid supplier update' });

      if (parsed.data.status) supplier.status = parsed.data.status;
      if (typeof parsed.data.documentsVerified === 'boolean') {
        supplier.documentsVerified = parsed.data.documentsVerified;
      }
      if (parsed.data.commissionRatePct === null) {
        delete supplier.commissionRatePct;
      } else if (typeof parsed.data.commissionRatePct === 'number') {
        supplier.commissionRatePct = parsed.data.commissionRatePct;
      }
      if (parsed.data.subscriptionPlan) {
        supplier.subscriptionPlan = parsed.data.subscriptionPlan;
      }
      supplier.updatedAt = new Date().toISOString();
      await upsertSupplier(supplier);

      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'SUPPLIER_UPDATED',
        targetType: 'supplier',
        targetId: supplier.id,
        details: `Status=${supplier.status}, DocsVerified=${supplier.documentsVerified}, Commission=${supplier.commissionRatePct ?? 'Global'}%`,
      });
      await createNotification({
        recipientUid: supplier.ownerUid,
        type: 'supplier',
        title: `Supplier Account Status: ${supplier.status}`,
        message: `Marketplace administration updated your supplier account status to ${supplier.status}.`,
        targetType: 'supplier',
        targetId: supplier.id,
      });

      res.json({ supplier });
    }
  );

  app.patch(
    '/api/admin/products/:productId',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const product = store.products[req.params.productId];
      if (!product) return res.status(404).json({ error: 'Product not found' });

      const schema = z.object({
        status: z
          .enum([
            'DRAFT',
            'PENDING_APPROVAL',
            'APPROVED',
            'PUBLISHED',
            'REJECTED',
            'CHANGES_REQUESTED',
            'ARCHIVED',
          ])
          .optional(),
        isPublished: z.boolean().optional(),
        adminRejectionReason: z.string().max(600).optional(),
        adminChangeRequestMessage: z.string().max(600).optional(),
        featured: z.boolean().optional(),
        isNewArrival: z.boolean().optional(),
        isBestSeller: z.boolean().optional(),
        sellingPriceUsd: z.number().positive().optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid product moderation input' });

      const {
        status: requestedStatus,
        isPublished: requestedPublish,
        adminRejectionReason,
        adminChangeRequestMessage,
        sellingPriceUsd,
        ...flags
      } = parsed.data;

      if (requestedStatus === 'REJECTED' && (!adminRejectionReason || adminRejectionReason.trim().length < 5)) {
        return res.status(400).json({ error: 'A clear rejection reason (minimum 5 characters) is mandatory.' });
      }
      if (
        requestedStatus === 'CHANGES_REQUESTED' &&
        (!adminChangeRequestMessage || adminChangeRequestMessage.trim().length < 5)
      ) {
        return res.status(400).json({
          error: 'A clear change request message (minimum 5 characters) is mandatory.',
        });
      }

      const prevStatus = product.status;
      const prevSelling = product.sellingPriceUsd;
      const nextSelling = typeof sellingPriceUsd === 'number' ? round2(sellingPriceUsd) : product.sellingPriceUsd;

      if (
        (requestedStatus === 'APPROVED' || requestedStatus === 'PUBLISHED') &&
        nextSelling < product.wholesalePriceUsd
      ) {
        return res.status(400).json({
          error: `Customer selling price ($${nextSelling}) cannot be lower than supplier base price ($${product.wholesalePriceUsd}).`,
        });
      }

      if (
        (requestedStatus === 'APPROVED' || requestedStatus === 'PUBLISHED') &&
        (!product.images || product.images.length === 0)
      ) {
        return res.status(400).json({
          error: 'Cannot approve or publish a product without at least one uploaded product image.',
        });
      }

      const now = new Date().toISOString();
      let nextStatus = requestedStatus ?? product.status;
      let nextPublished =
        typeof requestedPublish === 'boolean' ? requestedPublish : Boolean(product.isPublished);

      if (requestedStatus === 'PUBLISHED') {
        nextPublished = true;
        product.publishedAt = product.publishedAt || now;
      } else if (requestedStatus === 'APPROVED') {
        nextPublished = typeof requestedPublish === 'boolean' ? requestedPublish : false;
        if (nextPublished) {
          nextStatus = 'PUBLISHED';
          product.publishedAt = product.publishedAt || now;
        }
      } else if (
        requestedStatus === 'DRAFT' ||
        requestedStatus === 'PENDING_APPROVAL' ||
        requestedStatus === 'REJECTED' ||
        requestedStatus === 'CHANGES_REQUESTED' ||
        requestedStatus === 'ARCHIVED'
      ) {
        nextPublished = false;
      }

      Object.assign(product, flags, {
        status: nextStatus,
        isPublished: nextPublished,
        sellingPriceUsd: nextSelling,
        reviewedByEmail: req.authUser!.email,
        reviewedAt: now,
        updatedAt: now,
      });

      if (nextStatus === 'REJECTED') {
        product.adminRejectionReason = adminRejectionReason!.trim();
      } else if (nextStatus === 'CHANGES_REQUESTED') {
        product.adminChangeRequestMessage = adminChangeRequestMessage!.trim();
      } else if (nextStatus === 'APPROVED' || nextStatus === 'PUBLISHED') {
        delete product.adminRejectionReason;
        delete product.adminChangeRequestMessage;
      }

      await upsertProduct(product);
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'PRODUCT_MODERATED',
        targetType: 'product',
        targetId: product.id,
        details: `${product.title} -> ${prevStatus} => ${product.status} (published=${Boolean(product.isPublished)}), supplierPrice=$${product.wholesalePriceUsd}, retailPrice=$${prevSelling}->$ ${product.sellingPriceUsd}`,
      });

      if (requestedStatus || typeof requestedPublish === 'boolean') {
        const titleMap: Record<string, string> = {
          PUBLISHED: `Product Published Live: ${product.title}`,
          APPROVED: `Product Approved: ${product.title}`,
          REJECTED: `Product Rejected: ${product.title}`,
          CHANGES_REQUESTED: `Changes Requested: ${product.title}`,
          ARCHIVED: `Product Archived: ${product.title}`,
        };
        const msgMap: Record<string, string> = {
          PUBLISHED: `Your product "${product.title}" is now approved and live on TANZANITE EXPRESS storefront.`,
          APPROVED: `Your product "${product.title}" has been approved by Admin (awaiting live publish release).`,
          REJECTED: `Your product "${product.title}" was rejected: ${product.adminRejectionReason}`,
          CHANGES_REQUESTED: `Admin requested changes on "${product.title}": ${product.adminChangeRequestMessage}`,
          ARCHIVED: `Your product "${product.title}" has been archived.`,
        };
        await createNotification({
          recipientUid: product.supplierOwnerUid,
          type: 'product',
          title: titleMap[product.status] || `Product ${product.status}: ${product.title}`,
          message: msgMap[product.status] || `Your product status was updated to ${product.status}.`,
          targetType: 'product',
          targetId: product.id,
        });
      }

      res.json({ product });
    }
  );

  app.delete(
    '/api/admin/products/:productId',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const product = store.products[req.params.productId];
      if (!product) return res.status(404).json({ error: 'Product not found' });

      const hasSuborderHistory = Object.values(store.suborders).some((s) =>
        s.items.some((i) => i.productId === product.id)
      );
      if (hasSuborderHistory) {
        return res.status(409).json({
          error: 'Product is linked to existing orders and cannot be deleted; archive it instead.',
        });
      }

      const candidateUrls = [...(product.images || [])];
      await deleteProductRecord(product.id);
      await cleanupOrphanedImages(store, candidateUrls);
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'PRODUCT_DELETED',
        targetType: 'product',
        targetId: product.id,
        details: `Deleted product ${product.title} (${product.supplierName})`,
      });
      res.json({ deleted: true, productId: product.id });
    }
  );

  app.patch(
    '/api/admin/orders/:orderId/payment-confirm',
    requireAuth,
    requirePaymentVerifier,
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const order = store.orders[req.params.orderId];
      const payment = Object.values(store.payments).find(
        (p) => p.orderId === req.params.orderId
      );
      if (!order || !payment) {
        return res.status(404).json({ error: 'Order payment transaction not found' });
      }

      const schema = z.object({
        outcome: z.enum(['CONFIRMED', 'REJECTED']).default('CONFIRMED'),
        reason: z.string().max(400).optional(),
      });
      const parsed = schema.safeParse(req.body || {});
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid payment verification payload' });
      }

      if (parsed.data.outcome === 'REJECTED' && (!parsed.data.reason || parsed.data.reason.trim().length < 5)) {
        return res.status(400).json({
          error: 'A clear rejection reason (minimum 5 characters) is mandatory.',
        });
      }

      // Use latest PaymentSubmission if present, otherwise create an administrative review submission record
      let submission =
        (order.latestSubmissionId && store.paymentSubmissions[order.latestSubmissionId]) ||
        Object.values(store.paymentSubmissions).find((s) => s.orderId === order.id);

      if (!submission) {
        const proofResult = await submitManualPaymentProof({
          orderId: order.id,
          paymentMethod: order.paymentProvider === 'manual_nmb' ? 'manual_nmb' : 'manual_mobile',
          transactionId: order.submittedTransactionId || payment.reference,
          amountSent: order.totalDisplay,
          senderName: order.submittedPayerName || order.shippingAddress.fullName || order.customerEmail,
          senderPhone: order.submittedPayerPhone,
          actorUid: req.authUser!.uid,
          actorEmail: req.authUser!.email,
          actorRole: req.authUser!.role,
        });
        if ('error' in proofResult) {
          return res.status(proofResult.status).json({ error: proofResult.error });
        }
        submission = proofResult.submission;
      }

      const result = await reviewPaymentSubmission({
        submissionId: submission.id,
        action: parsed.data.outcome === 'REJECTED' ? 'REJECT' : 'APPROVE',
        reason: parsed.data.reason,
        actor: req.authUser!,
      });
      if ('error' in result) {
        return res.status(result.status).json({ error: result.error });
      }
      res.json({ ...result, outcome: parsed.data.outcome });
    }
  );

  // Admin sends supplier payout ref & releases suborder for dispatch (when manual release mode is active)
  app.patch(
    '/api/admin/suborders/:suborderId/settle-supplier',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const sub = store.suborders[req.params.suborderId];
      if (!sub) return res.status(404).json({ error: 'Suborder not found' });
      if (sub.paymentStatus !== 'CONFIRMED') {
        return res.status(400).json({
          error: 'Verify and approve the customer payment before releasing to the supplier.',
        });
      }

      const schema = z.object({
        settlementRef: z.string().trim().min(2, 'Enter transfer/mobile payout reference').max(120),
        note: z.string().max(300).optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Transfer reference is required to record settlement.' });
      }

      const now = new Date().toISOString();
      sub.supplierSettlementStatus = 'SENT_TO_SUPPLIER';
      sub.supplierSettlementRef = parsed.data.settlementRef;
      sub.supplierPaidAt = now;
      sub.fulfillmentReleased = true;
      if (sub.status === 'Payment Confirmed' || sub.status === 'Pending Payment' || sub.status === 'Awaiting Payment Verification') {
        sub.status = 'Awaiting Supplier Confirmation';
      }
      sub.updatedAt = now;
      sub.statusHistory.push({
        status: sub.status,
        timestamp: now,
        actor: `admin:${req.authUser!.email}`,
        note:
          parsed.data.note ||
          `Admin recorded supplier transfer ($${sub.supplierNetEarningsUsd} USD, Ref: ${parsed.data.settlementRef}) & enabled fulfillment.`,
      });
      await upsertSuborder(sub);

      const order = store.orders[sub.orderId];
      if (order) {
        const siblings = order.suborderIds.map((id) => store.suborders[id]).filter(Boolean);
        order.overallStatus = computeOverallOrderStatus(siblings);
        order.updatedAt = now;
        await upsertOrder(order);
      }

      await createNotification({
        recipientUid: sub.supplierOwnerUid,
        type: 'fulfillment',
        title: `Supplier Settlement Sent (${sub.id})`,
        message: `Admin transferred $${sub.supplierNetEarningsUsd} USD (Ref: ${parsed.data.settlementRef}). Please dispatch ${sub.items.length} item(s) to ${sub.customerShippingName} (${sub.customerShippingCity}, ${sub.customerShippingCountry}).`,
        targetType: 'suborder',
        targetId: sub.id,
      });
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'SUPPLIER_COST_SETTLED_AND_RELEASED',
        targetType: 'suborder',
        targetId: sub.id,
        details: `Paid ${sub.supplierName} $${sub.supplierNetEarningsUsd} (Admin kept $${sub.adminMarkupUsd ?? sub.marketplaceCommissionUsd}). Ref=${parsed.data.settlementRef}`,
      });

      res.json({ suborder: sub, order });
    }
  );

  // Explicit documented Admin exception override to release a suborder before payment verification
  app.patch(
    '/api/admin/suborders/:suborderId/release-exception',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const sub = store.suborders[req.params.suborderId];
      if (!sub) return res.status(404).json({ error: 'Suborder not found' });

      const schema = z.object({
        reason: z.string().trim().min(8, 'A documented reason (min 8 chars) is mandatory for exception release.').max(400),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Reason required.' });
      }

      const now = new Date().toISOString();
      const prevStatus = sub.status;
      sub.adminExceptionReleased = true;
      sub.adminExceptionReason = parsed.data.reason;
      sub.fulfillmentReleased = true;
      sub.status = 'Awaiting Supplier Confirmation';
      sub.updatedAt = now;
      sub.statusHistory.push({
        status: 'Awaiting Supplier Confirmation',
        timestamp: now,
        actor: `super_admin:${req.authUser!.email}`,
        note: `EXCEPTION RELEASE BEFORE PAYMENT VERIFICATION: ${parsed.data.reason}`,
      });
      await upsertSuborder(sub);

      const order = store.orders[sub.orderId];
      const payment = Object.values(store.payments).find((p) => p.orderId === sub.orderId);
      if (order) {
        const siblings = order.suborderIds.map((id) => store.suborders[id]).filter(Boolean);
        order.overallStatus = computeOverallOrderStatus(siblings);
        order.updatedAt = now;
        await upsertOrder(order);
      }

      await appendPaymentAuditLog({
        paymentId: payment?.id || 'unpaid',
        orderId: sub.orderId,
        action: 'SUBORDER_EXCEPTION_RELEASED',
        previousStatus: prevStatus,
        newStatus: sub.status,
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        reason: parsed.data.reason,
        metadata: { suborderId: sub.id },
      });
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'SUBORDER_EXCEPTION_RELEASED',
        targetType: 'suborder',
        targetId: sub.id,
        details: `Exception release by ${req.authUser!.email}: ${parsed.data.reason}`,
      });
      await createNotification({
        recipientUid: sub.supplierOwnerUid,
        type: 'fulfillment',
        title: `Admin Exception Release (${sub.id})`,
        message: `Admin released suborder ${sub.id} for fulfillment under documented exception: ${parsed.data.reason}`,
        targetType: 'suborder',
        targetId: sub.id,
      });

      res.json({ suborder: sub, order });
    }
  );

  app.patch(
    '/api/admin/suborders/:suborderId/intervene',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const sub = store.suborders[req.params.suborderId];
      if (!sub) return res.status(404).json({ error: 'Suborder not found' });

      const status = req.body?.status as OrderStatus;
      const note = String(req.body?.note || 'Admin intervention');
      const now = new Date().toISOString();
      if (status) sub.status = status;
      if (req.body?.carrierName) sub.carrierName = String(req.body.carrierName);
      if (req.body?.trackingNumber) sub.trackingNumber = String(req.body.trackingNumber);
      sub.updatedAt = now;
      sub.statusHistory.push({
        status: sub.status,
        timestamp: now,
        actor: `admin:${req.authUser!.email}`,
        note,
      });
      await upsertSuborder(sub);

      const order = store.orders[sub.orderId];
      if (order) {
        const siblings = order.suborderIds.map((id) => store.suborders[id]).filter(Boolean);
        order.overallStatus = computeOverallOrderStatus(siblings);
        order.updatedAt = now;
        await upsertOrder(order);
      }

      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'SUBORDER_INTERVENTION',
        targetType: 'suborder',
        targetId: sub.id,
        details: `Set status=${sub.status}; note=${note}`,
      });

      if (status === 'Cancelled') {
        await createNotification({
          recipientUid: sub.supplierOwnerUid,
          type: 'order',
          title: `Order Cancelled (${sub.id})`,
          message: `Suborder ${sub.id} for order ${sub.orderId} was cancelled by Admin (${note}).`,
          targetType: 'suborder',
          targetId: sub.id,
        });
      }
      await createNotification({
        recipientUid: sub.customerId,
        type: 'fulfillment',
        title: `Order Update: ${sub.status} (${sub.orderId})`,
        message: `Admin updated suborder ${sub.id} status to ${sub.status}: ${note}`,
        targetType: 'order',
        targetId: sub.orderId,
      });

      res.json({ suborder: sub });
    }
  );

  app.patch(
    '/api/admin/refunds/:refundId',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const refund = store.refunds[req.params.refundId];
      if (!refund) return res.status(404).json({ error: 'Refund request not found' });

      const schema = z.object({
        status: z.enum([
          'EVIDENCE_REQUESTED',
          'APPROVED',
          'REJECTED',
          'REFUNDED',
        ]),
        adminNotes: z.string().max(600).optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid refund decision' });

      const now = new Date().toISOString();
      refund.status = parsed.data.status;
      if (parsed.data.adminNotes) refund.adminNotes = parsed.data.adminNotes;
      refund.updatedAt = now;

      if (parsed.data.status === 'REFUNDED') {
        const sub = store.suborders[refund.suborderId];
        if (sub) {
          sub.status = 'Refunded';
          sub.updatedAt = now;
          sub.statusHistory.push({
            status: 'Refunded',
            timestamp: now,
            actor: `admin:${req.authUser!.email}`,
            note: 'Admin approved and recorded refund settlement.',
          });
          await upsertSuborder(sub);
        }
        const order = store.orders[refund.orderId];
        if (order) {
          order.paymentStatus = 'REFUNDED';
          order.overallStatus = 'Refunded';
          order.updatedAt = now;
          await upsertOrder(order);
        }
      }

      await saveStore(store);
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'REFUND_DECISION',
        targetType: 'refund',
        targetId: refund.id,
        details: `Status=${refund.status}; Notes=${refund.adminNotes || ''}`,
      });
      await createNotification({
        recipientUid: refund.customerId,
        type: 'return',
        title: `Refund Claim ${refund.status}`,
        message: `Your refund claim ${refund.id} has been updated to ${refund.status}.`,
        targetType: 'refund',
        targetId: refund.id,
      });
      const sup = store.suppliers[refund.supplierId];
      if (sup) {
        await createNotification({
          recipientUid: sup.ownerUid,
          type: 'return',
          title: `Refund Claim ${refund.status} (${refund.id})`,
          message: `Admin updated customer refund claim ${refund.id} to ${refund.status}.`,
          targetType: 'refund',
          targetId: refund.id,
        });
      }
      res.json({ refund });
    }
  );

  app.patch(
    '/api/admin/payouts/:payoutId',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const payout = store.payouts[req.params.payoutId];
      if (!payout) return res.status(404).json({ error: 'Payout request not found' });

      const schema = z.object({
        status: z.enum(['UNDER_REVIEW', 'APPROVED', 'PAID', 'REJECTED']),
        reference: z.string().max(120).optional(),
        notes: z.string().max(400).optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid payout decision' });

      payout.status = parsed.data.status;
      payout.reference = parsed.data.reference || payout.reference;
      payout.notes = parsed.data.notes || payout.notes;
      payout.reviewedBy = req.authUser!.email;
      payout.updatedAt = new Date().toISOString();
      await saveStore(store);

      const supplier = store.suppliers[payout.supplierId];
      if (supplier) {
        await createNotification({
          recipientUid: supplier.ownerUid,
          type: 'payment',
          title: `Payout ${payout.status}`,
          message: `Payout of $${payout.amountUsd} USD marked as ${payout.status}.`,
          targetType: 'supplier',
          targetId: supplier.id,
        });
      }

      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'SUPPLIER_PAYOUT_UPDATED',
        targetType: 'payout',
        targetId: payout.id,
        details: `${payout.supplierName} $${payout.amountUsd} -> ${payout.status}`,
      });
      res.json({ payout });
    }
  );

  app.post(
    '/api/admin/commission-rules',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const schema = z.object({
        scope: z.enum(['global', 'category', 'supplier', 'promotional']),
        targetId: z.string().max(128).optional(),
        label: z.string().min(2).max(120),
        percentage: z.number().min(0).max(60),
        fixedFeeUsd: z.number().nonnegative().default(0),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid commission rule' });

      const store = await getStore();
      const id = generateId('rule');
      const rule = {
        id,
        ...parsed.data,
        active: true,
        updatedAt: new Date().toISOString(),
      };
      store.commissionRules[id] = rule;
      if (rule.scope === 'global') {
        store.settings.globalCommissionPct = rule.percentage;
      }
      await saveStore(store);
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'COMMISSION_RULE_CREATED',
        targetType: 'commission_rule',
        targetId: id,
        details: `${rule.label} (${rule.scope}) = ${rule.percentage}%`,
      });
      res.json({ rule });
    }
  );

  app.delete(
    '/api/admin/commission-rules/:ruleId',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      delete store.commissionRules[req.params.ruleId];
      await saveStore(store);
      res.json({ ok: true });
    }
  );

  app.post(
    '/api/admin/coupons',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const schema = z.object({
        code: z.string().min(3).max(32),
        type: z.enum(['percentage', 'fixed']),
        value: z.number().positive(),
        minOrderUsd: z.number().nonnegative().default(0),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid coupon details' });

      const store = await getStore();
      const id = generateId('coup');
      const coupon = {
        id,
        code: parsed.data.code.trim().toUpperCase(),
        type: parsed.data.type,
        value: parsed.data.value,
        minOrderUsd: parsed.data.minOrderUsd,
        active: true,
        usageCount: 0,
      };
      store.coupons[id] = coupon;
      await saveStore(store);
      res.json({ coupon });
    }
  );

  app.patch(
    '/api/admin/coupons/:couponId',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const coupon = store.coupons[req.params.couponId];
      if (!coupon) return res.status(404).json({ error: 'Coupon not found' });
      coupon.active = Boolean(req.body?.active);
      await saveStore(store);
      res.json({ coupon });
    }
  );

  app.patch(
    '/api/admin/settings',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const updates = req.body || {};
      const merged = {
        ...store.settings,
        ...updates,
        currencyRates: {
          ...store.settings.currencyRates,
          ...(updates.currencyRates || {}),
        },
        socialLinks: {
          ...store.settings.socialLinks,
          ...(updates.socialLinks || {}),
        },
        updatedAt: new Date().toISOString(),
      };
      // Keep officialRecipientName, legacy manualPayment*, and structured mpesa*/nmb* settings synchronized cleanly
      if (updates.mpesaPhone !== undefined) merged.manualPaymentPhone = updates.mpesaPhone;
      else if (updates.manualPaymentPhone !== undefined) merged.mpesaPhone = updates.manualPaymentPhone;

      if (updates.officialRecipientName !== undefined) {
        const cleanOfficial = String(updates.officialRecipientName).trim();
        merged.officialRecipientName = cleanOfficial;
        merged.manualPaymentAccountName = cleanOfficial;
        if (updates.mpesaAccountHolder === undefined) {
          merged.mpesaAccountHolder = cleanOfficial;
        }
        if (updates.nmbAccountName === undefined) {
          merged.nmbAccountName = cleanOfficial;
        }
      }

      if (updates.mpesaAccountHolder !== undefined) {
        merged.manualPaymentAccountName = updates.mpesaAccountHolder;
      } else if (updates.manualPaymentAccountName !== undefined && updates.officialRecipientName === undefined) {
        merged.mpesaAccountHolder = updates.manualPaymentAccountName;
        merged.officialRecipientName = updates.manualPaymentAccountName;
      }

      if (updates.nmbAccountNumber !== undefined) {
        merged.manualPaymentBankAccount = updates.nmbAccountNumber;
      } else if (updates.manualPaymentBankAccount !== undefined) {
        merged.nmbAccountNumber = updates.manualPaymentBankAccount;
      }
      store.settings = merged;
      await upsertMarketplaceSettings(merged);
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'MARKETPLACE_SETTINGS_UPDATED',
        targetType: 'settings',
        targetId: 'default',
        details: 'Updated marketplace payment methods, banners, or operational settings.',
      });
      res.json({ settings: store.settings });
    }
  );

  app.post(
    '/api/admin/announcements',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const schema = z.object({
        audience: z.enum(['all', 'suppliers', 'customers']),
        title: z.string().min(3).max(120),
        message: z.string().min(5).max(800),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid announcement' });

      const store = await getStore();
      const recipients = Object.values(store.users).filter((u) => {
        if (parsed.data.audience === 'all') return true;
        if (parsed.data.audience === 'suppliers') return u.role === 'supplier';
        return u.role === 'customer';
      });
      for (const u of recipients) {
        await createNotification({
          recipientUid: u.uid,
          type: 'system',
          title: parsed.data.title,
          message: parsed.data.message,
        });
      }
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'ANNOUNCEMENT_BROADCAST',
        targetType: 'notification',
        targetId: parsed.data.audience,
        details: `Sent "${parsed.data.title}" to ${recipients.length} account(s).`,
      });
      res.json({ sentCount: recipients.length });
    }
  );

  app.patch(
    '/api/admin/users/:uid',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const target = store.users[req.params.uid];
      if (!target) return res.status(404).json({ error: 'User not found' });
      if (target.uid === req.authUser!.uid && req.body?.status === 'suspended') {
        return res.status(400).json({ error: 'Cannot suspend your own Super Admin account.' });
      }
      const schema = z.object({
        role: z.enum(['super_admin', 'staff', 'supplier', 'customer', 'delivery_partner']).optional(),
        status: z.enum(['active', 'suspended']).optional(),
        permissions: z
          .object({
            canVerifyPayments: z.boolean().optional(),
            canManageSettings: z.boolean().optional(),
            canModerateCatalog: z.boolean().optional(),
          })
          .optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid account update' });
      if (parsed.data.role) target.role = parsed.data.role;
      if (parsed.data.status) target.status = parsed.data.status;
      if (parsed.data.permissions) {
        target.permissions = {
          ...(target.permissions || {}),
          ...parsed.data.permissions,
        };
      }
      target.updatedAt = new Date().toISOString();
      await upsertUser(target);
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'USER_ACCOUNT_UPDATED',
        targetType: 'user',
        targetId: target.uid,
        details: `${target.email} -> role=${target.role}, status=${target.status}, canVerifyPayments=${Boolean(target.permissions?.canVerifyPayments)}`,
      });
      res.json({ user: target });
    }
  );

  app.patch(
    '/api/admin/tickets/:ticketId',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const ticket = store.tickets[req.params.ticketId];
      if (!ticket) return res.status(404).json({ error: 'Support ticket not found' });

      const schema = z.object({
        status: z.enum(['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED']).optional(),
        priority: z.enum(['low', 'medium', 'high', 'urgent']).optional(),
        replyMessage: z.string().max(1200).optional(),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'Invalid ticket update' });

      const prevStatus = ticket.status;
      const now = new Date().toISOString();
      if (parsed.data.status) ticket.status = parsed.data.status;
      if (parsed.data.priority) ticket.priority = parsed.data.priority;
      ticket.assignedStaffEmail = req.authUser!.email;
      if (parsed.data.replyMessage && parsed.data.replyMessage.trim()) {
        ticket.responses.push({
          author: req.authUser!.email,
          role: req.authUser!.role,
          message: parsed.data.replyMessage.trim(),
          timestamp: now,
        });
      }
      ticket.updatedAt = now;
      await upsertSupportTicket(ticket);

      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: parsed.data.replyMessage ? 'SUPPORT_TICKET_REPLIED' : 'SUPPORT_TICKET_UPDATED',
        targetType: 'ticket',
        targetId: ticket.id,
        targetUserId: ticket.userId,
        relatedOrderId: ticket.orderId,
        previousValue: prevStatus,
        newValue: ticket.status,
        details: `Updated support ticket "${ticket.subject}" (${prevStatus} -> ${ticket.status}).`,
      });

      await createNotification({
        recipientUid: ticket.userId,
        type: 'system',
        priority: 'high',
        title: `Support Ticket Update (${ticket.status})`,
        message: parsed.data.replyMessage?.trim()
          ? `Admin replied to "${ticket.subject}": ${parsed.data.replyMessage.trim()}`
          : `Ticket "${ticket.subject}" status changed to ${ticket.status}.`,
        targetType: 'ticket',
        targetId: ticket.id,
      });

      res.json({ ticket });
    }
  );

  // Admin Master Audit Search, Notification History Recovery, Data Retention, Backups & Erasure Endpoints
  app.get(
    '/api/admin/audit-logs',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req, res) => {
      const store = await getStore();
      const q = String(req.query.q || '').trim().toLowerCase();
      const action = String(req.query.action || 'ALL').trim();
      const actorRole = String(req.query.actorRole || 'ALL').trim();
      const outcome = String(req.query.outcome || 'ALL').trim();
      const dateFrom = String(req.query.dateFrom || '').trim();
      const dateTo = String(req.query.dateTo || '').trim();
      const page = Math.max(1, Number(req.query.page || 1) || 1);
      const limit = Math.min(200, Math.max(1, Number(req.query.limit || 40) || 40));

      let logs = Object.values(store.auditLogs).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt)
      );

      if (action && action !== 'ALL') {
        logs = logs.filter((l) => l.action === action);
      }
      if (actorRole && actorRole !== 'ALL') {
        logs = logs.filter((l) => l.actorRole === actorRole);
      }
      if (outcome && outcome !== 'ALL') {
        logs = logs.filter((l) => (l.outcome || 'SUCCESS') === outcome);
      }
      if (dateFrom) {
        logs = logs.filter((l) => l.createdAt.slice(0, 10) >= dateFrom);
      }
      if (dateTo) {
        logs = logs.filter((l) => l.createdAt.slice(0, 10) <= dateTo);
      }
      if (q) {
        logs = logs.filter(
          (l) =>
            l.id.toLowerCase().includes(q) ||
            l.action.toLowerCase().includes(q) ||
            l.actorEmail.toLowerCase().includes(q) ||
            l.actorUid.toLowerCase().includes(q) ||
            l.targetId.toLowerCase().includes(q) ||
            (l.targetUserId || '').toLowerCase().includes(q) ||
            (l.relatedOrderId || '').toLowerCase().includes(q) ||
            (l.technicalRef || '').toLowerCase().includes(q) ||
            l.details.toLowerCase().includes(q)
        );
      }

      const actions = Array.from(new Set(Object.values(store.auditLogs).map((l) => l.action))).sort();
      const total = logs.length;
      const totalPages = Math.max(1, Math.ceil(total / limit));
      const paged = logs.slice((page - 1) * limit, page * limit);

      res.json({
        logs: paged,
        actions,
        pagination: { page, pageSize: limit, total, totalPages, hasMore: page < totalPages },
      });
    }
  );

  app.get(
    '/api/admin/audit-logs/export',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req, res) => {
      const store = await getStore();
      const format = String(req.query.format || 'csv').toLowerCase();
      const q = String(req.query.q || '').trim().toLowerCase();
      let logs = Object.values(store.auditLogs).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt)
      );
      if (q) {
        logs = logs.filter(
          (l) =>
            l.action.toLowerCase().includes(q) ||
            l.actorEmail.toLowerCase().includes(q) ||
            l.targetId.toLowerCase().includes(q) ||
            (l.relatedOrderId || '').toLowerCase().includes(q) ||
            l.details.toLowerCase().includes(q)
        );
      }
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="tanzanite-audit-logs.json"');
        return res.send(JSON.stringify(logs, null, 2));
      }
      const csv = toCsv(
        logs.map((l) => ({
          id: l.id,
          createdAt: l.createdAt,
          action: l.action,
          outcome: l.outcome || 'SUCCESS',
          actorEmail: l.actorEmail,
          actorRole: l.actorRole,
          targetType: l.targetType,
          targetId: l.targetId,
          targetUserId: l.targetUserId || '',
          relatedOrderId: l.relatedOrderId || '',
          previousValue: l.previousValue || '',
          newValue: l.newValue || '',
          technicalRef: l.technicalRef || '',
          details: l.details,
        }))
      );
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="tanzanite-audit-logs.csv"');
      res.send(csv);
    }
  );

  app.get(
    '/api/admin/notifications/audit',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req, res) => {
      const store = await getStore();
      const q = String(req.query.q || '').trim().toLowerCase();
      const hiddenOnly = String(req.query.hiddenOnly || '') === 'true';
      const page = Math.max(1, Number(req.query.page || 1) || 1);
      const limit = Math.min(200, Math.max(1, Number(req.query.limit || 40) || 40));

      let list = Object.values(store.notifications).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt)
      );
      if (hiddenOnly) {
        list = list.filter((n) => Boolean(n.hiddenByRecipient));
      }
      if (q) {
        list = list.filter((n) => {
          const recipientEmail = store.users[n.recipientUid]?.email || '';
          return (
            n.id.toLowerCase().includes(q) ||
            n.recipientUid.toLowerCase().includes(q) ||
            recipientEmail.toLowerCase().includes(q) ||
            n.title.toLowerCase().includes(q) ||
            n.message.toLowerCase().includes(q) ||
            (n.targetId || '').toLowerCase().includes(q)
          );
        });
      }
      const total = list.length;
      const totalPages = Math.max(1, Math.ceil(total / limit));
      const paged = list.slice((page - 1) * limit, page * limit).map((n) => ({
        ...n,
        recipientEmail: store.users[n.recipientUid]?.email || n.recipientUid,
      }));
      res.json({
        notifications: paged,
        pagination: { page, pageSize: limit, total, totalPages, hasMore: page < totalPages },
      });
    }
  );

  app.get(
    '/api/admin/retention-policy',
    requireAuth,
    requireRoles('super_admin'),
    async (_req, res) => {
      const store = await getStore();
      res.json({ policy: getEffectiveRetentionPolicy(store) });
    }
  );

  app.patch(
    '/api/admin/retention-policy',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const schema = z.object({
        auditLogsDays: z.number().int().min(365).max(3650),
        ordersAndPaymentsDays: z.number().int().min(365).max(3650),
        notificationsDays: z.number().int().min(30).max(3650),
        activityEventsDays: z.number().int().min(30).max(1825),
        supportTicketsDays: z.number().int().min(90).max(3650),
        backupsKeepCount: z.number().int().min(3).max(60),
      });
      const parsed = schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid retention policy values.' });
      }
      const updated = await upsertRetentionPolicy({
        ...parsed.data,
        updatedAt: new Date().toISOString(),
        updatedByEmail: req.authUser!.email,
      });
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'RETENTION_POLICY_UPDATED',
        targetType: 'retention_policy',
        targetId: 'default',
        newValue: JSON.stringify(parsed.data),
        details: `Updated marketplace data retention rules (auditLogs=${parsed.data.auditLogsDays}d, orders=${parsed.data.ordersAndPaymentsDays}d).`,
      });
      res.json({ policy: updated });
    }
  );

  app.get(
    '/api/admin/backups',
    requireAuth,
    requireRoles('super_admin'),
    async (_req, res) => {
      const store = await getStore();
      res.json({ backups: listAvailableBackups(store) });
    }
  );

  app.post(
    '/api/admin/backups/create',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      const reason = String(req.body?.reason || '').trim().slice(0, 200) || 'Admin console snapshot';
      const { meta } = await createStoreBackup({ actor: req.authUser!, reason });
      const store = await getStore();
      res.json({ backup: meta, backups: listAvailableBackups(store) });
    }
  );

  app.get(
    '/api/admin/backups/:backupId/download',
    requireAuth,
    requireRoles('super_admin'),
    async (req, res) => {
      try {
        const archive = readBackupArchive(req.params.backupId);
        if (!archive) return res.status(404).json({ error: 'Backup snapshot not found.' });
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="tanzanite-${archive.meta.fileName}"`
        );
        res.send(archive.rawContent);
      } catch (err: any) {
        res.status(400).json({ error: err?.message || 'Backup archive verification failed.' });
      }
    }
  );

  app.post(
    '/api/admin/backups/:backupId/restore',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      try {
        const result = await restoreStoreFromBackup({
          backupId: req.params.backupId,
          actor: req.authUser!,
        });
        res.json({
          restored: true,
          ...result,
        });
      } catch (err: any) {
        res.status(400).json({ error: err?.message || 'Backup restore failed.' });
      }
    }
  );

  app.post(
    '/api/admin/users/:uid/anonymize',
    requireAuth,
    requireRoles('super_admin'),
    async (req: AuthRequest, res) => {
      try {
        const reason = String(req.body?.reason || '').trim().slice(0, 240);
        const result = await anonymizeUserForErasure({
          targetUid: req.params.uid,
          actor: req.authUser!,
          reason,
        });
        res.json({ anonymized: true, ...result });
      } catch (err: any) {
        res.status(400).json({ error: err?.message || 'Unable to anonymize user account.' });
      }
    }
  );

  // Admin AI Business Intelligence & Analytics Endpoints
  app.get(
    '/api/admin/analytics',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req, res) => {
      const store = await getStore();
      const range = typeof req.query.range === 'string' ? req.query.range : '30d';
      const from = typeof req.query.from === 'string' ? req.query.from : undefined;
      const to = typeof req.query.to === 'string' ? req.query.to : undefined;
      const metrics = computeAdminAnalytics(store, range, from, to);
      const reports = Object.values(store.aiReports)
        .filter((r) => r.scope === 'admin')
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .slice(0, 15);
      res.json({
        metrics,
        reports,
        geminiConfigured: isGeminiConfigured(),
      });
    }
  );

  app.post(
    '/api/admin/ai-report',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req: AuthRequest, res) => {
      const store = await getStore();
      const range = typeof req.body?.range === 'string' ? req.body.range : '30d';
      const from = typeof req.body?.from === 'string' ? req.body.from : undefined;
      const to = typeof req.body?.to === 'string' ? req.body.to : undefined;
      const metrics = computeAdminAnalytics(store, range, from, to);
      const aiContent = await generateAdminAiReport(metrics);

      const report: AiReportRecord = {
        id: generateId('rep'),
        scope: 'admin',
        requestedByUid: req.authUser!.uid,
        rangeLabel: metrics.rangeLabel,
        aiGenerated: aiContent.aiGenerated,
        model: aiContent.model,
        statusMessage: aiContent.statusMessage,
        executiveSummary: aiContent.executiveSummary,
        highlights: aiContent.highlights,
        actionableRecommendations: aiContent.actionableRecommendations,
        risksAndAlerts: aiContent.risksAndAlerts,
        metricsSnapshot: {
          grossRevenueUsd: metrics.grossRevenueUsd,
          marketplaceCommissionsUsd: metrics.marketplaceCommissionsUsd,
          totalOrdersCount: metrics.totalOrdersCount,
          pendingPaymentsCount: metrics.pendingPaymentsCount,
          repeatPurchaseRatePct: metrics.repeatPurchaseRatePct,
          overallConversionRatePct: metrics.overallConversionRatePct,
        },
        createdAt: new Date().toISOString(),
      };
      await upsertAiReport(report);
      await appendAuditLog({
        actorUid: req.authUser!.uid,
        actorEmail: req.authUser!.email,
        actorRole: req.authUser!.role,
        action: 'ADMIN_BI_REPORT_GENERATED',
        targetType: 'ai_report',
        targetId: report.id,
        details: `Generated BI report (${metrics.rangeLabel}, aiGenerated=${report.aiGenerated})`,
      });
      res.json({ report, metrics });
    }
  );

  app.get(
    '/api/admin/analytics/export',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req, res) => {
      const store = await getStore();
      const range = typeof req.query.range === 'string' ? req.query.range : '30d';
      const from = typeof req.query.from === 'string' ? req.query.from : undefined;
      const to = typeof req.query.to === 'string' ? req.query.to : undefined;
      const metrics = computeAdminAnalytics(store, range, from, to);
      const rows = [
        {
          section: 'SUMMARY',
          label: metrics.rangeLabel,
          totalOrders: metrics.totalOrdersCount,
          confirmedSales: metrics.totalSalesCount,
          grossRevenueUsd: metrics.grossRevenueUsd,
          commissionsUsd: metrics.marketplaceCommissionsUsd,
          pendingPayments: metrics.pendingPaymentsCount,
          verifiedPayments: metrics.verifiedPaymentsCount,
          rejectedPayments: metrics.rejectedPaymentsCount,
          repeatPurchaseRatePct: metrics.repeatPurchaseRatePct,
          cartAbandonmentRatePct: metrics.cartAbandonmentRatePct,
          productViews: metrics.productViewsCount,
          conversionRatePct: metrics.overallConversionRatePct,
        },
        ...metrics.bestSellingProducts.map((p) => ({
          section: 'TOP_PRODUCT',
          label: p.title,
          totalOrders: p.unitsSold,
          confirmedSales: p.unitsSold,
          grossRevenueUsd: p.revenueUsd,
          commissionsUsd: 0,
          pendingPayments: 0,
          verifiedPayments: 0,
          rejectedPayments: 0,
          repeatPurchaseRatePct: 0,
          cartAbandonmentRatePct: 0,
          productViews: p.views,
          conversionRatePct: p.conversionRatePct,
        })),
        ...metrics.bestSuppliers.map((s) => ({
          section: 'TOP_SUPPLIER',
          label: s.supplierName,
          totalOrders: s.ordersCount,
          confirmedSales: s.ordersCount,
          grossRevenueUsd: s.revenueUsd,
          commissionsUsd: 0,
          pendingPayments: 0,
          verifiedPayments: 0,
          rejectedPayments: 0,
          repeatPurchaseRatePct: s.onTimeRatePct,
          cartAbandonmentRatePct: 0,
          productViews: 0,
          conversionRatePct: 0,
        })),
      ];
      const csv = toCsv(rows);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="tanzanite-express-bi-${range}.csv"`
      );
      res.send(csv);
    }
  );

  app.get(
    '/api/admin/export/:type',
    requireAuth,
    requireRoles('super_admin', 'staff'),
    async (req, res) => {
      const store = await getStore();
      const type = req.params.type;
      let rows: Record<string, unknown>[] = [];

      if (type === 'payments') {
        rows = Object.values(store.paymentSubmissions)
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
          .map((s) => ({
            submissionId: s.id,
            orderId: s.orderId,
            customerEmail: s.customerEmail,
            paymentMethod: s.paymentMethod === 'manual_mobile' ? 'M-Pesa (Tanzania)' : 'NMB Bank Transfer',
            transactionId: s.transactionId,
            amountExpectedDisplay: s.amountExpectedDisplay,
            amountSentDisplay: s.amountSentDisplay,
            currency: s.currency,
            senderName: s.senderName,
            senderPhone: s.senderPhone || '',
            transactionDate: s.transactionDate,
            status: s.status,
            isDuplicateSuspected: s.isDuplicateSuspected,
            amountMismatchFlag: s.amountMismatchFlag,
            rejectionReason: s.rejectionReason || '',
            reviewedByEmail: s.reviewedByEmail || '',
            reviewedAt: s.reviewedAt || '',
            createdAt: s.createdAt,
          }));
      } else if (type === 'orders') {
        rows = Object.values(store.orders).map((o) => ({
          orderId: o.id,
          customerEmail: o.customerEmail,
          currency: o.currency,
          totalUsd: o.totalUsd,
          totalDisplay: o.totalDisplay,
          paymentProvider: o.paymentProvider,
          paymentStatus: o.paymentStatus,
          overallStatus: o.overallStatus,
          country: o.shippingAddress.country,
          createdAt: o.createdAt,
        }));
      } else if (type === 'suborders') {
        rows = Object.values(store.suborders).map((s) => ({
          suborderId: s.id,
          orderId: s.orderId,
          supplierName: s.supplierName,
          subtotalUsd: s.supplierSubtotalUsd,
          shippingFeeUsd: s.shippingFeeUsd,
          commissionPct: s.marketplaceCommissionRatePct,
          commissionUsd: s.marketplaceCommissionUsd,
          supplierNetUsd: s.supplierNetEarningsUsd,
          status: s.status,
          trackingNumber: s.trackingNumber || '',
          createdAt: s.createdAt,
        }));
      } else if (type === 'suppliers') {
        rows = Object.values(store.suppliers).map((s) => ({
          supplierId: s.id,
          businessName: s.businessName,
          country: s.country,
          status: s.status,
          documentsVerified: s.documentsVerified,
          commissionOverridePct: s.commissionRatePct ?? 'Global',
          plan: s.subscriptionPlan,
          createdAt: s.createdAt,
        }));
      } else {
        rows = Object.values(store.products).map((p) => ({
          productId: p.id,
          title: p.title,
          supplierName: p.supplierName,
          gender: p.gender,
          category: p.category,
          sellingPriceUsd: p.sellingPriceUsd,
          totalStock: p.totalStock,
          status: p.status,
        }));
      }

      const csv = toCsv(rows);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="tanzanite-express-${type}.csv"`);
      res.send(csv);
    }
  );

  const httpServer = http.createServer(app);

  // ------------------------------------------------------------------
  // VITE MIDDLEWARE (DEV) OR STATIC ASSETS (PROD)
  // ------------------------------------------------------------------
  if (process.env.NODE_ENV !== 'production') {
    const hmrDisabled = process.env.DISABLE_HMR === 'true';
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        ws: { server: httpServer },
        hmr: hmrDisabled ? false : { server: httpServer },
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`TANZANITE EXPRESS running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
