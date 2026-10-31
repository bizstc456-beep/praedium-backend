// ============================================
// FILE: server.js - PRAEDIUM BACKEND
// ============================================

const dotenv = require('dotenv');

// Load .env only in development, not in production (Railway)
if (process.env.NODE_ENV !== 'production') {
  dotenv.config();
}

// Sentry must be required and initialized before express (and the other
// libraries below) are required, so its auto-instrumentation can patch
// them. Safe to leave running everywhere -- with no SENTRY_DSN set (e.g. a
// local dev machine that doesn't have one), it quietly no-ops instead of
// throwing. Its default integrations already cover uncaught exceptions and
// unhandled promise rejections (an async route handler that throws without
// a try/catch, which would otherwise just crash the process with nothing
// to show for it), on top of the explicit capture below.
const Sentry = require('@sentry/node');
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV || 'development',
  tracesSampleRate: 0.1,
});

// Every catch block in this file already does `console.error(message, err)`
// -- forward those to Sentry too, so a bug shows up as an event instead of
// only existing in Railway's logs until a customer complains.
const originalConsoleError = console.error.bind(console);
console.error = (...args) => {
  originalConsoleError(...args);
  const error = args.find((a) => a instanceof Error);
  if (error) {
    Sentry.captureException(error);
  } else {
    Sentry.captureMessage(args.map(String).join(' '), 'error');
  }
};

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const twilio = require('twilio');
const Anthropic = require('@anthropic-ai/sdk');
const multer = require('multer');
const cron = require('node-cron');

// ============================================
// INITIALIZE ALL SERVICES
// ============================================

const app = express();

// Railway sits in front of this app behind a reverse proxy, so req.ip would
// otherwise resolve to the proxy's address for every request. Trusting the
// first proxy hop lets express-rate-limit key on the real client IP.
app.set('trust proxy', 1);

// Middleware
// crossOriginResourcePolicy defaults to "same-origin" in helmet, which would
// block the frontend (a different origin - Vercel vs Railway) from reading
// API responses via fetch. Loosen just that piece; keep helmet's other
// defaults (CSP, etc. - mostly inert for a pure JSON API anyway).
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// Allowed origins for browser requests. FRONTEND_URL can be a single origin
// or a comma-separated list (e.g. if the site is reachable at both the www
// and apex domain). Both the www and apex praedium.pro variants are allowed
// by default so a DNS/Vercel domain change doesn't silently break CORS, and
// a trailing slash on any configured origin is tolerated. localhost is
// always allowed for local dev.
const allowedOrigins = (process.env.FRONTEND_URL || 'https://www.praedium.pro,https://praedium.pro')
  .split(',')
  .map((o) => o.trim().replace(/\/$/, ''))
  .concat(['http://localhost:3000']);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (curl, mobile apps, server-to-server, Stripe webhooks)
    if (!origin) {
      return callback(null, true);
    }
    const normalizedOrigin = origin.replace(/\/$/, '');
    if (allowedOrigins.includes(normalizedOrigin)) {
      return callback(null, true);
    }
    // Log the actual rejected origin so a mismatch (wrong domain, http vs
    // https, a Vercel preview URL) is visible in Railway logs instead of
    // just "Not allowed by CORS" with no context.
    console.error(`CORS rejected origin: "${origin}" (allowed: ${allowedOrigins.join(', ')})`);
    return callback(new Error('Not allowed by CORS'));
  },
}));

// Rate limiting: general API traffic gets a generous cap, auth endpoints
// (prone to abuse - credential stuffing, spam signups) get a tighter one.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' },
});
app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);

// The Stripe webhook route needs the raw request body (not JSON-parsed) to
// verify the signature, so it must be excluded from the global JSON parser.
app.use((req, res, next) => {
  if (req.originalUrl === '/api/webhooks/stripe') {
    return next();
  }
  return express.json()(req, res, next);
});

// Supabase (Database)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Stripe (Payments)
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Subscription tiers and the unit-cap math live in lib/planLogic.js so they
// can be unit-tested without a database, Stripe, or Twilio -- see
// __tests__/planLogic.test.js. Never redefine these here; edit that file.
const {
  PLAN_TIERS,
  DEFAULT_PLAN_TIER,
  UNITS_BY_PROPERTY_TYPE,
  inferUnitCount,
  isValidTierKey,
  resolveTierKey,
} = require('./lib/planLogic');

// Monthly price per tier, fetched live from Stripe rather than hardcoded --
// the actual dollar amounts only ever live in Stripe (as Price objects
// referenced by the STRIPE_PRICE_* env vars), so asking Stripe directly
// means this never drifts out of sync with a price changed in the
// dashboard. Cached in memory for a few minutes since prices essentially
// never change between requests and this is called on every admin
// dashboard load.
let tierPriceCache = { fetchedAt: 0, prices: null };
async function getTierMonthlyPrices() {
  const CACHE_TTL_MS = 10 * 60 * 1000;
  if (tierPriceCache.prices && (Date.now() - tierPriceCache.fetchedAt) < CACHE_TTL_MS) {
    return tierPriceCache.prices;
  }
  const prices = {};
  for (const [tierKey, tier] of Object.entries(PLAN_TIERS)) {
    const priceId = process.env[tier.priceEnvVar];
    if (!priceId) {
      prices[tierKey] = 0;
      continue;
    }
    try {
      const price = await stripe.prices.retrieve(priceId);
      prices[tierKey] = (price.unit_amount || 0) / 100;
    } catch (err) {
      console.error(`Failed to fetch Stripe price for tier "${tierKey}":`, err.message);
      prices[tierKey] = 0;
    }
  }
  tierPriceCache = { fetchedAt: Date.now(), prices };
  return prices;
}

// Sums inferred unit counts across every property a landlord owns -- the
// basis for enforcing their plan's unit cap. Safe to call from any route
// even though inferUnitCount is defined later in this file: routes only
// run after the whole module (and therefore inferUnitCount) has loaded.
async function getUnitUsageForUser(userId) {
  const { data: props, error } = await supabase
    .from('properties')
    .select('property_type')
    .eq('user_id', userId);
  if (error) throw error;
  return (props || []).reduce((sum, p) => sum + inferUnitCount(p.property_type), 0);
}

// Looks up a landlord's plan tier, falling back to Starter if the customers
// row has no plan_tier yet (e.g. it predates this column) or holds an
// unrecognized value.
async function getPlanTierForUser(userId) {
  const { data: customer } = await supabase
    .from('customers')
    .select('plan_tier')
    .eq('user_id', userId)
    .single();
  const tierKey = customer && customer.plan_tier;
  return PLAN_TIERS[tierKey] ? tierKey : DEFAULT_PLAN_TIER;
}

// Twilio (SMS)
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// Claude (AI)
const anthropic = new Anthropic({
  apiKey: process.env.CLAUDE_API_KEY
});

// File uploads (documents) -- held in memory, then streamed to Supabase
// Storage. 15MB cap covers scanned leases/IDs comfortably. fileFilter keeps
// this to the document/photo types the app actually handles -- an upload
// endpoint with no type check will happily store an .html or .svg file,
// which is a real (if modest) risk once it's handed back out via a signed
// URL and opened in a browser tab.
const DOCUMENT_MIME_TYPES = new Set([
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/heic',
  'image/heif',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (DOCUMENT_MIME_TYPES.has(file.mimetype)) return cb(null, true);
    const err = new Error('Unsupported file type. Upload a PDF, Word document, or image.');
    err.isFileFilterError = true;
    cb(err);
  },
});

// Narrower variant for the tenant maintenance-request photo -- images only.
const uploadImage = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) return cb(null, true);
    const err = new Error('Unsupported file type. Upload an image.');
    err.isFileFilterError = true;
    cb(err);
  },
});

// ============================================
// AUTH HELPERS
// ============================================

// Landlords who are allowed to see the Admin Dashboard.
// Configure via ADMIN_EMAILS="a@x.com,b@y.com" in Railway; falls back to the founder account.
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'bizstc456@gmail.com')
  .split(',')
  .map(e => e.trim().toLowerCase())
  .filter(Boolean);

// Verifies the Supabase access token sent as "Authorization: Bearer <token>"
// and returns the authenticated user, or null if missing/invalid.
async function getAuthenticatedUser(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return null;

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
}

// Express middleware: requires a valid session, attaches req.user.
async function requireAuth(req, res, next) {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Missing or invalid session' });
  }
  req.user = user;
  next();
}

// Express middleware: requires a valid session AND an admin email.
async function requireAdmin(req, res, next) {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Missing or invalid session' });
  }
  if (!ADMIN_EMAILS.includes((user.email || '').toLowerCase())) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  req.user = user;
  next();
}

// Express middleware: requires a valid session that is linked to a tenant
// record (tenants.auth_user_id), for the tenant self-service portal.
// Attaches the tenant row as req.tenant.
async function requireTenantAuth(req, res, next) {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Missing or invalid session' });
  }

  const { data: tenant, error } = await supabase
    .from('tenants')
    .select('*')
    .eq('auth_user_id', user.id)
    .single();

  if (error || !tenant) {
    return res.status(403).json({ error: 'No tenant portal account is linked to this login' });
  }

  req.user = user;
  req.tenant = tenant;
  next();
}

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// Register new landlord
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, phone } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password
    });

    if (authError) {
      return res.status(400).json({ error: authError.message });
    }

    const { data: customer, error: dbError } = await supabase
      .from('customers')
      .insert([
        {
          user_id: authData.user.id,
          email,
          name,
          phone,
          trial_ends_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          status: 'active',
          plan_tier: DEFAULT_PLAN_TIER
        }
      ])
      .select();

    if (dbError) {
      return res.status(400).json({ error: dbError.message });
    }

    // Onboarding automation: welcome the new landlord by text as soon as
    // their account exists, mirroring the tenant welcome-SMS flow. Phone is
    // optional at registration, and this is best-effort -- a failed text
    // never fails account creation, which has already succeeded by this
    // point.
    if (phone) {
      try {
        const welcomeMessage = await generateLandlordWelcomeMessage(name);
        await sendSMS(phone, welcomeMessage, authData.user.id);
      } catch (smsError) {
        console.error('Landlord welcome SMS failed:', smsError);
      }
    }

    res.json({
      success: true,
      customer: customer[0],
      user: authData.user
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({
      success: true,
      user: data.user,
      session: data.session
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// PROPERTY MANAGEMENT ROUTES
// ============================================

// Create property
app.post('/api/properties', requireAuth, async (req, res) => {
  try {
    const { address, city, province, postal_code, property_type, bedrooms, bathrooms, notes } = req.body;

    if (!address || !city) {
      return res.status(400).json({ error: 'Address and city are required' });
    }

    const newUnits = inferUnitCount(property_type);
    const tierKey = await getPlanTierForUser(req.user.id);
    const tier = PLAN_TIERS[tierKey];
    const currentUnits = await getUnitUsageForUser(req.user.id);
    if (currentUnits + newUnits > tier.maxUnits) {
      return res.status(403).json({
        error: `Adding this property would put you at ${currentUnits + newUnits} units, over your ${tier.label} plan's ${tier.maxUnits}-unit limit. Upgrade your plan to add more.`,
        code: 'plan_limit_reached',
        plan_tier: tierKey,
        max_units: tier.maxUnits,
        current_units: currentUnits
      });
    }

    const { data, error } = await supabase
      .from('properties')
      .insert([
        {
          user_id: req.user.id,
          address,
          city,
          province,
          postal_code,
          property_type,
          bedrooms,
          bathrooms,
          notes,
          created_at: new Date()
        }
      ])
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, property: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all properties for a landlord
app.get('/api/properties/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's properties" });
    }

    const { data, error } = await supabase
      .from('properties')
      .select('*')
      .eq('user_id', user_id)
      .order('created_at', { ascending: true });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, properties: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update a property you own. user_id is never accepted from the client --
// ownership can't be transferred through this route.
app.put('/api/properties/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const { address, city, province, postal_code, property_type, bedrooms, bathrooms, notes } = req.body;

    if (property_type) {
      const { data: currentProp } = await supabase
        .from('properties')
        .select('property_type')
        .eq('id', property_id)
        .single();
      const oldUnits = inferUnitCount(currentProp && currentProp.property_type);
      const newUnits = inferUnitCount(property_type);
      if (newUnits > oldUnits) {
        const tierKey = await getPlanTierForUser(existing.user_id);
        const tier = PLAN_TIERS[tierKey];
        const currentTotalUnits = await getUnitUsageForUser(existing.user_id);
        const projectedUnits = currentTotalUnits - oldUnits + newUnits;
        if (projectedUnits > tier.maxUnits) {
          return res.status(403).json({
            error: `Changing this property's type would put you at ${projectedUnits} units, over your ${tier.label} plan's ${tier.maxUnits}-unit limit. Upgrade your plan to add more.`,
            code: 'plan_limit_reached',
            plan_tier: tierKey,
            max_units: tier.maxUnits,
            current_units: currentTotalUnits
          });
        }
      }
    }

    const updates = { address, city, province, postal_code, property_type, bedrooms, bathrooms, notes };

    const { data, error } = await supabase
      .from('properties')
      .update(updates)
      .eq('id', property_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, property: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a property (and everything under it) you manage. Removes its
// tenants' payments and documents, the tenants themselves, the property's
// own documents, then the property. There's no undo -- the frontend confirms first.
app.delete('/api/properties/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const { data: tenants } = await supabase
      .from('tenants')
      .select('id')
      .eq('property_id', property_id);
    const tenantIds = (tenants || []).map(t => t.id);

    const docFilter = tenantIds.length
      ? `property_id.eq.${property_id},tenant_id.in.(${tenantIds.join(',')})`
      : `property_id.eq.${property_id}`;
    const { data: docs } = await supabase
      .from('documents')
      .select('storage_path')
      .or(docFilter);
    if (docs && docs.length) {
      await supabase.storage.from(DOCUMENTS_BUCKET).remove(docs.map(d => d.storage_path));
      await supabase.from('documents').delete().or(docFilter);
    }

    if (tenantIds.length) {
      await supabase.from('payments').delete().in('tenant_id', tenantIds);
    }

    await supabase.from('tenants').delete().eq('property_id', property_id);

    const { error } = await supabase.from('properties').delete().eq('id', property_id);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// TENANT MANAGEMENT ROUTES
// ============================================

// Postgres rejects '' for a date column -- the lease-date fields come from
// optional <input type="date"> elements, which send '' when left blank.
// Normalize those (and undefined/null) to a real null before they hit the DB.
function toNullableDate(value) {
  return value ? value : null;
}

// Add a tenant (a unit + its lease) to a property you own
app.post('/api/tenants', requireAuth, async (req, res) => {
  try {
    const { property_id, name, email, phone, unit_label, rent_amount, lease_start_date, lease_end_date } = req.body;

    if (!property_id || !name || !phone) {
      return res.status(400).json({ error: 'property_id, name, and phone are required' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id, address')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const { data, error } = await supabase
      .from('tenants')
      .insert([
        {
          property_id,
          name,
          email,
          phone,
          unit_label,
          rent_amount,
          lease_start_date: toNullableDate(lease_start_date),
          lease_end_date: toNullableDate(lease_end_date),
          created_at: new Date()
        }
      ])
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    const newTenant = data[0];

    // Lease-signed automation: fire a welcome SMS as soon as a tenant/lease
    // is created. Best-effort -- a failed text never fails tenant creation.
    try {
      const welcomeMessage = await generateWelcomeMessage(newTenant.name, property.address, newTenant.unit_label);
      await sendSMS(newTenant.phone, welcomeMessage, property.user_id);
    } catch (smsError) {
      console.error('Welcome SMS failed:', smsError);
    }

    // Same automation chain: if an email was given, send the portal invite
    // right away too instead of making the landlord click "Invite to
    // Portal" as a separate step. Best-effort, same as the SMS above -- no
    // email on file just means this is skipped (the manual button still
    // works later once one's added).
    if (newTenant.email) {
      try {
        await inviteTenantToPortal(newTenant);
      } catch (inviteError) {
        console.error('Automatic portal invite failed:', inviteError);
      }
    }

    res.json({ success: true, tenant: newTenant });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update a tenant/lease you manage
app.put('/api/tenants/:tenant_id', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { name, email, phone, unit_label, rent_amount, lease_start_date, lease_end_date } = req.body;
    const updates = {
      name,
      email,
      phone,
      unit_label,
      rent_amount,
      lease_start_date: toNullableDate(lease_start_date),
      lease_end_date: toNullableDate(lease_end_date),
    };

    const { data, error } = await supabase
      .from('tenants')
      .update(updates)
      .eq('id', tenant_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, tenant: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a tenant (lease ended / unit vacated) you manage. Cascades to that
// tenant's payments and documents so nothing orphaned is left behind.
app.delete('/api/tenants/:tenant_id', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { data: docs } = await supabase
      .from('documents')
      .select('storage_path')
      .eq('tenant_id', tenant_id);
    if (docs && docs.length) {
      await supabase.storage.from(DOCUMENTS_BUCKET).remove(docs.map(d => d.storage_path));
      await supabase.from('documents').delete().eq('tenant_id', tenant_id);
    }

    await supabase.from('payments').delete().eq('tenant_id', tenant_id);

    const { error } = await supabase.from('tenants').delete().eq('id', tenant_id);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get tenants for a single property you own
app.get('/api/tenants/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's tenants" });
    }

    const { data, error } = await supabase
      .from('tenants')
      .select('*')
      .eq('property_id', property_id);

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, tenants: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// PAYMENT TRACKING ROUTES
// ============================================

// Mark a payment as paid for a tenant you manage
app.post('/api/payments/mark-paid', requireAuth, async (req, res) => {
  try {
    const { tenant_id, amount, payment_date, payment_method } = req.body;

    if (!tenant_id || !amount) {
      return res.status(400).json({ error: 'tenant_id and amount are required' });
    }

    const { data: tenantData, error: tenantError } = await supabase
      .from('tenants')
      .select('name, phone, property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenantData) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenantData.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { data: paymentData, error: paymentError } = await supabase
      .from('payments')
      .insert([
        {
          tenant_id,
          amount,
          payment_date: payment_date || new Date(),
          payment_method,
          status: 'paid',
          created_at: new Date()
        }
      ])
      .select();

    if (paymentError) {
      return res.status(400).json({ error: paymentError.message });
    }

    // A payment is already recorded at this point -- a failed confirmation
    // text is logged but shouldn't make the request look like it failed.
    let message = null;
    try {
      message = await generatePaymentConfirmationMessage(tenantData.name, amount);
      await sendSMS(tenantData.phone, message, property.user_id);
    } catch (smsError) {
      console.error('Payment confirmation SMS failed:', smsError);
    }

    const receipt = generateReceipt(
      tenantData.name,
      amount,
      payment_date,
      payment_method
    );

    res.json({
      success: true,
      payment: paymentData[0],
      message,
      receipt
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// Cancel the most recently recorded payment for a tenant you manage
app.delete('/api/payments/:tenant_id/latest', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenantData, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenantData) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenantData.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { data: latestPayment, error: latestError } = await supabase
      .from('payments')
      .select('id')
      .eq('tenant_id', tenant_id)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();
    if (latestError || !latestPayment) {
      return res.status(404).json({ error: 'No payment found to cancel' });
    }

    const { error: deleteError } = await supabase
      .from('payments')
      .delete()
      .eq('id', latestPayment.id);
    if (deleteError) {
      return res.status(400).json({ error: deleteError.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get payment history for a tenant you manage
app.get('/api/payments/:tenant_id', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenantData, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenantData) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenantData.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's payments" });
    }

    const { data, error } = await supabase
      .from('payments')
      .select('*')
      .eq('tenant_id', tenant_id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, payments: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all payments for a property you own
app.get('/api/payments/property/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's payments" });
    }

    const { data: tenants, error: tenantError } = await supabase
      .from('tenants')
      .select('id')
      .eq('property_id', property_id);

    if (tenantError) {
      return res.status(400).json({ error: tenantError.message });
    }

    const tenantIds = tenants.map(t => t.id);
    if (tenantIds.length === 0) {
      return res.json({ success: true, payments: [] });
    }

    const { data, error } = await supabase
      .from('payments')
      .select('*, tenants(name, phone)')
      .in('tenant_id', tenantIds)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, payments: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// EXPENSE TRACKING ROUTES
// ============================================
// Expenses are property-level (repairs, insurance, taxes, mortgage,
// utilities, management, other) and store user_id directly, unlike
// tenants/payments -- so listing/ownership checks don't need a join back
// through properties.

const EXPENSE_CATEGORIES = ['repairs', 'insurance', 'taxes', 'mortgage', 'utilities', 'management', 'other'];

// Add an expense for a property you own
app.post('/api/expenses', requireAuth, async (req, res) => {
  try {
    const { property_id, category, amount, expense_date, notes } = req.body;

    if (!property_id || !amount || !expense_date) {
      return res.status(400).json({ error: 'property_id, amount, and expense_date are required' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const safeCategory = EXPENSE_CATEGORIES.includes(category) ? category : 'other';

    const { data, error } = await supabase
      .from('expenses')
      .insert([{
        user_id: property.user_id,
        property_id,
        category: safeCategory,
        amount,
        expense_date,
        notes: notes || null,
        created_at: new Date(),
      }])
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, expense: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update an expense you own
app.put('/api/expenses/:expense_id', requireAuth, async (req, res) => {
  try {
    const { expense_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('expenses')
      .select('user_id')
      .eq('id', expense_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this expense' });
    }

    const { category, amount, expense_date, notes } = req.body;
    const updates = {
      category: EXPENSE_CATEGORIES.includes(category) ? category : 'other',
      amount,
      expense_date,
      notes: notes || null,
    };

    const { data, error } = await supabase
      .from('expenses')
      .update(updates)
      .eq('id', expense_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, expense: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete an expense you own
app.delete('/api/expenses/:expense_id', requireAuth, async (req, res) => {
  try {
    const { expense_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('expenses')
      .select('user_id')
      .eq('id', expense_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this expense' });
    }

    const { error } = await supabase.from('expenses').delete().eq('id', expense_id);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// All expenses for a landlord, across every property (used by the Reports page)
app.get('/api/expenses/landlord/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's expenses" });
    }

    const { data, error } = await supabase
      .from('expenses')
      .select('*')
      .eq('user_id', user_id)
      .order('expense_date', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, expenses: data || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Expenses for a single property you own
app.get('/api/expenses/property/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's expenses" });
    }

    const { data, error } = await supabase
      .from('expenses')
      .select('*')
      .eq('property_id', property_id)
      .order('expense_date', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, expenses: data || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// REPORTING ROUTES
// ============================================
// Income/expense report for a date range -- real money in and real money
// out only (paid payments, recorded expenses). Deliberately doesn't try to
// project "expected" rent over an arbitrary range (that gets fuzzy fast once
// tenants move in/out mid-range); the Dashboard's current-month numbers
// already cover "expected vs collected" for the present month.
app.get('/api/reports/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's reports" });
    }

    const today = new Date();
    const defaultStart = new Date(today.getFullYear(), 0, 1).toISOString().slice(0, 10);
    const defaultEnd = today.toISOString().slice(0, 10);
    const start = req.query.start || defaultStart;
    const end = req.query.end || defaultEnd;

    const { data: properties, error: propsError } = await supabase
      .from('properties')
      .select('id, address')
      .eq('user_id', user_id);
    if (propsError) return res.status(400).json({ error: propsError.message });

    const propertyIds = properties.map(p => p.id);

    const { data: tenants } = await supabase
      .from('tenants')
      .select('id, property_id')
      .in('property_id', propertyIds.length ? propertyIds : ['00000000-0000-0000-0000-000000000000']);

    const tenantToProperty = {};
    (tenants || []).forEach(t => { tenantToProperty[t.id] = t.property_id; });
    const tenantIds = (tenants || []).map(t => t.id);

    let payments = [];
    if (tenantIds.length) {
      const { data } = await supabase
        .from('payments')
        .select('*')
        .in('tenant_id', tenantIds)
        .eq('status', 'paid')
        .gte('payment_date', start)
        .lte('payment_date', end);
      payments = data || [];
    }

    const { data: expensesData } = await supabase
      .from('expenses')
      .select('*')
      .eq('user_id', user_id)
      .gte('expense_date', start)
      .lte('expense_date', end);
    const expenses = expensesData || [];

    const incomeByProperty = {};
    payments.forEach(p => {
      const propertyId = tenantToProperty[p.tenant_id];
      if (!propertyId) return;
      incomeByProperty[propertyId] = (incomeByProperty[propertyId] || 0) + (p.amount || 0);
    });

    const expensesByProperty = {};
    const expensesByCategory = {};
    expenses.forEach(e => {
      expensesByProperty[e.property_id] = (expensesByProperty[e.property_id] || 0) + (e.amount || 0);
      expensesByCategory[e.category] = (expensesByCategory[e.category] || 0) + (e.amount || 0);
    });

    const propertyReports = properties.map(p => {
      const income = incomeByProperty[p.id] || 0;
      const propertyExpenses = expensesByProperty[p.id] || 0;
      return {
        id: p.id,
        address: p.address,
        income,
        expenses: propertyExpenses,
        net: income - propertyExpenses,
      };
    });

    const totalIncome = payments.reduce((sum, p) => sum + (p.amount || 0), 0);
    const totalExpenses = expenses.reduce((sum, e) => sum + (e.amount || 0), 0);

    res.json({
      success: true,
      range: { start, end },
      summary: {
        income: totalIncome,
        expenses: totalExpenses,
        net: totalIncome - totalExpenses,
      },
      expenses_by_category: Object.entries(expensesByCategory).map(([category, amount]) => ({ category, amount })),
      properties: propertyReports,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// INSIGHTS ROUTES
// ============================================
// Portfolio-level cash flow and occupancy for landlords who think of
// themselves as investors, not just rent collectors. Occupancy is inferred
// from property_type -- there's no explicit unit-count field on properties,
// so a duplex/triplex/fourplex is assumed to be exactly that many units and
// everything else (single-family, condo, unset) is one.
// UNITS_BY_PROPERTY_TYPE / inferUnitCount now come from lib/planLogic.js (required near the top of this file).

app.get('/api/insights/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's insights" });
    }

    const { data: properties, error: propsError } = await supabase
      .from('properties')
      .select('id, address, property_type')
      .eq('user_id', user_id);
    if (propsError) return res.status(400).json({ error: propsError.message });

    const propertyIds = properties.map(p => p.id);

    const { data: tenants } = await supabase
      .from('tenants')
      .select('id, property_id, rent_amount')
      .in('property_id', propertyIds.length ? propertyIds : ['00000000-0000-0000-0000-000000000000']);
    const tenantList = tenants || [];
    const tenantIds = tenantList.map(t => t.id);

    // Last N calendar months, oldest to newest, including the current
    // (partial) month. N comes from ?months= (3, 6, or 12; default 6).
    const allowedMonthRanges = [3, 6, 12];
    const requestedMonths = parseInt(req.query.months, 10);
    const monthsCount = allowedMonthRanges.includes(requestedMonths) ? requestedMonths : 6;
    const now = new Date();
    const months = [];
    for (let i = monthsCount - 1; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push({ year: d.getFullYear(), month: d.getMonth(), label: d.toLocaleString('en-US', { month: 'short' }) });
    }

    const windowStart = new Date(months[0].year, months[0].month, 1).toISOString().slice(0, 10);
    const windowEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10);

    let payments = [];
    if (tenantIds.length) {
      const { data } = await supabase
        .from('payments')
        .select('tenant_id, amount, payment_date')
        .in('tenant_id', tenantIds)
        .eq('status', 'paid')
        .gte('payment_date', windowStart)
        .lte('payment_date', windowEnd);
      payments = data || [];
    }

    const { data: expensesData } = await supabase
      .from('expenses')
      .select('property_id, amount, category, expense_date')
      .eq('user_id', user_id)
      .gte('expense_date', windowStart)
      .lte('expense_date', windowEnd);
    const expenses = expensesData || [];

    const monthKey = (year, month) => `${year}-${String(month + 1).padStart(2, '0')}`;
    const incomeByMonth = {};
    const expensesByMonth = {};
    months.forEach(m => { incomeByMonth[monthKey(m.year, m.month)] = 0; expensesByMonth[monthKey(m.year, m.month)] = 0; });

    payments.forEach(p => {
      if (!p.payment_date) return;
      const d = new Date(p.payment_date);
      const key = monthKey(d.getFullYear(), d.getMonth());
      if (key in incomeByMonth) incomeByMonth[key] += (p.amount || 0);
    });
    expenses.forEach(e => {
      if (!e.expense_date) return;
      const d = new Date(e.expense_date);
      const key = monthKey(d.getFullYear(), d.getMonth());
      if (key in expensesByMonth) expensesByMonth[key] += (e.amount || 0);
    });

    const cashFlow = months.map(m => {
      const key = monthKey(m.year, m.month);
      const income = incomeByMonth[key] || 0;
      const expensesTotal = expensesByMonth[key] || 0;
      return { month: key, label: m.label, income, expenses: expensesTotal, net: income - expensesTotal };
    });

    const expensesByCategoryMap = {};
    expenses.forEach(e => {
      expensesByCategoryMap[e.category] = (expensesByCategoryMap[e.category] || 0) + (e.amount || 0);
    });

    // Per-property occupancy + current rent roll (what's currently leased,
    // not a particular month's collected payments).
    const tenantsByProperty = {};
    tenantList.forEach(t => {
      if (!tenantsByProperty[t.property_id]) tenantsByProperty[t.property_id] = [];
      tenantsByProperty[t.property_id].push(t);
    });

    let totalUnits = 0;
    let totalOccupied = 0;
    let totalRentRoll = 0;
    let totalVacancyLoss = 0;

    const propertyInsights = properties.map(p => {
      const propTenants = tenantsByProperty[p.id] || [];
      const units = inferUnitCount(p.property_type);
      const occupied = Math.min(propTenants.length, units);
      const vacant = Math.max(units - occupied, 0);
      const income = propTenants.reduce((sum, t) => sum + (t.rent_amount || 0), 0);
      const avgRent = occupied > 0 ? Math.round(income / occupied) : 0;
      const vacancyLoss = vacant * avgRent;

      totalUnits += units;
      totalOccupied += occupied;
      totalRentRoll += income;
      totalVacancyLoss += vacancyLoss;

      return {
        id: p.id,
        address: p.address,
        property_type: p.property_type,
        units,
        occupied,
        vacant,
        income,
        vacancy_loss: vacancyLoss,
      };
    });

    // A wholly-vacant property has no in-property rent to average from --
    // fall back to the portfolio's own average occupied rent so it still
    // gets a loss estimate instead of $0.
    const portfolioAvgRent = totalOccupied > 0 ? Math.round(totalRentRoll / totalOccupied) : 0;
    propertyInsights.forEach(p => {
      if (p.vacant > 0 && p.occupied === 0 && portfolioAvgRent > 0) {
        const extra = p.vacant * portfolioAvgRent;
        totalVacancyLoss += extra - p.vacancy_loss;
        p.vacancy_loss = extra;
      }
    });

    const currentMonth = cashFlow[cashFlow.length - 1] || { income: 0, expenses: 0, net: 0 };
    const previousMonth = cashFlow.length > 1 ? cashFlow[cashFlow.length - 2] : null;
    const netChangePct = previousMonth && previousMonth.net > 0
      ? Math.round(((currentMonth.net - previousMonth.net) / previousMonth.net) * 100)
      : null;

    res.json({
      success: true,
      summary: {
        net_cash_flow: currentMonth.net,
        net_change_pct: netChangePct,
        occupancy_units: totalUnits,
        occupancy_occupied: totalOccupied,
        occupancy_pct: totalUnits > 0 ? Math.round((totalOccupied / totalUnits) * 100) : 0,
        vacancy_loss: totalVacancyLoss,
        avg_rent_per_unit: totalOccupied > 0 ? Math.round(totalRentRoll / totalOccupied) : 0,
      },
      cash_flow: cashFlow,
      expenses_by_category: Object.entries(expensesByCategoryMap).map(([category, amount]) => ({ category, amount })),
      properties: propertyInsights,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// DOCUMENT MANAGEMENT ROUTES
// ============================================
// Files live in the private "documents" Supabase Storage bucket, one row per
// file in the "documents" table. A document is attached to a tenant (lease,
// ID copy, ...) or directly to a property (insurance policy, deed, ...),
// never both at once.

const DOCUMENTS_BUCKET = 'documents';

// Returns the landlord user_id that owns this tenant/property, or null.
async function resolveDocumentOwner(tenant_id, property_id) {
  if (tenant_id) {
    const { data: tenant } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (!tenant) return null;
    const { data: property } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    return property?.user_id || null;
  }
  if (property_id) {
    const { data: property } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', property_id)
      .single();
    return property?.user_id || null;
  }
  return null;
}

// Upload a document for a tenant or a property you manage.
// multipart/form-data fields: file, and either tenant_id or property_id, plus optional category.
app.post('/api/documents/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    const { tenant_id, property_id, category } = req.body;
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    if (!tenant_id && !property_id) {
      return res.status(400).json({ error: 'tenant_id or property_id is required' });
    }

    const ownerId = await resolveDocumentOwner(tenant_id, property_id);
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (!ownerId || (ownerId !== req.user.id && !isAdmin)) {
      return res.status(403).json({ error: 'You do not manage this tenant or property' });
    }

    const safeName = req.file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const storagePath = `${req.user.id}/${tenant_id || property_id}/${Date.now()}-${safeName}`;

    const { error: uploadError } = await supabase.storage
      .from(DOCUMENTS_BUCKET)
      .upload(storagePath, req.file.buffer, { contentType: req.file.mimetype });
    if (uploadError) {
      return res.status(400).json({ error: uploadError.message });
    }

    const { data, error } = await supabase
      .from('documents')
      .insert([{
        user_id: req.user.id,
        tenant_id: tenant_id || null,
        property_id: property_id || null,
        file_name: req.file.originalname,
        storage_path: storagePath,
        mime_type: req.file.mimetype,
        file_size: req.file.size,
        category: category || 'other',
        created_at: new Date(),
      }])
      .select();

    if (error) {
      // Insert failed -- remove the file we just uploaded so storage never
      // ends up with an orphaned object that has no matching row.
      await supabase.storage.from(DOCUMENTS_BUCKET).remove([storagePath]);
      return res.status(400).json({ error: error.message });
    }

    const { data: signed } = await supabase.storage
      .from(DOCUMENTS_BUCKET)
      .createSignedUrl(storagePath, 3600);

    res.json({ success: true, document: { ...data[0], url: signed?.signedUrl || null } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// List documents for a tenant you manage
app.get('/api/documents/tenant/:tenant_id', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;
    const ownerId = await resolveDocumentOwner(tenant_id, null);
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (!ownerId || (ownerId !== req.user.id && !isAdmin)) {
      return res.status(403).json({ error: "Cannot view another user's documents" });
    }

    const { data, error } = await supabase
      .from('documents')
      .select('*')
      .eq('tenant_id', tenant_id)
      .order('created_at', { ascending: false });
    if (error) return res.status(400).json({ error: error.message });

    const withUrls = await Promise.all((data || []).map(async (doc) => {
      const { data: signed } = await supabase.storage
        .from(DOCUMENTS_BUCKET)
        .createSignedUrl(doc.storage_path, 3600);
      return { ...doc, url: signed?.signedUrl || null };
    }));

    res.json({ success: true, documents: withUrls });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// List documents attached directly to a property you manage (building-level
// docs only -- a tenant's own documents come from the route above).
app.get('/api/documents/property/:property_id', requireAuth, async (req, res) => {
  try {
    const { property_id } = req.params;
    const ownerId = await resolveDocumentOwner(null, property_id);
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (!ownerId || (ownerId !== req.user.id && !isAdmin)) {
      return res.status(403).json({ error: "Cannot view another user's documents" });
    }

    const { data, error } = await supabase
      .from('documents')
      .select('*')
      .eq('property_id', property_id)
      .order('created_at', { ascending: false });
    if (error) return res.status(400).json({ error: error.message });

    const withUrls = await Promise.all((data || []).map(async (doc) => {
      const { data: signed } = await supabase.storage
        .from(DOCUMENTS_BUCKET)
        .createSignedUrl(doc.storage_path, 3600);
      return { ...doc, url: signed?.signedUrl || null };
    }));

    res.json({ success: true, documents: withUrls });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a document you own
app.delete('/api/documents/:document_id', requireAuth, async (req, res) => {
  try {
    const { document_id } = req.params;

    const { data: doc, error: fetchError } = await supabase
      .from('documents')
      .select('*')
      .eq('id', document_id)
      .single();
    if (fetchError || !doc) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (doc.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this document' });
    }

    await supabase.storage.from(DOCUMENTS_BUCKET).remove([doc.storage_path]);
    const { error } = await supabase.from('documents').delete().eq('id', document_id);
    if (error) return res.status(400).json({ error: error.message });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// TENANT PORTAL & MAINTENANCE ROUTES
// ============================================
// Tenants get invite-only accounts (landlord triggers a Supabase invite
// email; the tenant sets a password and logs in with email+password from
// then on -- same recovery-link pattern as the landlord forgot-password
// flow). A tenant's Supabase auth user is linked back to their tenants row
// via tenants.auth_user_id. v1 scope is view-only lease/payment info plus
// maintenance request submission -- no in-portal payments yet.

const MAINTENANCE_STATUSES = ['open', 'in_progress', 'resolved'];

// Invite a tenant you manage to create their portal login
// Sends the Supabase portal-invite email to a tenant and records the
// resulting auth_user_id. Shared by the manual "Invite to Portal" button
// and the automatic invite fired when a tenant/lease is created with an
// email on file. Throws on failure -- callers decide how to handle that
// (an HTTP error response for the manual route, a logged no-op for the
// automatic one).
async function inviteTenantToPortal(tenant) {
  const frontendUrl = process.env.FRONTEND_URL || 'https://www.praedium.pro';

  const { data: inviteData, error: inviteError } = await supabase.auth.admin.inviteUserByEmail(
    tenant.email,
    { redirectTo: `${frontendUrl}/tenant/set-password` }
  );

  if (inviteError) {
    throw new Error(inviteError.message);
  }

  const { error: updateError } = await supabase
    .from('tenants')
    .update({ auth_user_id: inviteData.user.id, invited_at: new Date() })
    .eq('id', tenant.id);

  if (updateError) {
    throw new Error(updateError.message);
  }

  return inviteData.user.id;
}

app.post('/api/tenants/:tenant_id/invite', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('*')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    if (!tenant.email) {
      return res.status(400).json({ error: 'Add an email address for this tenant before inviting them' });
    }
    if (tenant.auth_user_id) {
      return res.status(400).json({ error: 'This tenant already has a portal account' });
    }

    await inviteTenantToPortal(tenant);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tenant portal: my lease/rental info
app.get('/api/tenant-portal/me', requireTenantAuth, async (req, res) => {
  try {
    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('address')
      .eq('id', req.tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found' });
    }

    res.json({ success: true, tenant: req.tenant, property });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tenant portal: my payment history + current balance
app.get('/api/tenant-portal/payments', requireTenantAuth, async (req, res) => {
  try {
    const { data: payments, error } = await supabase
      .from('payments')
      .select('*')
      .eq('tenant_id', req.tenant.id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    // Same current-month balance math used on the landlord's tenant list,
    // so "amount due" here always matches what the landlord sees.
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
    const collectedThisMonth = (payments || [])
      .filter(p => p.status === 'paid' && new Date(p.created_at) >= startOfMonth)
      .reduce((sum, p) => sum + (p.amount || 0), 0);
    const expected = req.tenant.rent_amount || 0;
    const pending = Math.max(expected - collectedThisMonth, 0);

    res.json({
      success: true,
      payments,
      balance: {
        rent_amount: expected,
        collected_this_month: collectedThisMonth,
        pending_amount: pending,
        status: pending > 0 ? 'pending' : 'paid',
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tenant portal: my maintenance requests
app.get('/api/tenant-portal/maintenance', requireTenantAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('maintenance_requests')
      .select('*')
      .eq('tenant_id', req.tenant.id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    const withPhotoUrls = await Promise.all((data || []).map(async (r) => {
      if (!r.photo_path) return r;
      const { data: signed } = await supabase.storage
        .from(DOCUMENTS_BUCKET)
        .createSignedUrl(r.photo_path, 3600);
      return { ...r, photo_url: signed?.signedUrl || null };
    }));

    res.json({ success: true, requests: withPhotoUrls });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Tenant portal: submit a new maintenance request. Accepts multipart/form-data
// (title, description, and an optional 'photo' file) so a tenant can attach a
// picture of the issue -- plain JSON with no photo still works the same way.
app.post('/api/tenant-portal/maintenance', requireTenantAuth, uploadImage.single('photo'), async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title) {
      return res.status(400).json({ error: 'title is required' });
    }

    let photoPath = null;
    if (req.file) {
      const safeName = req.file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
      photoPath = `maintenance/${req.tenant.id}/${Date.now()}-${safeName}`;
      const { error: uploadError } = await supabase.storage
        .from(DOCUMENTS_BUCKET)
        .upload(photoPath, req.file.buffer, { contentType: req.file.mimetype });
      if (uploadError) {
        return res.status(400).json({ error: uploadError.message });
      }
    }

    const { data, error } = await supabase
      .from('maintenance_requests')
      .insert([
        {
          tenant_id: req.tenant.id,
          property_id: req.tenant.property_id,
          title,
          description: description || '',
          status: 'open',
          photo_path: photoPath,
          created_at: new Date(),
          updated_at: new Date(),
        },
      ])
      .select();

    if (error) {
      if (photoPath) {
        await supabase.storage.from(DOCUMENTS_BUCKET).remove([photoPath]);
      }
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, request: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Landlord view: all maintenance requests across your properties
app.get('/api/maintenance/landlord/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's maintenance requests" });
    }

    const { data: properties, error: propsError } = await supabase
      .from('properties')
      .select('id, address')
      .eq('user_id', user_id);
    if (propsError) return res.status(400).json({ error: propsError.message });

    const propertyIds = properties.map(p => p.id);
    if (propertyIds.length === 0) {
      return res.json({ success: true, requests: [] });
    }

    const { data: requests, error } = await supabase
      .from('maintenance_requests')
      .select('*, tenants(name, unit_label), properties(address)')
      .in('property_id', propertyIds)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    const withPhotoUrls = await Promise.all((requests || []).map(async (r) => {
      if (!r.photo_path) return r;
      const { data: signed } = await supabase.storage
        .from(DOCUMENTS_BUCKET)
        .createSignedUrl(r.photo_path, 3600);
      return { ...r, photo_url: signed?.signedUrl || null };
    }));

    res.json({ success: true, requests: withPhotoUrls });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Landlord: update a maintenance request's status
app.put('/api/maintenance/:request_id', requireAuth, async (req, res) => {
  try {
    const { request_id } = req.params;
    const { status } = req.body;

    if (!MAINTENANCE_STATUSES.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${MAINTENANCE_STATUSES.join(', ')}` });
    }

    const { data: request, error: requestError } = await supabase
      .from('maintenance_requests')
      .select('property_id')
      .eq('id', request_id)
      .single();
    if (requestError || !request) {
      return res.status(404).json({ error: 'Maintenance request not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', request.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this request' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this property' });
    }

    const { data, error } = await supabase
      .from('maintenance_requests')
      .update({ status, updated_at: new Date() })
      .eq('id', request_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, request: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// VENDOR CONTACTS (electrician, plumber, cleaner, etc.)
// ============================================
// Vendors are landlord-level, not tied to a single property -- a quick
// address book of go-to people for maintenance jobs. V1 is contact info
// only; a later version may add referral tracking.

const VENDOR_TRADES = ['general', 'plumbing', 'electrical', 'hvac', 'cleaning', 'landscaping', 'pest_control', 'locksmith', 'other'];

// List a landlord's vendors
app.get('/api/vendors/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's vendors" });
    }

    const { data, error } = await supabase
      .from('vendors')
      .select('*')
      .eq('user_id', user_id)
      .order('created_at', { ascending: true });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, vendors: data || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a vendor
app.post('/api/vendors', requireAuth, async (req, res) => {
  try {
    const { trade, name, phone, email } = req.body;

    if (!name || !phone) {
      return res.status(400).json({ error: 'name and phone are required' });
    }

    const safeTrade = VENDOR_TRADES.includes(trade) ? trade : 'general';

    const { data, error } = await supabase
      .from('vendors')
      .insert([{
        user_id: req.user.id,
        trade: safeTrade,
        name,
        phone,
        email: email || null,
        created_at: new Date(),
      }])
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, vendor: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update a vendor you own
app.put('/api/vendors/:vendor_id', requireAuth, async (req, res) => {
  try {
    const { vendor_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('vendors')
      .select('user_id')
      .eq('id', vendor_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Vendor not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this vendor' });
    }

    const { trade, name, phone, email } = req.body;
    if (!name || !phone) {
      return res.status(400).json({ error: 'name and phone are required' });
    }

    const updates = {
      trade: VENDOR_TRADES.includes(trade) ? trade : 'general',
      name,
      phone,
      email: email || null,
    };

    const { data, error } = await supabase
      .from('vendors')
      .update(updates)
      .eq('id', vendor_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, vendor: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a vendor you own
app.delete('/api/vendors/:vendor_id', requireAuth, async (req, res) => {
  try {
    const { vendor_id } = req.params;

    const { data: existing, error: fetchError } = await supabase
      .from('vendors')
      .select('user_id')
      .eq('id', vendor_id)
      .single();
    if (fetchError || !existing) {
      return res.status(404).json({ error: 'Vendor not found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (existing.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this vendor' });
    }

    const { error } = await supabase.from('vendors').delete().eq('id', vendor_id);
    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// LEASE RENEWAL ALERTS
// ============================================
// Quebec's Tribunal administratif du logement (TAL) requires landlords to
// give notice of a rent increase or other lease change within a fixed
// window before the lease ends, or the lease renews automatically on its
// existing terms. The window is 3-6 months before the end date for a lease
// of 12 months or more, and 1-2 months before the end date for a shorter
// fixed term. This is a general-reference calculation to flag upcoming
// deadlines, not legal advice -- confirm exact requirements for your
// situation before acting on it.

function addMonths(date, n) {
  const d = new Date(date);
  d.setMonth(d.getMonth() + n);
  return d;
}

function monthsBetween(start, end) {
  const s = new Date(start);
  const e = new Date(end);
  return (e.getFullYear() - s.getFullYear()) * 12 + (e.getMonth() - s.getMonth());
}

function computeRenewalWindow(tenant) {
  if (!tenant.lease_end_date) return null;

  const end = new Date(tenant.lease_end_date);
  // Unknown lease start -- default to the standard (>= 12 month) bracket,
  // the most common case for a residential lease in Quebec.
  const durationMonths = tenant.lease_start_date
    ? monthsBetween(tenant.lease_start_date, tenant.lease_end_date)
    : 12;
  const isStandardTerm = durationMonths >= 12;

  const windowStart = isStandardTerm ? addMonths(end, -6) : addMonths(end, -2);
  const windowEnd = isStandardTerm ? addMonths(end, -3) : addMonths(end, -1);

  const today = new Date();
  let status;
  if (today < windowStart) status = 'upcoming';
  else if (today <= windowEnd) status = 'in_window';
  else if (today <= end) status = 'window_passed';
  else status = 'lease_ended';

  const MS_PER_DAY = 24 * 60 * 60 * 1000;

  return {
    bracket: isStandardTerm ? '3-6 months before lease end' : '1-2 months before lease end',
    window_start: windowStart.toISOString().slice(0, 10),
    window_end: windowEnd.toISOString().slice(0, 10),
    status,
    days_until_window_opens: Math.ceil((windowStart - today) / MS_PER_DAY),
    days_until_window_closes: Math.ceil((windowEnd - today) / MS_PER_DAY),
  };
}

// Landlord view: every tenant with a lease end date, annotated with their
// TAL notice window and where they stand in it.
app.get('/api/lease-renewals/landlord/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's lease renewals" });
    }

    const { data: properties, error: propsError } = await supabase
      .from('properties')
      .select('id, address')
      .eq('user_id', user_id);
    if (propsError) return res.status(400).json({ error: propsError.message });

    const propertyById = {};
    (properties || []).forEach(p => { propertyById[p.id] = p; });
    const propertyIds = properties.map(p => p.id);
    if (propertyIds.length === 0) {
      return res.json({ success: true, renewals: [] });
    }

    const { data: tenants, error: tenantsError } = await supabase
      .from('tenants')
      .select('*')
      .in('property_id', propertyIds)
      .not('lease_end_date', 'is', null);
    if (tenantsError) return res.status(400).json({ error: tenantsError.message });

    const renewals = (tenants || [])
      .map(t => {
        const window = computeRenewalWindow(t);
        if (!window) return null;
        return {
          tenant_id: t.id,
          tenant_name: t.name,
          unit_label: t.unit_label,
          property_id: t.property_id,
          property_address: propertyById[t.property_id]?.address || null,
          lease_start_date: t.lease_start_date,
          lease_end_date: t.lease_end_date,
          renewal_notice_sent_at: t.renewal_notice_sent_at,
          ...window,
        };
      })
      .filter(Boolean)
      .sort((a, b) => new Date(a.window_start) - new Date(b.window_start));

    res.json({ success: true, renewals });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Landlord: mark that you've sent the renewal/rent-change notice for a tenant
app.post('/api/tenants/:tenant_id/renewal-notice-sent', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { data, error } = await supabase
      .from('tenants')
      .update({ renewal_notice_sent_at: new Date() })
      .eq('id', tenant_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, tenant: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Landlord: undo an accidental "notice sent" mark
app.delete('/api/tenants/:tenant_id/renewal-notice-sent', requireAuth, async (req, res) => {
  try {
    const { tenant_id } = req.params;

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('property_id')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const { data, error } = await supabase
      .from('tenants')
      .update({ renewal_notice_sent_at: null })
      .eq('id', tenant_id)
      .select();

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, tenant: data[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// SMS MESSAGING ROUTES
// ============================================

// Get all tenants across every property owned by a landlord (for the message-composer)
app.get('/api/tenants/landlord/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's tenants" });
    }

    const { data: properties, error: propsError } = await supabase
      .from('properties')
      .select('id, address')
      .eq('user_id', user_id);
    if (propsError) return res.status(400).json({ error: propsError.message });

    const propertyIds = properties.map(p => p.id);
    if (propertyIds.length === 0) {
      return res.json({ success: true, tenants: [] });
    }

    const { data: tenants, error: tenantsError } = await supabase
      .from('tenants')
      .select('*')
      .in('property_id', propertyIds);
    if (tenantsError) return res.status(400).json({ error: tenantsError.message });

    // Same per-tenant status/renewal computation as the dashboard route, so
    // any screen listing tenants (Properties, Communication Center) can show
    // paid/pending and "lease ends soon" without a second round trip.
    const tenantIds = (tenants || []).map(t => t.id);
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);

    let payments = [];
    if (tenantIds.length) {
      const { data } = await supabase
        .from('payments')
        .select('*')
        .in('tenant_id', tenantIds)
        .gte('created_at', startOfMonth.toISOString());
      payments = data || [];
    }

    const collectedByTenant = {};
    payments
      .filter(p => p.status === 'paid')
      .forEach(p => {
        collectedByTenant[p.tenant_id] = (collectedByTenant[p.tenant_id] || 0) + (p.amount || 0);
      });

    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    const today = new Date();

    const tenantsWithStatus = (tenants || []).map(t => {
      const collected = collectedByTenant[t.id] || 0;
      const expected = t.rent_amount || 0;
      const pending = Math.max(expected - collected, 0);
      const daysUntilLeaseEnd = t.lease_end_date
        ? Math.ceil((new Date(t.lease_end_date) - today) / MS_PER_DAY)
        : null;
      return {
        ...t,
        collected_this_month: collected,
        pending_amount: pending,
        status: pending > 0 ? 'pending' : 'paid',
        renewal_soon: daysUntilLeaseEnd !== null && daysUntilLeaseEnd >= 0 && daysUntilLeaseEnd <= 90,
        days_until_lease_end: daysUntilLeaseEnd,
      };
    });

    res.json({ success: true, tenants: tenantsWithStatus });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Send an SMS to one of your own tenants
app.post('/api/sms/send', requireAuth, async (req, res) => {
  try {
    const { tenant_id, message } = req.body;
    if (!tenant_id || !message) {
      return res.status(400).json({ error: 'Missing tenant_id or message' });
    }

    const { data: tenant, error: tenantError } = await supabase
      .from('tenants')
      .select('*')
      .eq('id', tenant_id)
      .single();
    if (tenantError || !tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    const { data: property, error: propertyError } = await supabase
      .from('properties')
      .select('user_id')
      .eq('id', tenant.property_id)
      .single();
    if (propertyError || !property) {
      return res.status(404).json({ error: 'Property not found for this tenant' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (property.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'You do not manage this tenant' });
    }

    const result = await sendSMS(tenant.phone, message, property.user_id);

    res.json({
      success: true,
      message_sid: result.sid,
      status: result.status,
    });
  } catch (error) {
    console.error('Send SMS error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get SMS history (sent + received) for a landlord
app.get('/api/sms/inbox/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's messages" });
    }

    const { data, error } = await supabase
      .from('sms_messages')
      .select('*')
      .eq('user_id', user_id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, messages: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SMS quick-action templates (Rent Due Reminder, Late Payment Notice,
// Payment Received, etc.) -- shared across all landlords, not per-user, so
// no ownership check is needed here.
app.get('/api/sms/templates', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('sms_templates')
      .select('*')
      .order('template_name', { ascending: true });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    res.json({ success: true, templates: data || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Twilio calls this when a tenant replies by SMS. Configure it as this number's
// "A message comes in" webhook (Twilio Console -> Phone Numbers -> your number).
app.post('/api/webhooks/twilio/inbound', express.urlencoded({ extended: false }), async (req, res) => {
  try {
    // Twilio signs every webhook request with X-Twilio-Signature so we can
    // confirm it actually came from Twilio -- without this, anyone who finds
    // this URL could POST a fake "From"/"Body" and have it recorded as an
    // inbound tenant message.
    const twilioSignature = req.headers['x-twilio-signature'];
    const webhookUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    const isValidTwilioRequest = twilio.validateRequest(
      process.env.TWILIO_AUTH_TOKEN,
      twilioSignature,
      webhookUrl,
      req.body
    );
    if (!isValidTwilioRequest) {
      console.error('Twilio inbound webhook: signature validation failed, rejecting request');
      return res.status(403).send('Forbidden');
    }

    const from = req.body.From;
    const body = req.body.Body || '';
    const messageSid = req.body.MessageSid;

    const { data: tenant } = await supabase
      .from('tenants')
      .select('*')
      .eq('phone', from)
      .maybeSingle();

    let userId = null;
    if (tenant) {
      const { data: property } = await supabase
        .from('properties')
        .select('user_id')
        .eq('id', tenant.property_id)
        .single();
      userId = property?.user_id || null;
    }

    await supabase.from('sms_messages').insert([{
      user_id: userId,
      to_phone: from,
      message: body,
      status: 'received',
      twilio_sid: messageSid,
      created_at: new Date(),
    }]);

    res.set('Content-Type', 'text/xml');
    res.send('<?xml version="1.0" encoding="UTF-8"?><Response></Response>');
  } catch (error) {
    console.error('Twilio inbound webhook error:', error);
    res.set('Content-Type', 'text/xml');
    res.status(500).send('<?xml version="1.0" encoding="UTF-8"?><Response></Response>');
  }
});

// ============================================
// BILLING ROUTES
// ============================================

// Create a hosted Stripe Checkout session for the $150/mo plan with a 30-day trial.
// Card is collected now (required to auto-convert to the paid plan after the trial),
// but nothing is charged until the trial ends.
// Current plan tier + unit usage for a landlord -- drives the pricing
// page's "current plan" state and the upgrade prompt when a create/edit is
// blocked by the unit cap.
app.get('/api/billing/plan/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'This billing account does not belong to you' });
    }

    const { data: customer } = await supabase
      .from('customers')
      .select('plan_tier, subscription_status, cancel_at_period_end, current_period_end, trial_ends_at')
      .eq('user_id', user_id)
      .single();

    const tierKey = await getPlanTierForUser(user_id);
    const tier = PLAN_TIERS[tierKey];
    const currentUnits = await getUnitUsageForUser(user_id);
    // A customer has plan_tier = Starter by default from registration, before
    // they have ever been through checkout -- subscription_status is only
    // ever set by the Stripe webhook, so its presence is what actually means
    // "this tier is active", not just "this is the fallback tier".
    const subscriptionStatus = customer ? customer.subscription_status : null;
    const hasSubscription = Boolean(subscriptionStatus);

    res.json({
      success: true,
      plan_tier: tierKey,
      plan_label: tier.label,
      max_units: tier.maxUnits === Infinity ? null : tier.maxUnits,
      current_units: currentUnits,
      subscription_status: subscriptionStatus,
      has_subscription: hasSubscription,
      cancel_at_period_end: customer ? Boolean(customer.cancel_at_period_end) : false,
      current_period_end: customer ? customer.current_period_end : null,
      trial_ends_at: customer ? customer.trial_ends_at : null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
  try {
    // Identity comes from the verified session, never the request body --
    // otherwise anyone could start a trial checkout tagged with someone
    // else's user id.
    const userId = req.user.id;
    const email = req.user.email;

    const tierKey = PLAN_TIERS[req.body.tier] ? req.body.tier : null;
    if (!tierKey) {
      return res.status(400).json({ error: `tier is required and must be one of: ${Object.keys(PLAN_TIERS).join(', ')}` });
    }
    const tier = PLAN_TIERS[tierKey];
    const priceId = process.env[tier.priceEnvVar];
    if (!priceId) {
      return res.status(500).json({ error: `${tier.priceEnvVar} is not configured on the server` });
    }

    const frontendUrl = process.env.FRONTEND_URL || 'https://www.praedium.pro';

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      customer_email: email,
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      subscription_data: {
        trial_period_days: 30,
        metadata: { user_id: userId, plan_tier: tierKey },
      },
      metadata: { user_id: userId, plan_tier: tierKey },
      success_url: `${frontendUrl}/payment?checkout=success`,
      cancel_url: `${frontendUrl}/payment?checkout=cancelled`,
    });

    res.json({ success: true, url: session.url, sessionId: session.id });
  } catch (error) {
    console.error('Create checkout session error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Switch an existing subscriber to a different tier (upgrade or downgrade).
// Unlike create-checkout-session, this modifies the existing Stripe
// subscription in place rather than starting a second one.
app.post('/api/billing/change-plan', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const tierKey = req.body.tier;

    if (!isValidTierKey(tierKey)) {
      return res.status(400).json({ error: `tier is required and must be one of: ${Object.keys(PLAN_TIERS).join(', ')}` });
    }

    const { data: customer } = await supabase
      .from('customers')
      .select('stripe_subscription_id, plan_tier')
      .eq('user_id', userId)
      .single();

    if (!customer?.stripe_subscription_id) {
      return res.status(400).json({ error: 'No active subscription found. Start a trial first.' });
    }

    if (customer.plan_tier === tierKey) {
      return res.status(400).json({ error: 'You are already on this plan' });
    }

    const tier = PLAN_TIERS[tierKey];
    const newPriceId = process.env[tier.priceEnvVar];
    if (!newPriceId) {
      return res.status(500).json({ error: `${tier.priceEnvVar} is not configured on the server` });
    }

    const subscription = await stripe.subscriptions.retrieve(customer.stripe_subscription_id);
    const itemId = subscription.items.data[0]?.id;
    if (!itemId) {
      return res.status(500).json({ error: 'Could not find subscription item to update' });
    }

    const updated = await stripe.subscriptions.update(customer.stripe_subscription_id, {
      items: [{ id: itemId, price: newPriceId }],
      proration_behavior: 'create_prorations',
      cancel_at_period_end: false,
    });

    await supabase
      .from('customers')
      .update({
        plan_tier: tierKey,
        cancel_at_period_end: false,
        current_period_end: updated.current_period_end
          ? new Date(updated.current_period_end * 1000).toISOString()
          : null,
      })
      .eq('user_id', userId);

    return res.json({ success: true, plan_tier: tierKey });
  } catch (error) {
    console.error('Change plan error:', error);
    return res.status(500).json({ error: error.message });
  }
});

// Cancel at period end -- the landlord keeps full access until the date
// they already paid through, then the subscription actually ends (handled
// by the customer.subscription.deleted webhook below).
app.post('/api/billing/cancel', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    // Both optional -- a cancellation is never blocked on giving feedback.
    const { reason, feedback } = req.body || {};

    const { data: customer } = await supabase
      .from('customers')
      .select('stripe_subscription_id, email, name')
      .eq('user_id', userId)
      .single();

    if (!customer?.stripe_subscription_id) {
      return res.status(400).json({ error: 'No active subscription found' });
    }

    const updated = await stripe.subscriptions.update(customer.stripe_subscription_id, {
      cancel_at_period_end: true,
    });

    const periodEnd = updated.current_period_end
      ? new Date(updated.current_period_end * 1000).toISOString()
      : null;

    const { error: cancelUpdateError } = await supabase
      .from('customers')
      .update({
        cancel_at_period_end: true,
        current_period_end: periodEnd,
        cancellation_reason: reason || null,
        cancellation_feedback: feedback || null,
      })
      .eq('user_id', userId);
    if (cancelUpdateError) {
      // The Stripe cancellation above already succeeded -- never fail the
      // cancellation itself over the reason/feedback not saving. Log it so
      // it's visible (e.g. the cancellation_reason/cancellation_feedback
      // columns not existing yet shows up here, not as a silent no-op).
      console.error('Failed to save cancellation reason/feedback', cancelUpdateError);
    }

    // Best-effort heads-up to the owner so a cancellation (and why) doesn't
    // just sit quietly in the database until someone happens to look.
    if (process.env.OWNER_PHONE_NUMBER) {
      try {
        const who = customer.email || customer.name || userId;
        const reasonPart = reason ? ` Reason: ${reason}.` : '';
        const feedbackPart = feedback ? ` Feedback: "${feedback}"` : '';
        await sendSMS(
          process.env.OWNER_PHONE_NUMBER,
          `Praedium: ${who} is canceling their subscription.${reasonPart}${feedbackPart}`,
          userId
        );
      } catch (smsErr) {
        console.error('Failed to send cancellation SMS alert', smsErr);
      }
    }

    return res.json({ success: true, current_period_end: periodEnd });
  } catch (error) {
    console.error('Cancel subscription error:', error);
    return res.status(500).json({ error: error.message });
  }
});

// Undo a pending cancellation -- lets someone change their mind before
// their period actually ends.
app.post('/api/billing/resume', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    const { data: customer } = await supabase
      .from('customers')
      .select('stripe_subscription_id')
      .eq('user_id', userId)
      .single();

    if (!customer?.stripe_subscription_id) {
      return res.status(400).json({ error: 'No active subscription found' });
    }

    await stripe.subscriptions.update(customer.stripe_subscription_id, {
      cancel_at_period_end: false,
    });

    await supabase
      .from('customers')
      .update({ cancel_at_period_end: false })
      .eq('user_id', userId);

    return res.json({ success: true });
  } catch (error) {
    console.error('Resume subscription error:', error);
    return res.status(500).json({ error: error.message });
  }
});



// Get billing history
app.get('/api/billing/invoices/:customer_id', requireAuth, async (req, res) => {
  try {
    const { customer_id } = req.params;

    const { data: customer } = await supabase
      .from('customers')
      .select('stripe_customer_id, user_id')
      .eq('id', customer_id)
      .single();

    if (!customer?.stripe_customer_id) {
      return res.status(400).json({ error: 'No billing account found' });
    }

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (customer.user_id !== req.user.id && !isAdmin) {
      return res.status(403).json({ error: 'This billing account does not belong to you' });
    }

    const invoices = await stripe.invoices.list({
      customer: customer.stripe_customer_id
    });

    res.json({ success: true, invoices: invoices.data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Webhook for Stripe events
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const userId = session.metadata && session.metadata.user_id;

      if (userId && session.mode === 'subscription') {
        const planTier = (session.metadata && session.metadata.plan_tier) || DEFAULT_PLAN_TIER;
        await supabase
          .from('customers')
          .update({
            stripe_customer_id: session.customer,
            stripe_subscription_id: session.subscription,
            subscription_status: 'trialing',
            plan_tier: planTier,
          })
          .eq('user_id', userId);
      } else {
        console.error('checkout.session.completed missing user_id metadata or not a subscription', session.id);
      }
    }

    if (event.type === 'invoice.payment_succeeded') {
      const invoice = event.data.object;
      await supabase
        .from('customers')
        .update({ subscription_status: 'active' })
        .eq('stripe_customer_id', invoice.customer);
    }

    if (event.type === 'invoice.payment_failed') {
      const invoice = event.data.object;
      const { data: customerRow } = await supabase
        .from('customers')
        .update({ subscription_status: 'past_due' })
        .eq('stripe_customer_id', invoice.customer)
        .select('user_id, email, phone, name')
        .single();

      const amount = ((invoice.amount_due || 0) / 100).toFixed(2);

      // Proactive alert so a failed payment doesn't just sit quietly on the
      // admin dashboard until someone happens to look. Wrapped in its own
      // try/catch -- an SMS failure here should never break the webhook ack
      // back to Stripe (which would otherwise just retry and re-fail).
      if (process.env.OWNER_PHONE_NUMBER) {
        try {
          const who = customerRow?.email || invoice.customer_email || invoice.customer;
          await sendSMS(
            process.env.OWNER_PHONE_NUMBER,
            `Praedium billing alert: payment failed for ${who} ($${amount}). Subscription is now past_due.`,
            customerRow?.user_id || null
          );
        } catch (smsErr) {
          console.error('Failed to send past_due SMS alert', smsErr);
        }
      }

      // Also let the customer themselves know -- otherwise the only way
      // they'd find out is by noticing a feature stopped working.
      if (customerRow?.phone) {
        try {
          const frontendUrl = process.env.FRONTEND_URL || 'https://www.praedium.pro';
          const firstName = (customerRow.name || '').split(' ')[0] || 'there';
          await sendSMS(
            customerRow.phone,
            `Hi ${firstName}, your Praedium payment of $${amount} didn't go through. Please update your payment method at ${frontendUrl}/payment to keep your account active.`,
            customerRow.user_id || null
          );
        } catch (smsErr) {
          console.error('Failed to send past_due SMS to customer', smsErr);
        }
      }
    }
    if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
      const subscription = event.data.object;

      const updates = {
        subscription_status: event.type === 'customer.subscription.deleted' ? 'canceled' : subscription.status,
        cancel_at_period_end: Boolean(subscription.cancel_at_period_end),
        current_period_end: subscription.current_period_end
          ? new Date(subscription.current_period_end * 1000).toISOString()
          : null,
      };

      // Keep plan_tier in sync in case the plan was changed directly in the
      // Stripe dashboard rather than through /api/billing/change-plan.
      const priceId = subscription.items?.data?.[0]?.price?.id;
      if (priceId) {
        const matchedTierKey = Object.keys(PLAN_TIERS).find(
          (key) => process.env[PLAN_TIERS[key].priceEnvVar] === priceId
        );
        if (matchedTierKey) updates.plan_tier = matchedTierKey;
      }

      await supabase
        .from('customers')
        .update(updates)
        .eq('stripe_subscription_id', subscription.id);
    }
    res.json({ received: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

// Claude's response "content" is an array of blocks, and not every block is
// guaranteed to be plain text (e.g. a leading block of a different type) --
// blindly reading content[0].text can silently come back undefined, which
// then gets sent to Twilio as an empty message body and rejected (error
// 21602 "Message body is required") with no useful trace back to the real
// cause. Pull out the first actual text block instead, and surface a clear
// error if the model didn't return one so it shows up plainly in the logs.
function extractClaudeText(response) {
  const textBlock = (response.content || []).find((block) => block.type === 'text' && block.text);
  if (!textBlock) {
    throw new Error(`Claude returned no usable text content (stop_reason: ${response.stop_reason})`);
  }
  return textBlock.text;
}

async function generateWelcomeMessage(tenantName, propertyAddress, unitLabel) {
  const message = await anthropic.messages.create({
    model: 'claude-opus-5',
    // claude-opus-5 reasons adaptively by default, and that reasoning counts
    // against max_tokens -- for a short, simple task like a one-sentence SMS
    // it can burn the whole budget thinking and leave nothing for the actual
    // text (stop_reason: "max_tokens" with no usable content). "low" effort
    // keeps it from over-thinking a trivial prompt, and 1024 leaves headroom
    // even if it reasons a little anyway.
    max_tokens: 1024,
    output_config: { effort: 'low' },
    messages: [
      {
        role: 'user',
        content: `Write a brief, friendly SMS welcome message (under 160 characters) to a new tenant whose lease was just created. Tenant name: ${tenantName}. Property: ${propertyAddress || 'their new home'}${unitLabel ? `, unit ${unitLabel}` : ''}. Be warm and professional, and mention they can submit maintenance requests and will get rent reminders through the tenant portal.`
      }
    ]
  });

  return extractClaudeText(message);
}

async function generateLandlordWelcomeMessage(landlordName) {
  const message = await anthropic.messages.create({
    model: 'claude-opus-5',
    max_tokens: 1024,
    output_config: { effort: 'low' },
    messages: [
      {
        role: 'user',
        content: `Write a brief, friendly SMS welcome message (under 160 characters) to a new landlord who just signed up for Praedium, a rental property management app. Landlord name: ${landlordName}. Be warm and professional, and mention they can start by adding their first property.`
      }
    ]
  });

  return extractClaudeText(message);
}

async function generatePaymentConfirmationMessage(tenantName, amount) {
  const message = await anthropic.messages.create({
    model: 'claude-opus-5',
    // claude-opus-5 reasons adaptively by default, and that reasoning counts
    // against max_tokens -- for a short, simple task like a one-sentence SMS
    // it can burn the whole budget thinking and leave nothing for the actual
    // text (stop_reason: "max_tokens" with no usable content). "low" effort
    // keeps it from over-thinking a trivial prompt, and 1024 leaves headroom
    // even if it reasons a little anyway.
    max_tokens: 1024,
    output_config: { effort: 'low' },
    messages: [
      {
        role: 'user',
        content: `Write a brief, friendly SMS confirmation message (under 160 characters) confirming a rent payment. Tenant name: ${tenantName}. Amount: $${amount}. Be warm and professional.`
      }
    ]
  });

  return extractClaudeText(message);
}

// Twilio requires E.164 format (+1XXXXXXXXXX) for the "to" number. The
// tenant/property forms just take whatever digits someone types, so a plain
// 10-digit North American number (the common case for Canadian/US phones)
// needs "+1" added, or it's silently rejected by Twilio. If it's already
// E.164 (starts with "+") or doesn't match a recognizable NANP shape, it's
// passed through unchanged and Twilio will raise its own clear error.
function toE164(phone) {
  if (!phone) return phone;
  const trimmed = String(phone).trim();
  if (trimmed.startsWith('+')) return trimmed;
  const digits = trimmed.replace(/\D/g, '');
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith('1')) return `+${digits}`;
  return trimmed;
}

async function sendSMS(phone, message, user_id) {
  if (!message || !String(message).trim()) {
    throw new Error('sendSMS called with an empty message body -- refusing to call Twilio');
  }
  try {
    const toPhone = toE164(phone);
    const result = await twilioClient.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: toPhone
    });

    await supabase
      .from('sms_messages')
      .insert([
        {
          user_id,
          to_phone: toPhone,
          message,
          status: result.status,
          twilio_sid: result.sid,
          created_at: new Date()
        }
      ]);

    return result;
  } catch (error) {
    console.error('SMS error:', error);
    throw error;
  }
}

function generateReceipt(tenantName, amount, paymentDate, paymentMethod) {
  return {
    tenant_name: tenantName,
    amount,
    payment_date: paymentDate,
    payment_method: paymentMethod,
    receipt_number: `REC-${Date.now()}`,
    timestamp: new Date()
  };
}

// ============================================
// AUTOMATED RENT REMINDERS
// ============================================
// Runs once a day. A tenant's rent due day is inferred from the day-of-month
// of their lease_start_date (clamped to the current month's length -- a
// lease that started on the 31st falls back to the 28th/30th in short
// months). Sends a reminder 3 days before rent is due and a late notice 2
// days after, but only when no 'paid' payment has been recorded yet this
// calendar month, so a tenant who already paid is never texted twice.
// Set ENABLE_RENT_REMINDERS=false in the environment to turn this off
// without a code change.
const RENT_REMINDERS_ENABLED = process.env.ENABLE_RENT_REMINDERS !== 'false';

function clampDueDay(dueDay, year, month) {
  const lastDayOfMonth = new Date(year, month + 1, 0).getDate();
  return Math.min(dueDay, lastDayOfMonth);
}

async function sendDueRentReminders() {
  if (!RENT_REMINDERS_ENABLED) return;
  try {
    const { data: tenants, error } = await supabase
      .from('tenants')
      .select('id, name, phone, rent_amount, lease_start_date, property_id')
      .not('lease_start_date', 'is', null)
      .not('phone', 'is', null);
    if (error) {
      console.error('Rent reminder fetch failed:', error.message);
      return;
    }

    const today = new Date();
    const year = today.getFullYear();
    const month = today.getMonth();
    const todayDateOnly = new Date(year, month, today.getDate());

    // First pass is pure in-memory date math -- figure out which tenants are
    // actually due/late today before touching the database at all.
    const candidates = [];
    for (const tenant of tenants || []) {
      if (!tenant.rent_amount) continue;

      const dueDay = new Date(tenant.lease_start_date).getDate();
      const thisMonthDueDate = new Date(year, month, clampDueDay(dueDay, year, month));
      const diffDays = Math.round((todayDateOnly - thisMonthDueDate) / 86400000);

      const isUpcoming = diffDays === -3;
      const isLate = diffDays === 2;
      if (!isUpcoming && !isLate) continue;

      candidates.push({ tenant, isUpcoming });
    }
    if (!candidates.length) return;

    // Batch-fetch this month's paid payments for just the candidate tenants
    // in one query, instead of one query per tenant.
    const candidateTenantIds = candidates.map(c => c.tenant.id);
    const startOfMonth = new Date(year, month, 1).toISOString();
    const { data: paidData, error: paidError } = await supabase
      .from('payments')
      .select('tenant_id')
      .in('tenant_id', candidateTenantIds)
      .eq('status', 'paid')
      .gte('payment_date', startOfMonth);
    if (paidError) {
      // Fail open toward sending the reminder rather than silently skipping
      // it -- paidTenantIds just stays empty below.
      console.error('Rent reminder payment check failed:', paidError.message);
    }
    const paidTenantIds = new Set((paidData || []).map(p => p.tenant_id));

    // Batch-fetch the owning user_id for every referenced property in one
    // query, instead of one query per tenant.
    const propertyIds = [...new Set(candidates.map(c => c.tenant.property_id).filter(Boolean))];
    const ownerByPropertyId = {};
    if (propertyIds.length) {
      const { data: propsData, error: propsError } = await supabase
        .from('properties')
        .select('id, user_id')
        .in('id', propertyIds);
      if (propsError) {
        console.error('Rent reminder property lookup failed:', propsError.message);
      }
      (propsData || []).forEach(p => { ownerByPropertyId[p.id] = p.user_id; });
    }

    for (const { tenant, isUpcoming } of candidates) {
      if (paidTenantIds.has(tenant.id)) continue;

      const message = isUpcoming
        ? `Hi ${tenant.name}, friendly reminder that your rent of $${tenant.rent_amount} is due in 3 days.`
        : `Hi ${tenant.name}, your rent of $${tenant.rent_amount} was due a couple days ago. Please arrange payment as soon as you can.`;

      try {
        const ownerId = ownerByPropertyId[tenant.property_id] || null;
        await sendSMS(tenant.phone, message, ownerId);
      } catch (smsError) {
        console.error(`Rent reminder SMS to tenant ${tenant.id} failed:`, smsError.message);
      }
    }
  } catch (err) {
    console.error('sendDueRentReminders failed:', err.message);
  }
}

if (RENT_REMINDERS_ENABLED) {
  cron.schedule('0 9 * * *', sendDueRentReminders);
}

// ============================================
// DASHBOARD ROUTES
// ============================================

app.get('/api/dashboard/:user_id', requireAuth, async (req, res) => {
  try {
    const { user_id } = req.params;

    const isAdmin = ADMIN_EMAILS.includes((req.user.email || '').toLowerCase());
    if (req.user.id !== user_id && !isAdmin) {
      return res.status(403).json({ error: "Cannot view another user's dashboard" });
    }

    const { data: properties } = await supabase
      .from('properties')
      .select('*')
      .eq('user_id', user_id);

    const propertyIds = properties.map(p => p.id);

    const { data: tenants } = await supabase
      .from('tenants')
      .select('*')
      .in('property_id', propertyIds.length ? propertyIds : ['00000000-0000-0000-0000-000000000000']);

    const tenantIds = tenants.map(t => t.id);
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);

    // Only this landlord's own tenants' payments -- previously this summed every
    // landlord's payments for the month, inflating everyone's "collected" total.
    let payments = [];
    if (tenantIds.length) {
      const { data } = await supabase
        .from('payments')
        .select('*')
        .in('tenant_id', tenantIds)
        .gte('created_at', startOfMonth.toISOString());
      payments = data || [];
    }

    // Rent lives on the tenant/lease now, not the property -- a duplex or
    // triplex has one rent per unit, not one for the whole building.
    // rent_amount and payment amounts are both stored in cents.
    const totalExpected = tenants.reduce((sum, t) => sum + (t.rent_amount || 0), 0);
    const totalCollected = payments
      .filter(p => p.status === 'paid')
      .reduce((sum, p) => sum + (p.amount || 0), 0);

    // Per-tenant collected/pending, so each unit shows its own status.
    const collectedByTenant = {};
    payments
      .filter(p => p.status === 'paid')
      .forEach(p => {
        collectedByTenant[p.tenant_id] = (collectedByTenant[p.tenant_id] || 0) + (p.amount || 0);
      });

    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    const today = new Date();

    const tenantsWithStatus = tenants.map(t => {
      const collected = collectedByTenant[t.id] || 0;
      const expected = t.rent_amount || 0;
      const pending = Math.max(expected - collected, 0);
      const daysUntilLeaseEnd = t.lease_end_date
        ? Math.ceil((new Date(t.lease_end_date) - today) / MS_PER_DAY)
        : null;
      return {
        ...t,
        collected_this_month: collected,
        pending_amount: pending,
        status: pending > 0 ? 'pending' : 'paid',
        // Quebec's lease non-renewal / rent-increase notice window opens
        // 3-6 months before the lease ends -- flag inside 90 days so it's
        // never missed by accident.
        renewal_soon: daysUntilLeaseEnd !== null && daysUntilLeaseEnd >= 0 && daysUntilLeaseEnd <= 90,
        days_until_lease_end: daysUntilLeaseEnd,
      };
    });

    const tenantsByProperty = {};
    tenantsWithStatus.forEach(t => {
      if (!tenantsByProperty[t.property_id]) tenantsByProperty[t.property_id] = [];
      tenantsByProperty[t.property_id].push(t);
    });

    const propertiesWithStatus = properties.map(p => {
      const propTenants = tenantsByProperty[p.id] || [];
      const collected = propTenants.reduce((sum, t) => sum + t.collected_this_month, 0);
      const expected = propTenants.reduce((sum, t) => sum + (t.rent_amount || 0), 0);
      const pending = Math.max(expected - collected, 0);
      return {
        ...p,
        tenants: propTenants,
        collected_this_month: collected,
        pending_amount: pending,
        status: pending > 0 ? 'pending' : 'paid',
      };
    });

    const renewalsSoon = tenantsWithStatus.filter(t => t.renewal_soon);

    res.json({
      success: true,
      summary: {
        total_properties: properties.length,
        total_tenants: tenants.length,
        total_expected_this_month: totalExpected,
        total_collected_this_month: totalCollected,
        pending_amount: Math.max(totalExpected - totalCollected, 0),
        late_payments: payments.filter(p => p.status === 'late').length,
        leases_renewing_soon: renewalsSoon.length
      },
      properties: propertiesWithStatus,
      tenants: tenantsWithStatus,
      renewals_soon: renewalsSoon,
      payments
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

// Platform-wide stats + user list, for the Admin Dashboard only.
// Uses the service-role client server-side -- this can never be called safely from the browser.
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const { data: usersPage, error: usersError } = await supabase.auth.admin.listUsers({ perPage: 200 });
    if (usersError) throw usersError;

    const { data: properties, error: propsError } = await supabase.from('properties').select('*');
    if (propsError) throw propsError;

    const { data: tenants, error: tenantsError } = await supabase.from('tenants').select('*');
    if (tenantsError) throw tenantsError;

    const { data: payments, error: paymentsError } = await supabase.from('payments').select('*');
    if (paymentsError) throw paymentsError;

    const { data: maintenanceRequests, error: maintenanceError } = await supabase
      .from('maintenance_requests')
      .select('status');
    if (maintenanceError) throw maintenanceError;

    const { data: customers, error: customersError } = await supabase
      .from('customers')
      .select('user_id, email, subscription_status, plan_tier, trial_ends_at, created_at');
    if (customersError) throw customersError;

    const tierPrices = await getTierMonthlyPrices();

    const users = usersPage.users.map(u => ({
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      confirmed_at: u.email_confirmed_at,
    }));

    // ---- Signups, last 8 weeks (rolling 7-day buckets, oldest first) ----
    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    const now = new Date();
    const signupsByWeek = [];
    for (let i = 7; i >= 0; i--) {
      const bucketEnd = new Date(now.getTime() - i * 7 * MS_PER_DAY);
      const bucketStart = new Date(bucketEnd.getTime() - 7 * MS_PER_DAY);
      const count = users.filter(u => {
        const created = new Date(u.created_at);
        return created > bucketStart && created <= bucketEnd;
      }).length;
      signupsByWeek.push({ week_ending: bucketEnd.toISOString().slice(0, 10), count });
    }

    // ---- Needs attention: stalled onboarding + failed/past-due billing ----
    const propertyCountByUser = {};
    properties.forEach(p => {
      propertyCountByUser[p.user_id] = (propertyCountByUser[p.user_id] || 0) + 1;
    });

    const threeDaysAgo = new Date(now.getTime() - 3 * MS_PER_DAY);
    const stalledOnboarding = users
      .filter(u => !propertyCountByUser[u.id] && new Date(u.created_at) < threeDaysAgo)
      .map(u => ({
        email: u.email,
        reason: 'no_properties',
        since: u.created_at,
      }));

    // Only a genuinely past-due or canceled subscription belongs here --
    // a customer still in their trial isn't a billing issue.
    const billingIssues = (customers || [])
      .filter(c => c.subscription_status === 'past_due' || c.subscription_status === 'canceled')
      .map(c => ({
        email: c.email,
        reason: c.subscription_status === 'past_due' ? 'payment_failed' : 'canceled',
        since: c.created_at,
      }));

    const needsAttention = [...billingIssues, ...stalledOnboarding].slice(0, 8);

    // ---- Subscription revenue: MRR, at-risk revenue, tier breakdown ----
    // "active" is the only status counted toward real recurring revenue;
    // "past_due" is still nominally subscribed but not currently paying,
    // so it's broken out separately as revenue at risk rather than folded
    // into MRR.
    const subscriptionStatusCounts = { none: 0, trialing: 0, active: 0, past_due: 0, canceled: 0 };
    const tierBreakdown = {};
    Object.keys(PLAN_TIERS).forEach((key) => {
      tierBreakdown[key] = { label: PLAN_TIERS[key].label, trialing: 0, active: 0, past_due: 0 };
    });

    let mrr = 0;
    let atRiskRevenue = 0;
    (customers || []).forEach((c) => {
      const status = c.subscription_status || 'none';
      subscriptionStatusCounts[status] = (subscriptionStatusCounts[status] || 0) + 1;

      if (status === 'trialing' || status === 'active' || status === 'past_due') {
        const tierKey = resolveTierKey(c.plan_tier);
        if (tierBreakdown[tierKey]) tierBreakdown[tierKey][status] += 1;

        const price = tierPrices[tierKey] || 0;
        if (status === 'active') mrr += price;
        if (status === 'past_due') atRiskRevenue += price;
      }
    });

    const activeSubscriberCount = subscriptionStatusCounts.active;
    const arpu = activeSubscriberCount > 0 ? mrr / activeSubscriberCount : 0;

    // ---- Platform activity ----
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const sevenDaysAgo = new Date(now.getTime() - 7 * MS_PER_DAY);

    const paymentsThisMonth = payments.filter(
      p => p.status === 'paid' && new Date(p.created_at) >= startOfMonth
    ).length;
    const maintenanceOpen = maintenanceRequests.filter(
      m => m.status === 'open' || m.status === 'in_progress'
    ).length;
    const propertiesThisWeek = properties.filter(
      p => new Date(p.created_at) >= sevenDaysAgo
    ).length;

    res.json({
      success: true,
      stats: {
        totalUsers: users.length,
        totalProperties: properties.length,
        totalTenants: tenants.length,
        // Rent dollars processed through the platform on behalf of
        // landlords' tenants -- NOT Praedium's own revenue. See
        // `subscription` below for actual MRR.
        totalRevenue: payments.reduce((sum, p) => sum + (p.amount || 0), 0),
        paymentsThisMonth,
        maintenanceOpen,
        propertiesThisWeek,
      },
      subscription: {
        mrr,
        arr: mrr * 12,
        atRiskRevenue,
        arpu,
        activeSubscriberCount,
        statusCounts: subscriptionStatusCounts,
        tierBreakdown,
      },
      signupsByWeek,
      needsAttention,
      users,
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// ============================================
// ERROR HANDLING
// ============================================



// ============================================
// START SERVER
// ============================================

// ============================================================
// ACCOUNT DATA EXPORT & DELETION (Law 25 / PIPEDA)
// ============================================================
// Self-service "right to access" and "right to erasure" for landlords.
// Export returns everything Praedium holds about the landlord's own
// account (not their properties/tenants/leases -- account-level only).
// Deletion is a request + grace period, not instant: we flag the
// account and notify the founder so it can be reviewed/actioned
// manually, rather than hard-deleting on the spot.

app.get('/api/account', requireAuth, async (req, res) => {
  try {
    const { data: account, error: accountError } = await supabase
      .from('customers')
      .select('name, email, phone')
      .eq('user_id', req.user.id)
      .single();

    if (accountError) {
      console.error('Account fetch: failed to load customer row', accountError);
      return res.status(500).json({ error: 'Failed to load account' });
    }

    return res.status(200).json(account);
  } catch (err) {
    console.error('Account fetch error', err);
    return res.status(500).json({ error: 'Failed to load account' });
  }
});

app.put('/api/account', requireAuth, async (req, res) => {
  try {
    const { phone } = req.body;

    if (phone) {
      const digitsOnly = String(phone).replace(/[^\d+]/g, '');
      if (digitsOnly.replace(/^\+/, '').length < 10) {
        return res.status(400).json({ error: 'Please enter a valid phone number' });
      }
    }

    const { data: account, error: updateError } = await supabase
      .from('customers')
      .update({ phone: phone || null })
      .eq('user_id', req.user.id)
      .select('name, email, phone')
      .single();

    if (updateError) {
      console.error('Account update: failed to save phone', updateError);
      return res.status(500).json({ error: 'Failed to save phone number' });
    }

    return res.status(200).json(account);
  } catch (err) {
    console.error('Account update error', err);
    return res.status(500).json({ error: 'Failed to save phone number' });
  }
});
app.get('/api/account/export', requireAuth, async (req, res) => {
  try {
    const { data: account, error: accountError } = await supabase
      .from('customers')
      .select('*')
      .eq('user_id', req.user.id)
      .single();

    if (accountError) {
      console.error('Account export: failed to load customer row', accountError);
      return res.status(500).json({ error: 'Failed to generate export' });
    }

    const { data: smsHistory, error: smsError } = await supabase
      .from('sms_messages')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (smsError) {
      console.error('Account export: failed to load sms_messages', smsError);
      return res.status(500).json({ error: 'Failed to generate export' });
    }

    const payload = {
      export_generated_at: new Date().toISOString(),
      account,
      sms_history: smsHistory || []
    };

    const filename = `praedium-account-export-${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.status(200).send(JSON.stringify(payload, null, 2));
  } catch (err) {
    console.error('Account export error', err);
    return res.status(500).json({ error: 'Failed to generate export' });
  }
});

app.post('/api/account/delete-request', requireAuth, async (req, res) => {
  try {
    const { data: existing, error: fetchError } = await supabase
      .from('customers')
      .select('user_id, email, name, deletion_requested_at')
      .eq('user_id', req.user.id)
      .single();

    if (fetchError || !existing) {
      console.error('Delete request: failed to load customer row', fetchError);
      return res.status(500).json({ error: 'Failed to submit deletion request' });
    }

    if (existing.deletion_requested_at) {
      return res.status(200).json({
        success: true,
        already_requested: true,
        deletion_requested_at: existing.deletion_requested_at
      });
    }

    const requestedAt = new Date().toISOString();
    const { error: updateError } = await supabase
      .from('customers')
      .update({ deletion_requested_at: requestedAt })
      .eq('user_id', req.user.id);

    if (updateError) {
      console.error('Delete request: failed to update customer row', updateError);
      return res.status(500).json({ error: 'Failed to submit deletion request' });
    }

    if (process.env.OWNER_PHONE_NUMBER) {
      try {
        const who = existing.email || existing.name || req.user.id;
        await sendSMS(
          process.env.OWNER_PHONE_NUMBER,
          `Praedium: account deletion requested by ${who}. Review within the grace period.`,
          req.user.id
        );
      } catch (smsErr) {
        console.error('Failed to send deletion-request SMS alert', smsErr);
      }
    }

    return res.status(200).json({
      success: true,
      already_requested: false,
      deletion_requested_at: requestedAt
    });
  } catch (err) {
    console.error('Delete request error', err);
    return res.status(500).json({ error: 'Failed to submit deletion request' });
  }
});

// Upload errors (e.g. a file over the multer size limit) are thrown by
// the upload.single(...) middleware before a route's own try/catch runs,
// so without this they fall through as a bare 500. Catch them here with
// a clear, user-facing message instead.
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File is too large. Maximum size is 15MB.' });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err && err.isFileFilterError) {
    return res.status(400).json({ error: err.message });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Praedium backend running on port ${PORT}`);
  });
}

module.exports = app;
