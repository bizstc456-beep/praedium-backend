// Pure plan-tier / unit-cap logic, deliberately kept dependency-free (no
// supabase, stripe, or twilio) so it can be unit-tested in isolation --
// see ../__tests__/planLogic.test.js. server.js requires this file as the
// single source of truth; never redefine these constants in server.js.

const PLAN_TIERS = {
  starter: { label: 'Starter', maxUnits: 5, priceEnvVar: 'STRIPE_PRICE_STARTER' },
  growth: { label: 'Growth', maxUnits: 20, priceEnvVar: 'STRIPE_PRICE_GROWTH' },
  portfolio: { label: 'Portfolio', maxUnits: Infinity, priceEnvVar: 'STRIPE_PRICE_PORTFOLIO' },
};
const DEFAULT_PLAN_TIER = 'starter';

// Occupancy is inferred from property_type -- there's no explicit
// unit-count field on properties, so a duplex/triplex/fourplex is assumed
// to be exactly that many units and everything else (single-family, condo,
// unset) is one.
const UNITS_BY_PROPERTY_TYPE = { duplex: 2, triplex: 3, fourplex: 4 };

function inferUnitCount(propertyType) {
  return UNITS_BY_PROPERTY_TYPE[propertyType] || 1;
}

function isValidTierKey(key) {
  return Boolean(PLAN_TIERS[key]);
}

// Falls back to Starter for a missing or unrecognized stored tier key (e.g.
// a customers row that predates the plan_tier column).
function resolveTierKey(storedTierKey) {
  return PLAN_TIERS[storedTierKey] ? storedTierKey : DEFAULT_PLAN_TIER;
}

// Would adding `additionalUnits` push a landlord on `tierKey` over their cap?
function wouldExceedCap(tierKey, currentUnits, additionalUnits) {
  const tier = PLAN_TIERS[tierKey] || PLAN_TIERS[DEFAULT_PLAN_TIER];
  return (currentUnits + additionalUnits) > tier.maxUnits;
}

module.exports = {
  PLAN_TIERS,
  DEFAULT_PLAN_TIER,
  UNITS_BY_PROPERTY_TYPE,
  inferUnitCount,
  isValidTierKey,
  resolveTierKey,
  wouldExceedCap,
};
