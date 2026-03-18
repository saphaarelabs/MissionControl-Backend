CREATE TABLE IF NOT EXISTS billing_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    userid TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL DEFAULT 'xpay',
    plan_key TEXT NOT NULL,
    billing_cycle TEXT NOT NULL,
    amount_cents INTEGER,
    currency TEXT NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL DEFAULT 'checkout_pending',
    xpay_subscription_id TEXT UNIQUE,
    xpay_receipt_id TEXT UNIQUE,
    checkout_url TEXT,
    customer_email TEXT,
    customer_name TEXT,
    last_event_type TEXT,
    raw_last_payload JSONB,
    activated_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_status
    ON billing_subscriptions(status);

CREATE INDEX IF NOT EXISTS idx_billing_subscriptions_provider
    ON billing_subscriptions(provider);
