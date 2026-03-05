-- =====================================================
-- MIGRATION: Add Idempotent Provisioning Support
-- Run this in Supabase SQL Editor
-- =====================================================

-- Step 1: Add new columns to user_profiles
ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS provisioning_lock_id TEXT,
    ADD COLUMN IF NOT EXISTS provisioning_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS provisioning_completed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS provisioning_error TEXT,
    ADD COLUMN IF NOT EXISTS provisioning_retry_count INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_health_check TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Step 2: Add 'failed' status to enum (if not exists)
DO $$ 
BEGIN
    ALTER TYPE user_operation_status ADD VALUE IF NOT EXISTS 'failed';
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Step 3: Create indexes
CREATE INDEX IF NOT EXISTS idx_user_profiles_status 
    ON user_profiles(operation_status);

CREATE INDEX IF NOT EXISTS idx_user_profiles_lock 
    ON user_profiles(provisioning_lock_id) 
    WHERE provisioning_lock_id IS NOT NULL;

-- Step 4: Copy/paste all the functions from supabase-schema.sql:
-- - acquire_provisioning_lock
-- - complete_provisioning  
-- - fail_provisioning
-- - get_provisioning_status
-- - cleanup_stale_provisioning

-- Step 5: Migrate existing data
-- Mark all current 'provisioning' states as 'failed' if they're stale
UPDATE user_profiles
SET 
    operation_status = 'failed',
    provisioning_error = 'Migrated from old system - please retry',
    provisioning_completed_at = NOW()
WHERE operation_status = 'provisioning';

-- Step 6: Verify
SELECT 
    operation_status, 
    COUNT(*) as count,
    COUNT(CASE WHEN provisioning_error IS NOT NULL THEN 1 END) as with_errors
FROM user_profiles
GROUP BY operation_status;

-- Expected output:
-- status        | count | with_errors
-- --------------|-------|------------
-- onboarded     | X     | 0
-- ready         | Y     | 0  
-- failed        | Z     | Z  (all failed have errors)
