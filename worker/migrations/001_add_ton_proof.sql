-- IFZI additive core migration.
-- Safe for the existing production schema inspected on 2026-11-18.
-- This migration intentionally does not drop, rename, or recreate existing tables.

ALTER TABLE users ADD COLUMN network TEXT NOT NULL DEFAULT '-239';
ALTER TABLE users ADD COLUMN wallet_status TEXT NOT NULL DEFAULT 'pending'
  CHECK(wallet_status IN ('pending','approved','under_review','suspended'));
ALTER TABLE users ADD COLUMN wallet_verified_at INTEGER;
ALTER TABLE users ADD COLUMN suspended_reason TEXT;
ALTER TABLE users ADD COLUMN updated_at INTEGER;
ALTER TABLE users ADD COLUMN referral_code TEXT;
ALTER TABLE users ADD COLUMN task_boost_multiplier INTEGER NOT NULL DEFAULT 1 CHECK(task_boost_multiplier IN (1,3));

CREATE UNIQUE INDEX idx_users_referral_code ON users(referral_code)
  WHERE referral_code IS NOT NULL;
CREATE INDEX idx_users_wallet_status ON users(wallet_status, created_at);

ALTER TABLE withdrawals ADD COLUMN review_note TEXT;

CREATE TABLE task_submissions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  task_key TEXT NOT NULL CHECK(task_key IN ('telegram','youtube','x')),
  proof_url TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','approved','rejected')),
  reviewed_by TEXT,
  review_note TEXT,
  created_at INTEGER NOT NULL,
  reviewed_at INTEGER
);
CREATE INDEX idx_task_submissions_user_status
  ON task_submissions(user_id, status, created_at);

CREATE TABLE daily_checkins (
  user_id TEXT NOT NULL REFERENCES users(id),
  checkin_date TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, checkin_date)
);

CREATE TABLE ton_boost_payments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  tx_hash TEXT NOT NULL UNIQUE,
  sender_raw TEXT NOT NULL,
  destination_raw TEXT NOT NULL,
  amount_nano TEXT NOT NULL,
  network TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','verified','rejected')),
  verified_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_ton_boost_user_status
  ON ton_boost_payments(user_id, status, created_at);

CREATE TABLE pool_ledger (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL
    CHECK(event_type IN ('mining_claim','referral','withdrawal_paid','manual_bonus','boost_task','task_reward','daily_checkin')),
  user_id TEXT REFERENCES users(id),
  amount_raw TEXT NOT NULL,
  reference_id TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(event_type, reference_id)
);
CREATE INDEX idx_pool_ledger_user ON pool_ledger(user_id, created_at);

CREATE TABLE admin_audit (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  details TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE daily_emissions (
  emission_date TEXT PRIMARY KEY,
  emitted_raw TEXT NOT NULL DEFAULT '0',
  updated_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO pool_state(id,total_raw,distributed_raw,reserved_raw)
VALUES(1,'8400000000000000','0','0');
