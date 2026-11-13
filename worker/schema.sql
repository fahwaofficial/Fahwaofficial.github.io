PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  wallet_raw TEXT NOT NULL UNIQUE,
  telegram_id TEXT UNIQUE,
  referred_by TEXT REFERENCES users(id),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_challenges (
  nonce TEXT PRIMARY KEY,
  wallet_raw TEXT,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mining_cycles (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  level INTEGER NOT NULL,
  daily_rate_raw TEXT NOT NULL,
  gross_reward_raw TEXT NOT NULL,
  referral_user_id TEXT,
  started_at INTEGER NOT NULL,
  ends_at INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','completed','claimed'))
);
CREATE INDEX IF NOT EXISTS idx_cycles_user_status ON mining_cycles(user_id,status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_unclaimed_cycle_per_user ON mining_cycles(user_id) WHERE status IN ('running','completed');

CREATE TABLE IF NOT EXISTS reward_balances (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  available_raw TEXT NOT NULL DEFAULT '0',
  total_earned_raw TEXT NOT NULL DEFAULT '0',
  total_referral_raw TEXT NOT NULL DEFAULT '0'
);

CREATE TABLE IF NOT EXISTS claims (
  cycle_id TEXT PRIMARY KEY REFERENCES mining_cycles(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  gross_raw TEXT NOT NULL,
  user_raw TEXT NOT NULL,
  referral_raw TEXT NOT NULL,
  referral_user_id TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS withdrawals (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  wallet_raw TEXT NOT NULL,
  amount_raw TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','paid','rejected')),
  tx_hash TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status,created_at);

CREATE TABLE IF NOT EXISTS pool_state (
  id INTEGER PRIMARY KEY CHECK(id=1),
  total_raw TEXT NOT NULL,
  distributed_raw TEXT NOT NULL DEFAULT '0',
  reserved_raw TEXT NOT NULL DEFAULT '0'
);
INSERT OR IGNORE INTO pool_state(id,total_raw,distributed_raw)
VALUES(1,'8400000000000000','0');
