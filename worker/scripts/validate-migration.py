#!/usr/bin/env python3
"""Validate IFZI migration 001 against the production schema snapshot.

This test uses an in-memory SQLite database only. It never connects to Cloudflare.
"""
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
migration = ROOT / "worker" / "migrations" / "001_add_ton_proof.sql"

db = sqlite3.connect(":memory:")
db.execute("PRAGMA foreign_keys = ON")
db.executescript("""
CREATE TABLE users (
 id TEXT PRIMARY KEY, wallet_raw TEXT NOT NULL UNIQUE,
 telegram_id TEXT UNIQUE, referred_by TEXT REFERENCES users(id),
 created_at INTEGER NOT NULL
);
CREATE TABLE auth_challenges (
 nonce TEXT PRIMARY KEY, wallet_raw TEXT,
 expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE mining_cycles (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 level INTEGER NOT NULL, daily_rate_raw TEXT NOT NULL,
 gross_reward_raw TEXT NOT NULL, referral_user_id TEXT,
 started_at INTEGER NOT NULL, ends_at INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('running','completed','claimed'))
);
CREATE TABLE claims (
 cycle_id TEXT PRIMARY KEY REFERENCES mining_cycles(id),
 user_id TEXT NOT NULL REFERENCES users(id), gross_raw TEXT NOT NULL,
 user_raw TEXT NOT NULL, referral_raw TEXT NOT NULL,
 referral_user_id TEXT, created_at INTEGER NOT NULL
);
CREATE TABLE pool_state (
 id INTEGER PRIMARY KEY CHECK(id=1), total_raw TEXT NOT NULL,
 distributed_raw TEXT NOT NULL DEFAULT '0', reserved_raw TEXT NOT NULL DEFAULT '0'
);
CREATE TABLE reward_balances (
 user_id TEXT PRIMARY KEY REFERENCES users(id),
 available_raw TEXT NOT NULL DEFAULT '0',
 total_earned_raw TEXT NOT NULL DEFAULT '0',
 total_referral_raw TEXT NOT NULL DEFAULT '0'
);
CREATE TABLE withdrawals (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 wallet_raw TEXT NOT NULL, amount_raw TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','approved','paid','rejected')),
 tx_hash TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
INSERT INTO pool_state(id,total_raw,distributed_raw) VALUES
 (1,'8400000000000000','0');
""")

# Seed records prove migration preserves existing rows.
db.execute("INSERT INTO users(id,wallet_raw,created_at) VALUES('u1','0:abc',1)")
db.execute("INSERT INTO reward_balances(user_id,available_raw) VALUES('u1','123000000000')")
db.execute("INSERT INTO withdrawals(id,user_id,wallet_raw,amount_raw,status,created_at,updated_at) VALUES('w1','u1','0:abc','1000000000','pending',1,1)")

db.executescript(migration.read_text(encoding="utf-8"))
assert db.execute("SELECT wallet_raw FROM users WHERE id='u1'").fetchone()[0] == "0:abc"
assert db.execute("SELECT available_raw FROM reward_balances WHERE user_id='u1'").fetchone()[0] == "123000000000"
assert db.execute("SELECT status FROM withdrawals WHERE id='w1'").fetchone()[0] == "pending"
assert db.execute("SELECT total_raw FROM pool_state WHERE id=1").fetchone()[0] == "8400000000000000"

expected = {
 "task_submissions", "daily_checkins", "ton_boost_payments",
 "pool_ledger", "admin_audit"
}
actual = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
assert expected <= actual
columns = {r[1] for r in db.execute("PRAGMA table_info(users)")}
assert {"network", "wallet_status", "wallet_verified_at", "referral_code"} <= columns
challenge_columns = {r[1] for r in db.execute("PRAGMA table_info(auth_challenges)")}
assert "referral_code" in challenge_columns
print("PASS: migration applies to production schema snapshot; seeded user, balance, withdrawal and pool data preserved.")
