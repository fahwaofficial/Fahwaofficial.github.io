-- IFZI 30-day streaks and weekly milestone reward ledger.
-- Additive only: existing user, balance, claim and withdrawal rows are untouched.
CREATE TABLE IF NOT EXISTS streak_rewards (
  user_id TEXT NOT NULL REFERENCES users(id),
  cycle_start_date TEXT NOT NULL,
  milestone_day INTEGER NOT NULL CHECK(milestone_day IN (7,14,21,28)),
  reward_raw TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, cycle_start_date, milestone_day)
);
CREATE TABLE IF NOT EXISTS monthly_badges (
  user_id TEXT NOT NULL REFERENCES users(id),
  cycle_start_date TEXT NOT NULL,
  badge_code TEXT NOT NULL,
  awarded_at INTEGER NOT NULL,
  PRIMARY KEY(user_id, cycle_start_date)
);
CREATE INDEX IF NOT EXISTS idx_monthly_badges_user_awarded
  ON monthly_badges(user_id, awarded_at DESC);
