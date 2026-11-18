-- IFZI private allocation workflow. Additive only; existing mining data is untouched.
CREATE TABLE IF NOT EXISTS presale_orders (
  id TEXT PRIMARY KEY,
  amount_raw TEXT NOT NULL,
  buyer_wallet_raw TEXT NOT NULL,
  settlement_asset TEXT NOT NULL CHECK(settlement_asset IN ('TON','USDT','OTHER')),
  offer_text TEXT,
  agreed_amount_nano TEXT,
  status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','awaiting_payment','payment_verified','approved','delivered','rejected')),
  payment_tx_hash TEXT UNIQUE,
  payment_amount_nano TEXT,
  outgoing_tx_hash TEXT,
  admin_note TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_presale_orders_status_created ON presale_orders(status,created_at);
CREATE INDEX IF NOT EXISTS idx_presale_orders_wallet_created ON presale_orders(buyer_wallet_raw,created_at);
