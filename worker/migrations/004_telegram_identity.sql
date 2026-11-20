-- Link a verified Telegram Mini App user to the pending TON Proof challenge.
-- Additive only; no existing user, wallet, reward, claim or referral data is changed.
ALTER TABLE auth_challenges ADD COLUMN telegram_id TEXT;
