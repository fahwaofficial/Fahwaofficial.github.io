# IFZI production rollout checklist

This follow-up release is staged on `ifzi-launch-polish`. Do not merge its pull request until the checks below are complete.

## 1. Back up the existing D1 database

1. Open Cloudflare Dashboard.
2. Go to **Workers & Pages → D1 SQL Database → ifzi-mining-db**.
3. Export/download a backup of the database before changing its schema.
4. Keep the backup file outside the repository.

The migration is additive. It adds user status/referral fields and task, boost, ledger and audit tables. It does not drop or recreate existing tables.

## 2. Add Worker secrets in Cloudflare

Open **Workers & Pages → ifzi-mining-api → Settings → Variables and Secrets**. Under Production, add these as **Secrets**, not plain variables:

- `JWT_SECRET`: a newly generated random secret with at least 32 characters.
- `ADMIN_SECRET`: a different newly generated random secret with at least 32 characters.

Do not commit these values to GitHub or send them in chat.

## 3. Check GitHub Actions deployment credentials

In the repository's Settings → Secrets and variables → Actions, confirm these existing secrets are present:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

The deployment workflow uses them to apply the pending D1 migration and then deploy the Worker.

## 4. Final review and deployment

1. Confirm the draft pull request's **IFZI Worker CI** and **IFZI migration safety check** are green.
2. Confirm the D1 backup exists.
3. Only then mark the draft PR ready and merge it into `main`.
4. The main-branch deployment workflow applies pending migrations first. If migration application fails, Worker deployment stops.
5. After deployment, open `https://ifzi-mining-api.fahwaiman.workers.dev/health` and confirm it returns `ok: true`.

## 5. First live checks

1. Open `https://fahwaofficial.github.io/IFZI.html`.
2. Connect a TON Mainnet wallet that uses one of the supported standard wallet versions (V1R1–V5R1).
3. A valid TON Proof automatically verifies and approves a normal wallet; the site starts its 24-hour mining cycle after verification. Wallets marked `under_review` or `suspended` remain restricted.
4. Confirm the center IFZI logo shows the live 24-hour countdown; after expiry, tap the same logo to claim the reward. Confirm the balance remains after a refresh.
5. Test an exact withdrawal amount (minimum 1,000 IFZI) after at least one social task is approved. Withdrawal requests remain manually reviewed and paid by the administrator.

Unknown wallet implementations fail closed. WalletTg is not yet supported by this verifier.

## 6. Optional one-time 0.05 TON task

The 0.05 TON payment is the only paid task and is entirely optional. Ordinary Telegram, YouTube, X and Daily Check-in tasks do not require TON. After the Worker verifies a successful TON Mainnet transaction from the user's own verified wallet, to the configured receiver, for exactly 50,000,000 nanotons, it credits exactly 50,000 IFZI to that user's internal rewards balance. The reward is limited to one successful claim per wallet and is recorded in `ton_boost_payments`, `pool_ledger` and `reward_balances`. It does not multiply ordinary social-task rewards or mining rewards.

Before announcing the task publicly, deploy the Worker and run a controlled end-to-end mainnet test. Confirm the payment sender, receiver, exact amount, transaction hash, one-time restriction, pool allocation accounting and immediate balance update. Never ask users to send a second payment while the first is being checked.
