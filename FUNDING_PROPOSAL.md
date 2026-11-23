# IFZI — Development & Ecosystem Funding Proposal

**Project:** IFZI Community Mining  
**Network:** TON  
**Founder:** Fahwa  
**Website:** https://fahwaofficial.github.io/IFZI.html  
**Source code:** https://github.com/Fahwaofficial/Fahwaofficial.github.io  
**Telegram:** https://t.me/fahwa.bot  
**Jetton master:** `EQB9KGhnd0PA00ml_eXZoVrQKWrcxRv3NN3LNWoQp_RqDaA0`  
**Primary DEX pool:** https://app.ston.fi/pools/EQBjAe1hG6qi7AqSEXR7B6tueAvY5uONHDAIa8fJuX_B64f8

## 1. Executive summary

IFZI is a TON-based community token project with a Telegram-oriented user-acquisition and engagement concept. The project is developing a web mining experience where users connect a TON wallet, participate in time-based mining cycles, complete optional community tasks, invite other users, and accumulate rewards recorded by the project backend.

The long-term objective is to make IFZI useful as a community participation and rewards asset—not to promote short-term price speculation. We want to attract real users to Telegram and TON, give them a transparent way to earn a limited allocation over time, and build a sustainable project with public accounting and clear rules.

We are seeking **up to USD 10,000 in development and ecosystem support**, or a smaller milestone-based grant, to improve the reliability, security, usability, documentation, and adoption readiness of the product. This is a funding request, not a claim that funding has been approved or guaranteed.

## 2. Why this project may benefit the TON ecosystem

IFZI is designed around several ecosystem contributions:

- Bring users into a TON-connected Telegram community and introduce them to TON wallets and on-chain tokens.
- Give users a reason to return through transparent 24-hour participation cycles and free community tasks.
- Direct users to an existing TON DEX market when they independently choose to trade.
- Encourage responsible self-custody: the project must never request seed phrases or private keys.
- Publish understandable token allocation, reward, withdrawal, and development information.

We will not promise token-price appreciation, guaranteed returns, or guaranteed exchange listings. Mining rewards are community incentives and carry token-price and liquidity risk.

## 3. Product and current project status

The public project includes:

- A GitHub Pages web interface for IFZI community mining.
- TON Connect wallet connection.
- A Cloudflare Worker API and D1 database for account and mining-cycle records.
- A STON.fi swap-widget integration and a link to the IFZI/TON liquidity pool.
- A public IFZI Jetton master address and community channels.
- Community task and referral concepts, with rewards subject to the published rules and backend verification.

**Important status disclosure:** the mining and claim experience is still undergoing reliability testing. Wallet connection, cycle start, claim processing, database accounting, and withdrawal handling must pass end-to-end tests before the project describes mining as fully operational. Wallet connection currently uses an address-based session; it does not constitute cryptographic proof of wallet ownership. We intend to improve this security model before scaling distribution.

## 4. Token allocation and distribution plan

The project has designated **8,400,000 IFZI** as the mining allocation. The intended distribution horizon is approximately **two years**, subject to a published emission schedule, verified available reserves, and a functioning reward ledger.

Proposed principles:

1. Publish the allocation, total distributed amount, reserved amount, and remaining balance.
2. Calculate rewards on the server, not in the user's browser.
3. Use a fixed 24-hour cycle and prevent duplicate claims.
4. Keep referral rewards within the published 10% share and account for them in the same mining allocation.
5. Make ordinary participation and community tasks free; any optional paid feature must be clearly disclosed and must never be required to receive ordinary mining rewards.
6. Set a transparent minimum withdrawal and process withdrawals through a documented manual review and payout queue until a safe automated payout process is independently tested.
7. Publish changes before they take effect and preserve an audit trail for administrative actions.

The exact daily emission should be derived from the remaining allocation and the final reward rules, not advertised as a guaranteed fixed yield.

## 5. Funding request

**Requested amount: up to USD 10,000**

We are open to a smaller grant released against measurable milestones. Proposed use of funds:

| Workstream | Budget | Deliverables |
|---|---:|---|
| Mining backend reliability and security | $4,000 | End-to-end wallet/session, cycle-start, claim, duplicate-claim and database consistency tests; security fixes and monitoring |
| TON / STON.fi integration and testing | $2,500 | Validate swap-widget behavior, token/pool metadata, transaction routing and user-facing disclosures |
| Infrastructure, observability and QA | $1,500 | Error reporting, health checks, backups, deployment checks and regression tests |
| Documentation and user experience | $1,000 | User guide, risk disclosures, project documentation and accessible onboarding |
| Contingency for verified technical issues | $1,000 | Remediation of issues found during independent testing |

This is a proposed budget. Any grant provider's eligible-cost rules and reporting requirements will take precedence. We will not use a development grant for token-price support, market manipulation, wash trading, or undisclosed purchases of IFZI.

## 6. Milestones and reporting

### Milestone A — Stabilize the product
- Verify the production API and database schema without deleting or recreating user data.
- Test wallet connection, session persistence, mining start, 24-hour completion, claim, next-cycle start, and account refresh.
- Ensure a failed claim does not falsely report success or lose a user's recorded reward.
- Add structured error reporting and regression tests.

### Milestone B — Improve security and transparency
- Replace address-only authentication with a properly validated TON proof flow before relying on wallet ownership for sensitive actions.
- Keep private keys and seed phrases entirely outside the application.
- Verify all optional on-chain payments server-side before crediting any associated benefit.
- Publish reward accounting, withdrawal rules, administrative controls, and risk disclosures.

### Milestone C — Improve TON user experience
- Test the STON.fi integration on supported wallets and mobile in-app browsers.
- Provide clear token-master and pool links so users can verify the correct asset.
- Improve onboarding and explain network fees, slippage, liquidity, and token volatility.

### Milestone D — Community launch and measurement
- Run a limited test cohort before wider promotion.
- Report active users, completed cycles, successful claims, task participation, support incidents, and distribution totals.
- Use opt-in community education and transparent announcements rather than paid or artificial trading volume.

Progress reports will link to public code changes and, where appropriate, on-chain transactions and aggregate platform metrics. Personal wallet data will not be published as a user list.

## 7. Sustainability and user protection

IFZI's success will be measured by genuine participation and product reliability—not by short-term price spikes or trading volume alone.

Safeguards include:

- No collection of seed phrases or private keys.
- No promise of profit, fixed APY, or token-price growth.
- No undisclosed paid tasks; ordinary mining and ordinary community tasks remain free.
- Server-side reward calculations and duplicate-claim protection.
- Public disclosure of the mining allocation and distribution progress.
- Manual withdrawal review with transaction-hash records until payout automation is safely validated.
- Clear risk warnings for DEX trading and liquidity provision, including slippage and impermanent loss.

## 8. Partnership opportunities

We would welcome one or more of the following forms of support:

- A development grant or technical review.
- STON.fi / TON developer mentorship and integration feedback.
- Community education, ecosystem directory exposure, or an opportunity to present the project.
- Introductions to aligned TON ecosystem partners or responsible early-stage investors.
- A separate, clearly disclosed marketing partnership if a suitable program is available.

We understand that a grant, listing, marketing placement, or investment is subject to each partner's own review and is not guaranteed.

## 9. Links and verification

- Website: https://fahwaofficial.github.io/IFZI.html
- GitHub repository: https://github.com/Fahwaofficial/Fahwaofficial.github.io
- Telegram bot: https://t.me/fahwa.bot
- IFZI Jetton master: `EQB9KGhnd0PA00ml_eXZoVrQKWrcxRv3NN3LNWoQp_RqDaA0`
- STON.fi pool: https://app.ston.fi/pools/EQBjAe1hG6qi7AqSEXR7B6tueAvY5uONHDAIa8fJuX_B64f8

## 10. Contact

**Project lead:** Fahwa  
**Preferred contact:** Telegram community / project bot above.

Thank you for considering IFZI. We would be glad to provide a live product walkthrough, technical architecture, milestone plan, and further evidence requested during due diligence.
