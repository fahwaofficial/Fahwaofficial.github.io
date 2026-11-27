# IFZI Fixed-Price Presale — Acton/Tolk

## Status

Design and implementation workspace only. This branch is isolated from `main`; nothing here is deployed and the website preview remains non-purchasable until the contract passes local and Testnet integration tests.

## Confirmed sale parameters

- Network: TON
- Jetton master: `EQB9KGhnd0PA00ml_eXZoVrQKWrcxRv3NN3LNWoQp_RqDaA0`
- Jetton decimals: 9
- Sale inventory: 10,000,000 IFZI = `10000000000000000` base units
- Fixed price: 10,000 IFZI per 1 TON
- Maximum proceeds at full sell-out: 1,000 TON
- TON proceeds recipient (user-designated existing treasury): `UQAzPsvm5wnLdBiVqNV07mJvDEDZEfT1fQb08tw0oE4Lb40D`

The treasury address is user-designated, not independently proven to be controlled by the project. Confirm it from the project's own wallet before Mainnet.

## Architecture decision

Use the current TON toolchain: Acton + Tolk. Do not start a new Tact/Blueprint implementation: the current official TON tooling marks Tact and Blueprint deprecated for new projects and recommends Acton/Tolk.

The sale contract must own a dedicated IFZI Jetton wallet funded with the sale inventory. Buyers send TON to the sale contract; the contract routes sale proceeds to the treasury and requests a Jetton transfer from its own Jetton wallet to the buyer. The contract must validate the actual Jetton wallet/notification against the configured IFZI master; never trust a wallet address supplied by the browser.

Important TON constraint: Jetton transfers are asynchronous multi-message flows. A successful TON payment must not be treated as proof that IFZI reached the buyer. The implementation must model pending purchases and handle bounced messages, insufficient attached TON, recipient Jetton-wallet deployment, and refunds or a recoverable claim path. Do not describe the purchase as atomic unless end-to-end tests prove the complete delivery/refund behavior.

## Required contract controls

- Immutable IFZI master, fixed price, and sale inventory cap.
- Explicit owner/admin address.
- Pause and resume purchases.
- Reject payments when paused, sold out, malformed, or below any configured minimum.
- Exact integer arithmetic only; no floating-point math.
- Unique purchase identifiers and replay protection.
- Safe Jetton-wallet validation against the configured master.
- Clear accounting for sold, pending, delivered, and refundable amounts.
- Owner-only withdrawal of unsold IFZI after the sale is paused/closed.
- Owner-only withdrawal of TON proceeds to the designated treasury, without allowing arbitrary redirection.
- No minting and no seed phrase/private-key collection.
- Emergency path must not let the owner confiscate a buyer's paid-but-undelivered allocation.

## Test gates before Testnet

1. Build and static checks pass using Acton.
2. Local emulator tests cover exact price math, cap, sold-out, pause, unauthorized admin calls, fake Jetton-wallet rejection, replay, insufficient gas, and all bounce/refund paths.
3. Integration tests cover the real IFZI Jetton master and derived sale Jetton-wallet address.
4. Testnet deployment uses a testnet-only configuration and test Jettons; never send Mainnet IFZI or TON during this phase.
5. Testnet purchase, delivery, pause, unsold inventory withdrawal, and treasury withdrawal are verified in an explorer.
6. Only after user approval and independent review should a separate Mainnet deployment be prepared.

## Cost approach

Acton/Tolk, local compilation, and emulator tests are open-source tooling; no hosted launchpad fee is required. Testnet uses faucet funds. Mainnet deployment and each on-chain message/Jetton transfer require real TON for network fees. Exact cost must be measured from the compiled contract and Testnet transactions; do not promise a fixed fee in advance.

## Current implementation boundary

This document records the agreed parameters and security requirements. It is not a compiled contract, audit, deployment, or live sale. The existing preview file `IFZI-fixed-presale.html` remains disabled until the contract address and verified integration are available.
