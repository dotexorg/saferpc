# Changelog

One file per sync round. Newest first. Each entry is dated and named by the main themes it landed.

| Date | What landed |
|------|-------------|
| 2026-07-16 | v0.8.0 (0.7 + 0.8 work): no-auto-retry + deferred-reset + replay-window + abortPending, make-before-break + reconnecting ws/socket channels, sendTimeout 10s→3s, port-complete spec+KAT vectors; handshake absolute deadlines + maxPendingHandshakes + epoch-exhaustion guard, normative JWT/Ed25519/ECDSA auth profiles, cert+MFA helpers removed, bigint/cyclic/NaN input validation, all-zero-secret + replay-slot + directionality fixes, middleware fire-and-forget next() fails closed + sync-throw normalized, Node ≥20.19 |

---

*Format: `changelog/YYYY-MM-DD-kebab-keywords.md`. Each word is a grep anchor — not a description. Target 60-80 chars, hard cap 100. Add new entries at the top of the table.*
