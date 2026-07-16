# Reviews

Independent review artifacts for the 0.7 and 0.8 release lines. These are the
audits, design-review requests, and verdicts that drove the changes recorded in
`../changelog/`. Every finding raised here was re-verified in shipped code and
closed before release — nothing security-sensitive remains open, which is why
they're published rather than kept local.

Reviewers are distinct independent LLM auditors (referred to by handle in the
filenames): **Fable** and **gpt-5.6-sol** (the "porter" cross-language audit),
plus **neutral** passes done with a fresh, verdict-free context. Read each audit
as an outside opinion, not ground truth — the ground truth is the code + tests it
was checked against.

Files are grouped by the release they fed into and named `…-YYYY-MM-DD` where a
date applies. Read top to bottom within each table for chronological order.

## 0.7 line — client & transport rework

Landed: no-auto-retry, deferred reset, replay window, `abortPending`,
make-before-break session continuity, reconnecting channel adapters, and the
first port-complete spec + KAT vectors.

| # | File | What it is |
|---|------|-----------|
| 1 | [`0.7/review-spec-conformance.md`](0.7/review-spec-conformance.md) | Baseline spec ↔ implementation conformance at 0.6.1 — the starting state before the 0.7 rework. |
| 2 | [`0.7/review-transport-lifecycle.md`](0.7/review-transport-lifecycle.md) | Design review of transport lifecycle, retry, and error taxonomy. Motivated removing auto-retry and the deferred-reset model. |
| 3 | [`0.7/handshake-continuity-question.md`](0.7/handshake-continuity-question.md) | Review request: how to keep a session alive across a lazy re-handshake. |
| 4 | [`0.7/handshake-continuity-review.md`](0.7/handshake-continuity-review.md) | Outcome of that request: the make-before-break continuity mechanism. |

## 0.8 line — security hardening, auth profiles, conformance

Landed: absolute handshake deadlines, `maxPendingHandshakes`, epoch-exhaustion
guard, normative JWT/Ed25519/ECDSA auth profiles, removal of the
certificate/MFA helpers, input-validation hardening, and a full 44-item
conformance pass.

| # | File | What it is |
|---|------|-----------|
| 1 | [`0.8/auth-api-review-question.md`](0.8/auth-api-review-question.md) | Review request: is the auth-helper surface the right shape? |
| 2 | [`0.8/review-auth-helpers-fable-2026-07-14.md`](0.8/review-auth-helpers-fable-2026-07-14.md) | Fable's verdict: delete `createCertificateServerAuth` + `createMultifactorServerAuth` (unsafe composition), make the three surviving profiles normative with an enforced `v` field. |
| 3 | [`0.8/review-findings-2026-07-14.md`](0.8/review-findings-2026-07-14.md) | Security round 1 — 7 findings (candidate/AEAD split, sync-callback deadline, NaN limits, puppeteer in prod deps, reply-send candidate, middleware-without-`next`). |
| 4 | [`0.8/review-protocol-portability-fable-2026-07-14.md`](0.8/review-protocol-portability-fable-2026-07-14.md) | Fable's protocol-portability audit — can a clean-room port interoperate from the spec alone. |
| 5 | [`0.8/review-porter-audit-sol-2026-07-14.md`](0.8/review-porter-audit-sol-2026-07-14.md) | gpt-5.6-sol porter audit, round 1 — spec gaps a re-implementer would hit. |
| 6 | [`0.8/review-porter-audit-sol-round2-2026-07-15.md`](0.8/review-porter-audit-sol-round2-2026-07-15.md) | Porter audit round 2 — re-check after the round-1 fixes. |
| 7 | [`0.8/review-round2-neutral-for-fable-2026-07-15.md`](0.8/review-round2-neutral-for-fable-2026-07-15.md) | Neutral correctness & conformance pass — the 10 findings that define the 0.8.0 security set. |
| 8 | [`0.8/review-spec-conformance-0.8.0.md`](0.8/review-spec-conformance-0.8.0.md) | Spec ↔ implementation conformance at 0.8.0. |
| 9 | [`0.8/review-release-verdict-0.8.0.md`](0.8/review-release-verdict-0.8.0.md) | **Final release verdict.** Re-verifies every finding in shipped code, runs the full gate, the 44-item conformance checklist, and lists residual risks. Start here for the current state. |

## How to read

- Want the current state and what's left before merge/publish → start at the
  **0.8 release verdict** (last row).
- Want why a specific 0.8 change exists → find its finding in round-1
  (`review-findings`) or round-2 (`review-round2-neutral`).
- Want the 0.7 behavioural model (retry/reset/continuity) →
  `review-transport-lifecycle` + `handshake-continuity-review`.
