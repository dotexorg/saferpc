# Auth Helper Surface — Independent Design Review

Verified against `src/auth/server.ts`, `src/auth/client.ts`, `src/auth/index.ts`, `src/client.ts`, `src/server.ts`, `src/common.ts`, `spec/security.md`, `spec/api.md`, `spec/protocol.md`, `test/unit/auth-server.test.ts`, `test/security/auth-handshake.test.ts`. All claims below are checked against code.

---

## 1. Verdict per helper

### `createCertificateServerAuth` — **DELETE**

**One line:** it is `createECDSAServerAuth` with a different key-lookup callback, wearing a name that promises certificate handling it does not perform.

Supporting argument:

- The claim "byte-for-byte identical signature step" is **confirmed**: `src/auth/server.ts:240-246` (certificate) and `src/auth/server.ts:184-190` (ECDSA) both execute `crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, sig, transcript)`. The only structural difference is where `publicKey` comes from: `getPublicKey(identifier)` vs `verifyCertificate(cert)`.
- Everything security-relevant — chain building, path validation, expiry, revocation, trust anchors — lives in the app callback `verifyCertificate` (`src/auth/server.ts:204-207`). What the helper owns is `decodeAuthPayload` + two `isPlainBytes` checks + one WebCrypto call (`src/auth/server.ts:218-250`). That is plumbing, not security weight.
- The half-helper problem is real and confirmed: there is no client counterpart in `src/auth/client.ts` (only JWT/Ed25519/ECDSA helpers exist), and both the unit tests (`test/unit/auth-server.test.ts:446-450` — `mpEncode({ cert, sig })` + raw `crypto.subtle.sign`) and the integration test (`test/security/auth-handshake.test.ts:301-313`, with the literal comment "No client helper for certs — application supplies its own `sign`") hand-assemble the payload. If your own test suite has to write the client side by hand, every user will too — and a developer who has already written the client `sign` will find writing the ~25-line server `verify` trivial.
- Misuse signal: in a security-focused library, `createCertificateServerAuth` reads as "the library handles certificates." It doesn't. A developer who plugs in a naive `verifyCertificate` (parse cert, extract key, skip chain validation) gets a helper that happily stamps `{ subject, verified: true }` (`src/auth/server.ts:248`). The name absorbs trust the code doesn't earn.
- Replacement cost: a documented recipe in `spec/security.md` §"Certificate-based" showing a full `sign`/`verify` pair (your integration test at `auth-handshake.test.ts:288-315` is already exactly that recipe). Keep `createECDSAServerAuth` as the pointer for the signature step.

### `createMultifactorServerAuth` — **DELETE**

**One line:** a composition helper that structurally cannot enforce the one property that makes composition meaningful — same-principal binding — is a misuse generator, not a convenience.

Supporting argument:

- The gap is as described, confirmed at `src/auth/server.ts:299-305`: default combine is `{ ...primaryAuth, ...secondaryAuth, multifactor: true }`. No principal comparison, none possible — the helper sees opaque `Ctx` objects.
- The default merge is worse than the question states. Two additional defects beyond principal binding:
  1. **Spread order silently inverts trust.** `verifyToken` returns the raw token payload as principal (`src/auth/server.ts:105`). Configure `{ primary: ed25519, secondary: jwt }` and a JWT claim named `deviceId` — issuer-signed but attacker-requested — overwrites the *cryptographically verified* `deviceId` from the Ed25519 factor. The developer chose an ordering; the library turned it into a trust decision.
  2. **`multifactor: true` is spoofable in single-factor configs.** Since JWT auth passes token claims through unmodified (`src/auth/server.ts:105`; `sanitize` at `src/server.ts:587` strips only poison keys), a token containing `multifactor: true` sets the same context flag without the helper being involved. The marker an app would gate on is not trustworthy.
- The remaining value is small: decode, two byte-presence checks, short-circuit ordering (verified fail-closed by `test/unit/auth-server.test.ts:679-703`), and the dangerous merge. The safe version of this — decode two sub-payloads, run two verifiers, assert binding against your schema, build one principal — is ~12 lines of app code and *forces* the developer to confront the binding question the helper hides.
- Half-helper again: client side is hand-assembled in every test (`test/security/auth-handshake.test.ts:489-499`, `test/unit/auth-server.test.ts:563-570` — `mpEncode({ primary, secondary })`).
- Pre-1.0, zero known users, minimal-surface bias, and (per Q4 below) every kept helper becomes a normative wire schema you must specify and port. Both criteria columns point the same way.

---

## 2. If multifactor is kept anyway

**Answer: option (a) only — required `combineAuth`, no default merge — and reject (b).** But the documented-pattern answer dominates both:

- **(b) sequential verification is wrong for this library.** It changes `AuthOptions.verify`'s signature (`src/common.ts:584-587`) — a core, symmetric, spec'd type (`spec/api.md:159-171`, `spec/protocol.md:162,193`) used by both peers and every port — to serve one helper. And it buys nothing for the motivating case: a JWT cannot bind to a `deviceId` unless the issuer signed that binding into the token. Feeding the first principal into the second verifier doesn't create issuer-signed linkage; the link still has to come from the app's database ("does device X belong to subject Y"), which is exactly a `combineAuth`/app-code check. Signature churn, zero security gain.
- **(a) is honest but weak.** Making `combineAuth` required removes the toxic default, but nothing stops `combineAuth: (p, s) => ({ ...p, ...s })` — the misuse rebuilds itself in one line. A required callback whose contract ("MUST assert both factors resolve to one principal") is enforceable only by documentation is a documented pattern with extra steps.
- Therefore: **the documented pattern is the safer answer.** A "Composing two factors" section in `spec/security.md` with a complete `verify` that (1) decodes `{ primary, secondary }`, (2) calls two sub-verifiers with the same transcript, (3) throws unless `jwtPrincipal.sub` owns `edPrincipal.deviceId` per the app's own store, (4) returns one explicit principal. Your existing integration test (`auth-handshake.test.ts:478-520`) is 80% of this text already — it just needs the binding assertion added, which is precisely the line the helper couldn't write.

---

## 3. DX review of the overall auth surface

**The core shape is right — keep it.** `{ secret?, sign?, verify? }` is minimal, symmetric across peers, composes secret+asymmetric by construction, and fails closed: `validateAuthConfig` hard-errors when nothing is configured (`src/common.ts:389-405`, called at `src/client.ts:181` and `src/server.ts:267`). Spreadable helpers (`Pick<AuthOptions, "sign">` / `Pick<AuthOptions, "verify">`) compose naturally with `secret:` in the same object literal — the integration tests read exactly how real code will (`auth-handshake.test.ts:284-296`). The all-zero-secret runtime guard (`spec/protocol.md:237`, tested at `auth-handshake.test.ts:395-412`) and hardened `mpDecode` for payloads (`src/auth/server.ts:25-37`) are the good kind of paranoia. A developer wires the Ed25519 happy path in well under an hour from `spec/security.md:265-283`.

Concrete rough edges:

1. **Dead `v: 1` version field — spec/code divergence.** All three client helpers emit `v: 1` (`src/auth/client.ts:47`, `:86`, `:124`). No server helper reads it — there is no `payload["v"]` anywhere in `src/auth/server.ts`. Both spec tables omit it (`spec/api.md:442-444`, `spec/security.md:316`). It's an unenforced, undocumented wire byte. Either enforce `v === 1` server-side (mandatory if you take Q4's normative answer) or delete it. *This also contradicts the inlined question, whose payload tables (`{ jwt, ts, th }`, `{ deviceId, sig }`, `{ identifier, sig }`) omit the `v` field the code actually sends.*
2. **Three names for one concept.** The optional pre-verification gate is `validateDevice` (`src/auth/server.ts:117`), `validateEntity` (`:160`), `validateSubject` (`:208`). Pick one field name across configs.
3. **Inconsistent principal shapes.** Ed25519 → `{ deviceId, verified: true }` (`server.ts:150`); ECDSA → `{ identifier, verified: true }` (`:196`); certificate → `{ subject, verified: true }` (`:248`); JWT → raw `verifyToken` result, **no** `verified` marker (`:105`). Switching auth modes forces rewriting the `context` factory, and `verified: true` means "helper ran" in three modes and nothing in the fourth. Either standardize a principal envelope or drop `verified` entirely (it carries no information — an unverified session never reaches `context`).
4. **App-callback exceptions escape untyped.** `verifyCertificate` throws propagate raw — your own test asserts `rejects.toThrow(/bad cert chain/)` rather than an `RPCError` (`test/unit/auth-server.test.ts:488-497`). Same for a throwing `verifyToken` / `getPublicKey`. `onError` consumers get `RPCError("UNAUTHORIZED")` for some rejections and arbitrary `Error`s for others describing the same event. Wrap callback failures in `UNAUTHORIZED` (or `INTERNAL` for lookup infrastructure failures, as already done for a bad resolved key at `server.ts:139`).
5. **Mutual-auth asymmetry has zero helper coverage.** The core supports client-side `verify` (`src/client.ts:712-729`) and server-side `sign` (`src/server.ts:632-650`), but every client helper returns only `sign` and every server helper only `verify`. A developer doing mutual Ed25519 auth writes half of it by hand with no doc calling this out. Cheapest fix: one sentence in `spec/security.md` + reuse note (the server can spread `createEd25519ClientAuth`-style signing — but the names actively fight that reuse, see next point).
6. **`Client`/`Server` in helper names encode direction, not role.** `createEd25519ClientAuth` is really "Ed25519 signer" and `createEd25519ServerAuth` "Ed25519 verifier"; a server proving its identity needs the "Client" helper. If you touch naming pre-1.0, `createEd25519Signer` / `createEd25519Verifier` describes what they return and makes mutual auth read correctly.
7. Minor: `createEd25519ClientAuth` holds a raw seed in closure with no zeroization path or doc note (`src/auth/client.ts:58-92`); the JWT skew rejection message "Stale or future-dated auth" (`server.ts:93`) doesn't say which direction, which costs debugging minutes in clock-skew incidents.

Note that deleting the two helpers from §1 also deletes rough edges: cert/multifactor account for the untyped-exception case and the worst principal-shape inconsistency.

---

## 4. Cross-language spec question

**Commit: two-layer answer, and it is already half-implemented in your spec.** The core protocol keeps auth payloads opaque — `spec/protocol.md:146` already says "The signature payload is opaque to the protocol; its length must be in `1..MAX_AUTH_BYTES`." Keep that. Above it, **the payload schema of every helper you ship must be normative**, published as a versioned "standard auth profiles" appendix — not implementation-defined.

Reasoning: the deployments that motivate cross-language reimplementation are heterogeneous by definition — TS browser client against a Rust or Go server. If helper payloads are implementation-defined, `createEd25519ClientAuth` in TS and the Rust port's Ed25519 verifier have no interop guarantee, which makes the helpers useless in exactly the deployments the spec exists for. "Implementation-defined" is only coherent for auth the application writes end-to-end itself — and the spec already covers that case via the opaque-bytes rule.

Consequences you must accept with this answer:

- The `v` field stops being dead weight: profiles are versioned by it, and verifiers MUST reject unknown `v` (fixing rough edge #1).
- Every shipped helper = a wire schema you specify, test with cross-implementation vectors, and maintain forever. This is the strongest independent argument for the §1 deletions: post-deletion you specify three profiles (JWT, Ed25519, ECDSA) instead of five, and the two you'd have dropped are precisely the ones whose schemas (`{ cert, sig }`, `{ primary, secondary }`) delegate their semantics to app callbacks that no spec can pin down.

---

## Accuracy of the inlined question vs code

- ✅ Multifactor default merge, cert/ECDSA signature-step identity, hand-assembled test payloads, JWT const-time digest check (`server.ts:102`), "~30 lines" for the cert helper (actual body: `server.ts:216-250`) — all confirmed.
- ⚠️ **One divergence:** the payload tables omit the `v: 1` field that all three client helpers actually emit (`src/auth/client.ts:47, 86, 124`) and that no server helper validates. See rough edge #1.
- ⚠️ One nuance: "Even our own unit tests build the payload by hand" understates for multifactor — the *sub*-payloads are built with real client helpers (`test/unit/auth-server.test.ts:563-568`); only the `{ primary, secondary }` wrapper is by hand. Doesn't change the verdict; the wrapper is exactly the missing client half.

**Bottom line:** delete both helpers, publish two composition recipes in `spec/security.md` (certificate, two-factor with explicit binding assertion), make the three surviving helper payloads normative versioned profiles with enforced `v`, and unify the config-field/principal-shape naming while 0.x still lets you.
