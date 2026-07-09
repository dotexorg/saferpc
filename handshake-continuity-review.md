# Session continuity in the saferpc handshake — problem, external review, and where we landed

## The setup

saferpc gives two peers an encrypted RPC channel over any byte transport. The
handshake is deliberately minimal: one round-trip, and it doesn't happen until
the application actually makes its first call. The initiator sends a hello (an
ephemeral public key, a nonce, an epoch counter, and — optionally — a signature),
the responder derives a session key from an X25519 exchange folded together with
a pre-shared secret, proves it knows the secret with an HMAC, and replies. From
that point every message is encrypted.

One detail matters for everything below: the responder does not treat the new
session as *live* the moment the maths checks out. It waits for the first
encrypted frame that actually decrypts under the new key. Producing that frame is
the real proof that the other side holds the key — anyone can send bytes that
*look* like a handshake, but only the genuine peer can send bytes that decrypt.

## The problem

A server that already has a working session should be hard to knock off it. The
question we care about is: **can a stale or duplicated hello — literally the same
bytes the server already handled once — end a live session?** It shouldn't,
because re-sending an old hello proves nothing new about who you are or whether
you can actually talk.

The way the code worked, it could. The server ran each incoming hello as a fresh
attempt, kept the old session serving while the attempt ran (good), but then
retired and replaced the old session *the moment the signature verified and the
key was derived* — before waiting for that first real encrypted frame. And the
signature, in signature mode, only covers fields the initiator chose. It carries
nothing from the server, so a byte-for-byte copy of an old hello verifies again,
every time.

Put those together and you get an ugly outcome: replay an old hello, the server
happily retires the perfectly good session and stands up a new one — except the
new one can never come alive, because whoever replayed the hello doesn't hold the
private key and can't send that confirming frame. The working session is gone;
nothing usable replaces it.

We didn't argue about this in the abstract — we reproduced it. Capture one
legitimate hello, feed it back into an established session, and the very next
call on that session times out. The session was killed by a recording of an old
message.

## The proposed fix

The instinct is "make before break." Don't throw away the old key when a new
hello shows up. Keep both: the old session keeps serving, the new hello only
produces a *candidate* key sitting off to the side. Promote the candidate — and
only then retire the old key — when the first frame arrives that decrypts under
the candidate. That's the same "first real frame confirms it" rule the protocol
already uses for a fresh session, just applied to the replacement of an existing
one.

The point is that decrypting a frame under the candidate key requires actually
holding the private key material, which a replayed hello doesn't. So a duplicate
hello can create a candidate that quietly expires, but it can never take down the
live session.

## What the external review added

I put the question to a second model (framed purely as a protocol-design review,
no attack language, or its safety filter chokes on the vocabulary). It agreed
with the direction and, more usefully, pushed on the assumptions underneath it.

Its sharpest point: make-before-break only holds if the *server's* ephemeral key
is fresh on every attempt. If the server reused a static key, a replayed hello
would derive the *same* key as the live session — and then replayed traffic would
decrypt under the "candidate" and promote it. That turns a mere nuisance into a
full replay of recorded session traffic. So "the server's key is fresh per hello"
isn't an implementation detail; it's the load-bearing assumption the whole
property rests on, and it deserves to be written down as a protocol invariant, not
left to chance in the code.

It also flagged three things worth keeping:

- **A brute-force angle on weak secrets.** The server hands out its HMAC proof to
  any well-formed hello, and that proof is computed from a key that mixes in the
  shared secret. Someone can send their own hello, collect the proof, and grind
  guesses at the secret offline. Against a proper random 32-byte key this is
  hopeless (you'd be brute-forcing 256 bits). Against a secret someone derived
  from a password, it's real. That's a documentation duty: the secret is a key,
  not a passphrase.

- **In-flight frames during a legitimate swap.** When a real re-handshake does
  promote a new key, messages still in flight under the old key die. WireGuard
  keeps the previous key around, decrypt-only, for a short grace period to cover
  exactly this. Cheap to add while we're in here.

- **Flooding hellos to starve a real reconnect.** If an attacker spams hellos,
  they can keep bumping the "latest attempt" and crowd out a legitimate peer's
  reconnect. Denial of service is explicitly outside saferpc's threat model, so we
  won't chase it, but make-before-break raises the stakes a little and it's worth
  naming honestly in the assessment.

The review also offered a clean way to state the underlying rule, which is worth
quoting because it's the whole thing in one sentence:

> A transition that destroys authenticated state must be authenticated at least
> as strongly as the state it destroys. A signature over the sender's own chosen
> fields proves identity, not participation. Creating state can be gated on
> identity; destroying it must be gated on proof that you actually hold the key.

That's the same failure family as forged TCP resets and Wi-Fi deauth frames — an
unauthenticated message tearing down an authenticated connection — and the fix is
always the same shape: make the teardown prove itself.

## Where we actually landed

The good news is that the scariest item — the static-key replay — doesn't apply
to us. The server already generates a fresh ephemeral key inside each hello
handler; a duplicate hello produces a different key exchange and therefore a
different session key, so replayed traffic can't confirm anything. The review
raised a valid general risk; checking it against our actual code showed it was
already closed. But that's exactly why it now goes into the spec as a stated
invariant: one refactor moving that key back to a shared scope would silently
reopen the hole, and nobody would notice until it was a headline.

So the plan is:

1. Move the server to make-before-break: keep the live key serving, promote a
   candidate only when a frame decrypts under it, and keep the old key around
   decrypt-only for a short grace window.
2. Write down "the server's ephemeral key is fresh per attempt" as a protocol
   invariant, so it can't be refactored away by accident.
3. Document that the shared secret must be a real random key, not a password.
4. Note the hello-flood-versus-reconnect trade-off in the assessment as a known,
   accepted residual.
5. Add a continuity regression test: a duplicated hello must leave the live
   session untouched, while a genuine reconnect (a real new key) still succeeds.

The short version: the bug was that the server ended a good session on the
strength of a signature that could be replayed. The fix is to make ending a
session require proof that can't be — the same proof we already demand to start
one.
