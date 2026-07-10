# BCF Core

**Status**: frozen (Epic 1) — test vectors merged and passing against the reference implementation.
**Sources**: `damson:docs/BILATERAL_COMMITMENT_FORMAT.md` (concept spec), P13 §4–§5, locked decisions L1/L2/L9; resolves notes N1.1–N1.4.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described in RFC 2119 / RFC 8174.

## 1. Overview

A **Bilateral Commitment Format (BCF) artifact** is a COSE_Sign envelope in which two or more identified parties independently sign the same **claim**. The artifact is:

- **self-contained** — verification requires only the artifact bytes (plus the application payload, if payload verification is wanted); no key directory, no network;
- **independently verifiable** — any third party can run §8 offline;
- **composable** — claims reference predecessor claims by hash (semantics in `bcf-chain-and-log.md`), and payloads are opaque, so artifacts of different applications chain freely.

This document defines the claim structure, its single canonical encoding, the COSE profile, and the complete verification procedure. It deliberately defines nothing else (§10).

## 2. The Claim

A claim is a CBOR map with integer keys. Unknown keys MUST be rejected (E_STRUCTURE): the claim is the unit of agreement, and an unrecognized field is an unagreed field.

| Key | Name | Type | Presence | Meaning |
|---|---|---|---|---|
| 1 | `domain` | tstr | REQUIRED | Domain separator. MUST be exactly `"BCF/1"` for this version |
| 2 | `claim_type` | tstr | REQUIRED | Application claim type, e.g. `"bcf:terms/1"`. MUST match `[a-z0-9:/.-]+` and be ≤ 64 bytes; **enforced at V3** — aliasing via case or exotic characters must not create "distinct" types |
| 3 | `nonce` | bstr (16) | REQUIRED | Fresh random bytes chosen by the proposing party |
| 4 | `payload_hash` | bstr (32) | REQUIRED | SHA-256 of the opaque application payload (§2.1) |
| 5 | `parties` | array of party | REQUIRED | The required signer set, ≥ 2 entries (§2.2) |
| 6 | `prev` | array of bstr (32) | REQUIRED | Claim hashes of predecessor claims; `[]` for a genesis claim. Semantics: `bcf-chain-and-log.md` |
| 7 | `predicate` | array of tstr | OPTIONAL | Predicate identity set (§9); when present: ≥ 1 entry, each ≤ 256 bytes with scheme `src:`, `unison:`, or `oci:` — **enforced at V3**. New schemes require a new `domain` version or a registry profile (open decision O5) |

### 2.1 Payload separation

The payload is application bytes. The protocol treats it as opaque and binds it **only** through `payload_hash`. Protocol bytes and application bytes never mix: nothing in this specification ever inspects payload content, and no application data appears in the claim outside the payload hash. An artifact verifies with or without the payload present; presenting the payload additionally proves it is *the* payload (§8 step V9).

### 2.2 Party entry

A party entry is a CBOR map with integer keys:

| Key | Name | Type | Presence | Meaning |
|---|---|---|---|---|
| 1 | `id` | tstr | REQUIRED | Identity URI of the party, ≤ 256 bytes |
| 2 | `pub` | bstr | REQUIRED | Public key bytes: raw 32-byte Ed25519 key, or 33-byte SEC1 compressed secp256k1 key |
| 3 | `alg` | int | REQUIRED | COSE algorithm: `-8` (EdDSA) or `-47` (ES256K). MUST be consistent with `pub` length |

Party entries MUST be unique by `pub`, and unknown keys in a party entry MUST be rejected (E_PARTY) — the same unagreed-field rule as the claim map. Carrying the public key inline is what makes the artifact self-contained; binding `id` to `pub` (whether this key legitimately speaks for that identity) is a trust-list concern outside this spec (note N1.7).

`parties` is a **set encoded as an array**: entries MUST be sorted by the deterministic-CBOR encoding of the entry, bytewise ascending, so that semantically equal claims are byte-equal.

## 3. Deterministic encoding

Every structure that is hashed or signed under this spec MUST be encoded as deterministic CBOR per RFC 8949 §4.2.1:

1. Preferred (shortest-form) integer and length encodings.
2. Definite lengths only; indefinite-length items MUST be rejected.
3. Map keys sorted bytewise ascending by their encoded form.
4. No floating-point values; no tags except the outer COSE_Sign tag (§5).
5. Text strings MUST be valid UTF-8.

A decoder MUST verify on decode that the input is the deterministic encoding of its content (re-encode-and-compare, or an equivalent streaming check) and reject otherwise (E_NONCANONICAL). This applies **recursively to every `bstr .cbor` item**: the body protected header and each per-signature protected header are CBOR-in-bytes and MUST themselves be deterministic. There is no alternative encoding and no JSON path.

**This is an application profile of CBOR, not a new format.** Every artifact is *valid, deterministically-encoded* CBOR (RFC 8949 §4.2.1) — including no duplicate map keys (§5.6 validity) — further restricted to the value space of §2 (no floats, the single outer COSE_Sign tag, the fixed claim/envelope shapes). Any conformant CBOR decoder interoperates with the bytes a BCF implementation emits; a conformant *BCF* decoder additionally **rejects** any well-formed CBOR that falls outside this profile (E_NONCANONICAL / E_STRUCTURE). The strictness is on what is *accepted*, never on what is *emitted* — the same profiling discipline COSE (RFC 9052) and the `dCBOR` profile apply.

## 4. Claim hash and artifact identity

```
claim_bytes = deterministic_cbor(claim)
claim_hash  = SHA-256(claim_bytes)
```

`claim_hash` is the **identity of the agreement**. All external references to a BCF artifact — chain `prev` entries, receipts, log entries, rail bindings — MUST use `claim_hash`, never a hash of the envelope (envelope bytes vary with signature order and are not an identity).

## 5. The COSE_Sign envelope

The envelope is a tagged COSE_Sign message (CBOR tag 98, RFC 9052 §4.1):

```
COSE_Sign = [
  body_protected : bstr .cbor { 3: "application/bcf-claim+cbor" },
  body_unprotected : {},          ; MUST be empty
  payload : bstr = claim_bytes,   ; MUST NOT be nil (non-detached)
  signatures : [+ COSE_Signature]
]
```

Each `COSE_Signature`:

```
COSE_Signature = [
  protected : bstr .cbor {
    1: alg,                       ; -8 (EdDSA) or -47 (ES256K)
    4: kid,                       ; bstr: SHA-256 of the party's pub bytes
    15: { 6: iat }                ; CWT claims (RFC 9597); iat: int, POSIX seconds
  },
  unprotected : {},               ; MUST be empty
  signature : bstr
]
```

Rules:

- **One signature per party, exactly.** The set of signatures MUST correspond 1:1 to `claim.parties`, matched by `kid = SHA-256(party.pub)`. A missing party is E_SIG_MISSING; a signature whose `kid` matches no party, or a second signature for the same party, is E_SIG_EXTRA.
- **Algorithm binding.** `protected.alg` MUST equal the matched party's `claim.alg` (E_ALG). The algorithm a verifier runs is taken from the *claim*, which all parties signed — the header copy exists because RFC 9052 requires it, and any disagreement is rejected.
- **Per-signer timestamp** (resolves N1.1): each signer states its own signing time as `iat` inside the CWT-claims header parameter (15, RFC 9597) of its *protected* header. There is no claim-level timestamp: the two parties sign at different moments, and a claim-level time would be one party's assertion about both. `iat` is each signer's own assertion and is not range-checked at V7, but it SHOULD be a plausible non-negative POSIX time; verifiers MAY apply application-level freshness policy *after* V1–V9.
- **ES256K low-s.** ECDSA over secp256k1 is malleable (`s` ↔ `n−s`). ES256K signatures MUST use the low-s form; verifiers MUST reject high-s signatures (E_SIG_INVALID at V8). Note this buys *less* than envelope-byte uniqueness — signing order and `iat` already make envelope bytes non-unique, which is why identity is `claim_hash` (§4), never envelope bytes.
- **Empty unprotected headers.** Both unprotected maps MUST be empty. The property this buys is exact: **no unsigned bytes anywhere in the envelope** — nothing a relay can inject or alter without breaking a signature. (It does not buy envelope-byte uniqueness; see the low-s note above.)
- **Signing input** is the RFC 9052 `Sig_structure` with context `"Signature"`, the body protected header, the per-signature protected header, `external_aad = ''`, and `payload = claim_bytes`. `external_aad` MUST be empty: all context belongs inside the claim, where both parties sign it.

Domain separation is carried in the claim (`domain`, key 1) rather than in a COSE header: it must be inside the bytes every party signs and inside the bytes `claim_hash` covers, and the claim is the only structure that satisfies both.

## 6. Creation procedure

1. Proposer constructs the claim: fresh `nonce`, payload hashed into `payload_hash`, all parties listed, `prev` per the chain spec.
2. Proposer encodes `claim_bytes` (§3) and transmits claim + payload to the other parties over any transport.
3. Each party independently validates the claim against its own intent (application concern), then signs the Sig_structure (§5) and returns its `COSE_Signature`.
4. Any party (or any relay) assembles the envelope. Assembly requires no trust: every component is signed or hash-bound.

A half-signed envelope (fewer signatures than parties) is **not a BCF artifact** and confers nothing; it is at most evidence that the signing party made an offer. Fair-exchange of signatures is out of scope (§10) — the party who signs first accepts that the counterparty may walk away holding its signature.

## 7. Verification interface

```
verify_bcf(envelope_bytes, expected_domain, payload?) -> claim | error
```

`expected_domain` MUST be supplied by the caller (`"BCF/1"`); accepting whatever domain the artifact declares would defeat the separator. `payload` is optional (§2.1).

## 8. Verification procedure

Checks MUST run in this order, stopping at the first failure. The order is part of the spec: each step may rely on everything before it, and implementations agree on which error a given bad input produces (vectors pin this).

| # | Check | Failure |
|---|---|---|
| V1 | `envelope_bytes` decodes as deterministic CBOR (§3), tag 98, shape per §5 — including every `bstr .cbor` protected header, checked recursively | E_DECODE / E_NONCANONICAL |
| V2 | Body protected header is exactly `{3: "application/bcf-claim+cbor"}`; both unprotected maps empty; payload non-nil | E_ENVELOPE |
| V3 | `payload` decodes as deterministic CBOR map with exactly the keys of §2 (types, lengths, presence), `claim_type` matching its charset/length rule, and `predicate` (if present) satisfying its §2 syntax rules | E_STRUCTURE / E_NONCANONICAL |
| V4 | `claim.domain == expected_domain` | E_DOMAIN |
| V5 | Party entries well-formed (exactly the keys of §2.2, no unknown keys), unique by `pub`, sorted per §2.2, `alg` consistent with `pub` length, count ≥ 2 | E_PARTY |
| V6 | Signatures correspond 1:1 to parties via `kid = SHA-256(pub)` | E_SIG_MISSING / E_SIG_EXTRA |
| V7 | Each signature's protected header: `alg` equals party's claim `alg`; `kid` present; CWT-claims `iat` present and an int; no other header parameters; unprotected empty | E_ALG / E_HEADER |
| V8 | Each signature cryptographically verifies over the Sig_structure (§5) under the party's `pub`; ES256K signatures additionally low-s (§5) | E_SIG_INVALID |
| V9 | If `payload` argument supplied: `SHA-256(payload) == claim.payload_hash` | E_PAYLOAD_HASH |

On success, return the decoded claim and `claim_hash`. Beyond the **syntactic** rules of §2 (which V3 enforces in full), a verifier MUST NOT impose *semantics* on `claim_type`, `prev`, or `predicate` — what a type means, what a predecessor implies, and whether a predicate is acceptable belong to the chain spec, TGS, and the application. The syntax/semantics line matters: every MUST stated in §2 is checked by V1–V9; nothing normative in this document is left for "the application" to enforce.

The reference implementation of V1–V9 is the project's reviewer artifact: it MUST remain readable top-to-bottom in one sitting, with each check labeled by its V-number.

## 9. Predicate identity

The optional `predicate` field binds the agreement to specific computation(s) — "we agree these are the bytes that decide" (used by TGS for gating predicates; resolves N1.2–N1.4).

- Each entry is a URI. This spec defines three schemes, and V3 rejects all others: `src:<multihash>` (hash of source content), `unison:<hash>` (Unison term hash — source-level, content-addressed), `oci:<repo>@sha256:<digest>` (built artifact digest).
- **Source-content identity is the stronger primitive** (N1.2): a source hash identifies the algorithm; a build digest identifies one packaging of it, vulnerable to build-pipeline substitution. This is the source-vs-artifact provenance distinction from supply-chain security (SLSA, in-toto), applied to gating predicates. Where both exist, the source-level entry SHOULD be listed first, and the build digest treated as a derived claim.
- A multi-entry `predicate` is a **predicate_id_set** (N1.3): by signing the claim, every party co-attests that the entries identify the same computation. The equivalence claim needs no separate signer — it is inside the bilaterally signed bytes, and a party that signs a false equivalence has signed its own liability.
- `tee:<measurement>` is **not** a valid scheme and is rejected at V3 (N1.4): a TEE measurement attests *where code ran*, not *what the algorithm is*. TEE evidence enters as EAT/CoRIM-typed content inside an Attest payload (TGS spec), as runtime witness over an underlying `src:`/`unison:`/`oci:` predicate.
- Registry/resolution of predicate URIs is deliberately not specified here (open decision O5, Phase 4).

## 10. What BCF is not

No transport (any byte channel works; receipts live in `bcf-chain-and-log.md`). No ordering across artifacts (`prev` carries the data; semantics in the chain spec). No application semantics (payloads opaque). No escrow or settlement (TGS + rail bindings). No fair exchange of signatures (§6). No identity PKI (inline keys; `id`↔key trust is a profile concern). No revocation.

## 11. Removal table

Every element above, priced by the concrete attack its removal enables:

| Element | Attack if removed |
|---|---|
| `domain` (claim key 1) + caller-supplied `expected_domain` | Version confusion *within* BCF: a future BCF/2 claim (same content type) verifies under BCF/1 rules. Cross-*protocol* replay is already blocked by the signed content-type header (next-to-last row) — `domain` is not priced against that |
| `claim_type` | Type confusion: an Attest-shaped claim is presented where Terms is expected; the verifier cannot tell agreement-about-what |
| `claim_type` charset rule enforced at V3 | Type aliasing: case or homoglyph variants (`bcf:Step/1` vs `bcf:step/1`) masquerade as distinct types, evading every layer that compares types — including chain equivocation detection |
| `predicate` syntax rules enforced at V3 (scheme whitelist, non-empty) | Scheme smuggling: a `tee:` measurement rides as algorithm identity, laundering *where code ran* into *what the algorithm is*; an empty set asserts the equivalence of nothing while looking predicate-bound |
| `nonce` | Claim-hash collision across sessions: two independent agreements with identical terms share a `claim_hash`, so chain `prev` references and receipts cross-contaminate between sessions |
| `payload_hash` | Payload substitution: parties "agree" while each holds a different document; the artifact proves agreement about nothing |
| `parties` in the claim (not just envelope signatures) | Signer-set substitution: a relay re-wraps the claim with a different signature set; nothing signed states *who must sign* |
| ≥ 2 parties / 1:1 signature matching | A unilateral statement masquerades as a bilateral commitment; or one party signs twice to simulate a counterparty |
| Inline `pub` per party | Verification requires a live key directory: artifacts stop being self-contained and offline-verifiable, and the directory becomes the attack surface |
| `parties` sort rule (§2.2) | Hash splitting of equal claims: the same agreement encodes to different `claim_hash`es depending on party order, forking dedup, receipts, and equivocation comparison. (Canonical CBOR cannot catch this — it never reorders arrays — so V5 is the sole guard) |
| `kid = SHA-256(pub)` binding | Honest pricing: this is a matching device, not a security control — V8 already makes misattribution impossible (a signature verifies only under its producing key). Without `kid`: O(N·M) trial verification, and E_SIG_EXTRA vs E_SIG_INVALID become indistinguishable, so error behavior stops being deterministic and vectors cannot pin it |
| `alg` in claim + header-equality check (V7) | Algorithm confusion: an attacker relabels a signature's algorithm so verification runs under a weaker or wrong scheme |
| Deterministic encoding + re-encode check (V1/V3) | Encoding malleability: semantically identical claims with different bytes yield different `claim_hash`es — dedup, receipts, and chain references silently fork |
| `prev` (key 6, even when `[]`) | A claim's chain position becomes unsigned context: the same artifact replays at a different position in a session (genesis vs successor ambiguity) |
| Per-signer `iat` (protected) | No attributable signing time: a party can later claim it signed before/after some event with nothing in evidence either way; timestamps become forgeable by relays if unprotected |
| ES256K low-s rule (V8) | Signature malleability: anyone holding a valid envelope mints a second, byte-distinct valid signature for the same claim — noise for any layer that fingerprints signature bytes |
| Empty unprotected headers | Unsigned bytes in the envelope: relays gain a writable, signature-free field to inject or alter content in transit. (Not priced as envelope-byte *uniqueness* — signing order and `iat` already vary envelope bytes, which is why identity is `claim_hash`, §4) |
| Non-detached payload (claim inside envelope) | "Verification" against an absent claim: verifiers must fetch claim bytes out-of-band, and a wrong fetch verifies a different agreement |
| Empty `external_aad` (enforced) | Hidden context: two implementations disagree on AAD and produce mutually unverifiable artifacts; context smuggled outside the claim escapes `claim_hash` and is invisible to third-party verifiers |
| Outer tag 98 + content-type header | Format confusion with COSE_Sign1/other COSE messages; a single-signer message parses as multi-party at a sloppy decoder |

## 12. Test vectors

`specs/test-vectors/bcf-core/` — generated by an independent Python oracle (`cbor2` + PyCA `cryptography` for Ed25519; the pure-Python `ecdsa` package for ES256K, RFC 6979 deterministic; `specs/test-vectors/tools/`), not by the reference implementation; see `specs/test-vectors/README.md` for format rules. Coverage: one positive vector per supported configuration (2-party Ed25519, 3-party, predicate-bearing, payload-supplied, 2-party ES256K, mixed-curve) and one negative vector per removal-table row above, each naming its attack. ES256K is fully covered — positive 2-party and mixed-curve, high-s rejection (low-s rule, §5), and alg/pub-length consistency — generated by an oracle independent of the reference implementation's `k256`, and cross-checked against it. The Epic-1 freeze blocker is **closed**: every rule in this spec, both curves, is conformanced.

## 13. References

RFC 8949 (CBOR; §4.2.1 deterministic encoding) · RFC 9052 (COSE) · RFC 9597 (CWT claims in COSE headers) · RFC 2119/8174 · P13 `s1:ARCHITECTURE_PROPOSAL.md` §4–§5 · P05 `s1:COMMITMENT_LAYER.md` · concept spec `damson:docs/BILATERAL_COMMITMENT_FORMAT.md`.
