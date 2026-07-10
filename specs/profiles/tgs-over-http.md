# Profile: TGS over HTTP (stub)

**Status**: stub — scope + vector plan. Normative drafting: Phase 4 (alongside `../tgs.md`).
**Sources**: P10 (transport reduces to delivery + signed receipts, L6), P14 §8.3, RFC 9421.

## Scope

The concrete binding of the TGS lifecycle to HTTP: endpoint shapes, artifact carriage, and HTTP message signatures (RFC 9421) as the transport-level authentication layer. This profile adds **no semantics** — every guarantee comes from the BCF artifacts; RFC 9421 only authenticates delivery so that receipts can be issued mechanically.

Normative contents when drafted:

1. **Endpoint and method mapping** — one HTTP exchange per lifecycle transition; request/response media types for CBOR-encoded artifacts.
2. **RFC 9421 usage** — covered components, required signature parameters, key binding to the same party identities as the BCF signers (one identity, two uses, no confusion).
3. **Receipt issuance** — the signed receipt (per `bcf-chain-and-log.md` §6.1) carried in the HTTP response; what a sender may conclude from status code alone (nothing) vs from a receipt (delivery).
4. **Error and retry semantics** — idempotency keys derived from artifact hashes; safe-retry rules; receipts under retry (at-most-one effective delivery).
5. **Removal table** — notably the row for RFC 9421 itself: what attack exists if transport signing is dropped and only BCF-level signatures remain (the answer prices the layer honestly).

## Out of scope

Other transports (MPP-native, message-queue, store-and-forward email-grade — future profiles); TLS configuration guidance beyond a baseline requirement.

## Test-vector plan

| Vector class | What it pins down |
|---|---|
| Signed exchange | Full HTTP request/response pairs (golden bytes) for each lifecycle transition |
| Signature negative | Missing covered component; signature key ≠ artifact signer where the profile requires equality; stripped signature with valid body |
| Retry | Same artifact delivered twice → one receipt chain, no duplicate effect |
