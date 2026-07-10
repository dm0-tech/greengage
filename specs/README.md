# Specification Suite

This directory is the **canonical artifact** of the project. The Rust crates under `crates/` are a reference implementation of these documents; where they disagree, the disagreement is a bug to be resolved explicitly (see `IMPLEMENTATION_PLAN.md` §7).

## Status

Documents are drafted phase by phase per `IMPLEMENTATION_PLAN.md` §4. A spec is *frozen* for a phase when its MUSTs each have at least one positive and one negative test vector in `test-vectors/`. Current state: `bcf-core.md` and `bcf-chain-and-log.md` are frozen through the witnessed log (Epics 1–3); `session-atomicity.md` and the TGS documents are stubs (scope + vector plan). Per-document status lines are authoritative; review provenance is in the top-level `PROVENANCE.md`.

## Suite layout and dependency order

| Spec | Drafted in | Depends on | One-line scope |
|---|---|---|---|
| [`bcf-core.md`](bcf-core.md) | Phase 1 | — | The bilateral commitment envelope: claim, encoding, signatures, verification |
| [`bcf-chain-and-log.md`](bcf-chain-and-log.md) | Phases 1–2 | bcf-core | Chaining BCFs; signed receipts; chain-head publication; witnessed log |
| [`session-atomicity.md`](session-atomicity.md) | Phase 3 | bcf-core, bcf-chain-and-log | The one prevent-mode primitive: atomic single-hop exchange with evidence |
| [`tgs.md`](tgs.md) | Phase 4 | all of the above | Transaction gateway lifecycle: Terms → Commit → Attest → Settle |
| [`profiles/tgs-over-http.md`](profiles/tgs-over-http.md) | Phase 4 | tgs | Concrete HTTP binding via RFC 9421 message signatures |
| [`test-vectors/`](test-vectors/README.md) | every phase | — | Conformance ground truth for all of the above |

## Conventions (binding on all specs in this suite)

- **RFC 2119/8174 keywords** (MUST/SHOULD/MAY) in their normative sense.
- **Removal table required.** Every spec ends with a removal table: for each protocol element, the concrete attack its removal enables. An element with an empty row gets deleted, not defended.
- **Envelope/payload separation.** Protocol bytes and application bytes never mix; application semantics live in payloads the protocol treats as opaque.
- **Deterministic encoding.** All hashed or signed structures are encoded as deterministic CBOR (RFC 8949 §4.2.1). No alternative encodings.
- **Cite, don't re-derive.** Known constructions (COSE, adaptor signatures, 2PC, transparency logs) are referenced as black boxes with a citation, never re-explained in prose.

## Design authority

These specs consolidate the S1 research programme in the `damson` repo (see `IMPLEMENTATION_PLAN.md` for the corpus map). The concept documents `damson:docs/BILATERAL_COMMITMENT_FORMAT.md` and `damson:docs/proposals/TRANSACTION_GATEWAY_SPECIFICATION.md` are inputs; once `bcf-core.md` and `tgs.md` are frozen, **this suite supersedes them**.
