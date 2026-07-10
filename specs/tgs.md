# Transaction Gateway Specification (stub)

**Status**: stub — scope + vector plan. Normative drafting: Phase 4.
**Sources**: `damson:docs/proposals/TRANSACTION_GATEWAY_SPECIFICATION.md` (concept spec), P14 §8.3 (four normative gateway requirements, L11), P06 (predicate model, L8, O5/O1).

## Scope

Defines the coordination lifecycle by which BCF artifacts gate rail actions: **Terms → Commit → Attest → Settle**, where Commit and Settle are rail events and Terms and Attest are BCFs. Transport-agnostic; concrete bindings live under `profiles/`.

Normative contents when drafted:

1. **Lifecycle state machine** — states, the artifact or rail event that drives each transition, and the evidence each party holds in every state (including all non-honest stopping points).
2. **Terms BCF** — the claim type binding parties, amounts, rails, predicates, and timeout parameters; normative `offer_id` derivation.
3. **Binding chain** — how Terms → Commit → Attest → Settle artifacts chain (per `bcf-chain-and-log.md`) so that no artifact can be replayed into a different session.
4. **Predicate model** — `predicate_id` naming and prefixing; content-addressed predicate resolution (**O5 resolved here**); how precondition attestations (KYC, margin adequacy) chain into the session in both directions through the gateway; evidence classes a gateway may demand (**O1 resolved here**).
5. **The four normative gateway requirements** (P14 §8.3) — stated as MUSTs, each mapped to a conformance check executable against a live gateway.
6. **Relationship to existing protocols** — TGS as a profile over MPP / x402 / AP2 / ISO 20022 / direct escrow: what is reused, what is added, and why the additions are load-bearing (the lock-confidence argument).
7. **Removal table** — per element, the replay, mis-binding, or unilateral-settlement attack its removal enables.

## Out of scope

Wire format of any particular transport (see `profiles/`); rail-specific lock/release mechanics (rail bindings document their mapping to Commit/Settle); multilateral netting.

## Test-vector plan

| Vector class | What it pins down |
|---|---|
| Lifecycle: positive | Full Terms→Settle transcript with all artifacts; variant with chained KYC attestation entering and leaving the gateway |
| Lifecycle: negative | Attest replayed from another session; Commit without matching Terms; Settle without bilateral Attest; predicate mismatch |
| `offer_id` | Derivation golden vectors; collision-attempt vector |
| Gateway conformance | One executable check per normative gateway requirement, runnable against any implementation (Phase 4 exit criterion) |
