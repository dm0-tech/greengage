# Notes from Research

The cross-cut guidance the UC-A vertical leaves behind at every layer it touches. Extracted from the S1 corpus (P13 §9, P14 §7.5/§11.3, UC-A §8, P05/P06/P07/P10 follow-up sections); `damson:` = `../damson/`, with `s1:` = `damson:docs/research/s1/`.

**How to use this file.** When a build phase reaches a note's *bites* phase, the phase either resolves it (recording the decision in `IMPLEMENTATION_PLAN.md` §2/§3) or explicitly re-defers it with a new decide-by. Notes marked **counsel** or **deferred** are not engineering work; they are tracked so they don't silently disappear. The deliberately-open decisions O1–O7 in the plan are the subset of these notes already promoted to decision status.

## N1 — BCF core (static envelope)

| # | Bites | Note | Source |
|---|---|---|---|
| N1.1 | ✓ Epic 1 | **Resolved** — `iat` in the per-signature CWT-claims protected header (RFC 9597), no claim-level timestamp; spec §5, enforced at V7 | s1:COMMITMENT_LAYER.md §9.1.3 |
| N1.2 | ✓ Epic 1 | **Resolved** — `src:`/`unison:`/`oci:` schemes, source-content documented as the stronger primitive; spec §9, enforced at V3 | s1:COMPUTATION_GUARANTEES.md §9.1.1 |
| N1.3 | ✓ Epic 1 | **Resolved** — multi-entry `predicate` is a co-attested set (signed by all parties, no separate signer); spec §9 | s1:COMPUTATION_GUARANTEES.md §9.1.2 |
| N1.4 | ✓ Epic 1 | **Resolved** — `tee:` rejected as a `predicate` scheme (V3); TEE evidence rides as Attest-payload content | s1:COMPUTATION_GUARANTEES.md §9.1.4, §9.4.3 |
| N1.5 | Phase 4–5 | UETR is originator-generated and unsigned in the ISO 20022 `GrpHdr`; BCF must generate its own correlation ID and map UETR→BCF-ID, not trust UETR as anchor | s1:COORDINATION_LAYER.md §9.2.6 |
| N1.6 | deferred | SD-JWT-VC profile (`vct: bcf:bilateral-attestation/v1`, JWS general-JSON multi-signature; two-issuer accommodation) and the post-MVP W3C VC v2 + BBS unlinkable profile | s1:COMMITMENT_LAYER.md §9.1.4–5; ties to O2 |
| N1.7 | deferred | Trust-list governance is per-ecosystem (UC-A: travel-rule VASP CA + EUDIW; UC-B: SWIFT BIC hierarchy; UC-C: self-issued + QSeal); belongs to an identity-touchpoints packet, not the BCF spec | s1:COMMITMENT_LAYER.md §9.1.6 |

## N2 — Chain, receipts, log

| # | Bites | Note | Source |
|---|---|---|---|
| N2.1 | ✓ Epic 2 | **Resolved** — receipt = single-signer COSE_Sign1, bound by content (`artifact_hash`), never `prev` (§6.1); not a BCF artifact | s1:COORDINATION_LAYER.md §9.1.1 |
| N2.2 | ✓ Epic 2 | **Resolved** — gap = a held member's `prev` resolving to nothing; retransmission-request flow, no new artifact type; `find_gaps` implemented (§6.1) | s1:COORDINATION_LAYER.md §9.1.2 |
| N2.3 | ✓ Epic 2 | **Resolved** — poison message is evidence against whoever signed a successor onto malformed bytes (§6.1); resolved by content, not deletion | s1:COORDINATION_LAYER.md §9.1.4 |
| N2.4 | ✓ Epic 2 | **Resolved** — O3 chain-head = RFC 6962 Merkle root (§6.2); folded variant deferred | s1:COMMITMENT_LAYER.md §9.2.1, P13 §9.4 |
| N2.5 | Deferred | Multilateral (N>2) BCF semantics: canonical predecessor relationship, fork detection, ordering; MLS-as-group-envelope vs N bilateral channels. §6.3 (Epic 3) is a single-publisher-plus-witnesses log (bilateral-rooted) and did not address N>2 — re-deferred to a dedicated multilateral epic | s1:COMMITMENT_LAYER.md §9.2.2, s1:COORDINATION_LAYER.md §9.3.13 |
| N2.6 | ✓ Epic 2 | **Resolved** — receipts idempotent by `(artifact_hash, recipient.pub)`; duplicate delivery is redundant, not a fork (§6.1) | s1:COORDINATION_LAYER.md §9.1.3 |
| N2.7 | ✓ Epic 3 | **Resolved** — the inter-publication interval *is* the equivocation window heads leave open; cadence is a deployment parameter (§6.2); the witnessed-log client (rung 3, Epic 3) closes it to the witnessing interval | s1:COORDINATION_AUTHORITY.md §7.5(2) |

## N3 — Session atomicity

| # | Bites | Note | Source |
|---|---|---|---|
| N3.1 | Phase 3 | Build on MuSig2/FROST-grade signing; the single-hop PTLC/adaptor exchange + signed-2PC evidence is "buildable today" — do not invent new cryptography | s1:COORDINATION_AUTHORITY.md §11.2 |
| N3.2 | Phase 3 | Gateway abort/timeout semantics as a BCF session leg: who holds escrow in-flight at each stopping point; must be answered jointly with N4.2 | s1:COORDINATION_AUTHORITY.md §7.5(8) |
| N3.3 | Phase 3 | Equivocation *recovery* (who is made whole — legal/economic/technical) is unsolved everywhere; detect-mode gives evidence, not restitution; pair with counsel items N8 | s1:COORDINATION_AUTHORITY.md §7.5(3) |
| N3.4 | deferred | N-way (3+) atomicity is enumerated and deferred; do not let UC-B requirements creep into the Phase 3 primitive | s1:COORDINATION_AUTHORITY.md §9 |

## N4 — TGS and gateways

| # | Bites | Note | Source |
|---|---|---|---|
| N4.1 | Phase 4 | RFC 9421 vs detached JWS for signed webhooks: FAPI 2.0 moves to 9421 (our pick, L6); Open Banking is JWS-entrenched — the HTTP profile should note the JWS bridge for those counterparties | s1:COORDINATION_LAYER.md §9.2.9 |
| N4.2 | Phase 4 | The contestation-window analog: when a counterparty disappears mid-session, the latest mutually-agreed BCF surfaces to the rail via the Terms timeout + rail-side reconciliation window — make this a TGS normative section, not folklore | s1:COMMITMENT_LAYER.md §9.2.3 |
| N4.3 | Phase 5 | Direct-escrow reference contract: canonical 2-of-2 release pattern `release(termsBCF, attestBCF)` for the EVM rail binding | s1:COMMITMENT_LAYER.md §9.3.5 |
| N4.4 | deferred | Standards-track profiles: TGS-over-MPP (IETF draft alongside draft-ryan-httpauth-payment), TGS-over-x402 (`signed-offers-bilateral` extension), TGS-over-AP2 mandate schemas, TGS-over-ISO 20022+CDM. Each is an ecosystem engagement, not a build dependency | s1:COMMITMENT_LAYER.md §9.3.1–4 |
| N4.5 | Phase 5 | ISO 20022 carriage: does `SplmtryData` survive CBPR+/HVPS+ intermediaries or get stripped (forcing the alongside+UETR-link fallback)? Needs Swift network testing; also XAdES-vs-COSE precedence when a counterparty signs the BAH | s1:COORDINATION_LAYER.md §9.2.5, §9.2.7 |

## N5 — Computation guarantees

| # | Bites | Note | Source |
|---|---|---|---|
| N5.1 | Phase 4 | TEE weighting (O1): external validation pass favours TEE-default; P06 favours replicated-default + reserved-TEE. Decide per threat model; if TEEs are admitted, prefer offline-verifiable roots (Nitro/SEV-SNP over TDX) and decide whether two vendor-independent witnesses are required | P13 §9.2, s1:COMPUTATION_GUARANTEES.md §9.4.1–2 |
| N5.2 | Phase 5–6 | Determinism for replay: replayed predicates require event timestamps + integer arithmetic throughout — no wall-clock, floats, or hidden external calls in anything a counterparty re-executes | s1:COORDINATION_LAYER.md §9.4.17 |
| N5.3 | deferred | Runtime-witness substrate menu (CometBFT/Algorand/Stellar; permissioned topologies; who plays notary) is a per-pilot deployment decision, not a reference-impl decision | s1:COMPUTATION_GUARANTEES.md §9.2 |
| N5.4 | deferred | Formal-verification stack (TLA+/Lean 4/Dafny) is priced at 3–6 PM for a non-trivial algorithm; relevant to UC-B netting, not UC-A; AI-assisted proofs are accelerators, not sign-off | s1:COMPUTATION_GUARANTEES.md §9.3 |
| N5.5 | deferred | Trust-list governance for content-addressed predicate registries (Unison Share is single-operator; regulated UCs may require multi-operator) | s1:COMPUTATION_GUARANTEES.md §9.1.5 |

## N6 — Confidentiality

| # | Bites | Note | Source |
|---|---|---|---|
| N6.1 | Phase 5 | Where does the public observer actually exist in UC-A? If the stablecoin leg settles on a permissioned chain the whole obscuring case collapses into selective disclosure. Make the demo state its assumption explicitly | s1:CONFIDENTIAL_SETTLEMENT.md §10.2.6 |
| N6.2 | Phase 5 | Amount-hiding vs graph-anonymity are different products with different regulatory exposure; UC-A's public leg needs at most amount-hiding-at-boundary | s1:CONFIDENTIAL_SETTLEMENT.md §4.1 |
| N6.3 | deferred | Anonymity-set fragility: a low-frequency institutional corridor may make graph-obscuring self-defeating regardless of regulation | s1:CONFIDENTIAL_SETTLEMENT.md §10.3.12 |
| N6.4 | deferred | Post-quantum horizon: obscuring leans on discrete-log/pairing assumptions; harvest-now-decrypt-later favours selective disclosure (nothing sensitive public) for long-lived records — a standing argument for L7 | s1:CONFIDENTIAL_SETTLEMENT.md §10.3.14 |
| N6.5 | deferred | PSI verifiable-completeness: supervisors will ask for evidence sanctions screening ran against the *full* list (commit-to-full-set + verifiable logs) | s1:CONFIDENTIAL_SETTLEMENT.md §10.3.15 |

## N7 — The registrar branch (future packet, not this build)

The distributed-registrar + hierarchical-access branch awaits its own research packet. Its twelve questions, carried so they don't evaporate: (1) who threshold-co-signs registry heads; (2) checkpoint cadence vs finality (= N2.7); (3) equivocation recovery (= N3.3); (4) witness-set procurement/quorum/incentives, and whether supervisors double as witnesses (= O4); (5) when cryptographic enforcement beats perimeter ReBAC; (6) the ZIP-32-style hierarchical viewing-key tree — flagged as the **highest-value novel component to prototype**; (7) threshold-decryption escalation compatible with sovereignty; (8) gateway abort/timeout escrow (= N3.2); (9) the registry-side turnstile invariant bounding shielded-pool proof-failure damage; (10) association-set vs view-key attestation at withdrawal; (11) registrar availability semantics; (12) whether the shared log needs a verifiable *map*, given Trillian's is dead. — s1:COORDINATION_AUTHORITY.md §7.5, §11.2.

## N8 — Counsel-required (out of technologist scope)

| # | Note | Source |
|---|---|---|
| N8.1 | AMLR Art. 79 view-key boundary — the #1 open regulatory item: does amount-hiding + auditor/supervisor view key fall outside "anonymity-enhancing"? Assume EU CASPs over-comply until guidance lands | s1:CONFIDENTIAL_SETTLEMENT.md §10.1.1–2 |
| N8.2 | MiCA Art. 75 custody test: does a delegated-signing key model make a node a "custodian" with strict liability; can threshold/MPC shared-control avoid it | s1:CONFIDENTIAL_SETTLEMENT.md §10.1.3 |
| N8.3 | eIDAS QES status of BCF-as-COSE_Sign vs ETSI-profiled containers (CAdES/JAdES) | s1:COMMITMENT_LAYER.md §9.1.1 |
| N8.4 | Equivocation-as-event-of-default clause language; witness liability for cosigning a forked log; staleness-bound remedies; cross-jurisdiction admissibility of equivocation proofs | s1:COORDINATION_AUTHORITY.md §11.3 |
| N8.5 | Patent review (the deferred P02): counsel item, open. Detail lives in the research corpus, not here | P13 §9.7, s1:COMMITMENT_LAYER.md §9.4.1 |
| N8.6 | Per-jurisdiction legal-finality wrapper; GENIUS Act: confidential reserves unrecognised, monthly attestation baseline, ZK PoR supplement only | P13 §9.7, s1:CONFIDENTIAL_SETTLEMENT.md §10.1.4 |

## N9 — Standards and ecosystem engagement (strategy, not build)

Implied engagements across packets: IETF (CBOR/COSE, OAuth/SD-JWT-VC, httpauth/draft-ryan, RATS), W3C VC WG, x402 Foundation, AP2/FIDO, ISO 20022 RMG, ISDA CDM, Confidential Computing Consortium, SLSA/Sigstore. Decide actively-pursue vs monitor in a release-strategy pass once Phase 4 exists — the conformance suite is the natural artifact to bring. — s1:COMMITMENT_LAYER.md §9.4.2, s1:COMPUTATION_GUARANTEES.md §9.5.2.

## N10 — UC-A failure modes (become Phase 6 demo scripts)

Each row from UC-A §8 becomes a scripted demo run showing the evidence each party walks away with:

| Failure | Mitigation to demonstrate |
|---|---|
| Counterparty stalls mid-session | Terms timeout; rail-lock auto-refund; no Attest → no Settle |
| Stale position presented at settle | Chain-head anchor + reconcile-before-finality |
| "I never received it" | Absence of signed receipt is the attributable signal; retry on alternate transport |
| Misdirected SPEI leg | Irreversible by rail design; pre-dispatch validation (CLABE, sanctions) is mandatory and demonstrated |
| FX-rate dispute | Terms BCF binds the co-signed rate; non-repudiable |
| Predicate divergence | Both parties replay the content-addressed predicate on the agreed input log; divergence is attributable |

— s1:UC_A_CORRIDOR.md §8.

## NI — Implementation deferrals (not from the research corpus; opened in Epic 1 impl)

| # | Bites | Note |
|---|---|---|
| NI.1 | Phase 2+ | **`damson-crypto` consolidation.** `bcf-core` depends on `ed25519-dalek` + `k256` directly behind its `sig` module (plan decision I1). If/when a shared dm0 signing layer is wanted, add Ed25519 to `damson-crypto` upstream and route `sig` through it — never vendor. Revisit when a second greengage crate needs signing. |
| NI.2 | ✓ Epic 2 | **Done** — `bcf-chain` crate extracted (PR #7); `verify_chain` moved out of `bcf-core`, which now exposes `cbor`/`sig`/`party_entry` and owns the shared `Error` (plan decision I5). |
| NI.3 | latent | **`encode_into` depth self-defence.** The canonical encoder is safe today only because every value it sees came from the depth-capped decoder; the invariant is documented on `encode()`. If the encoder ever gains an external caller building values by hand, add an independent depth guard (R-C verification finding). |
