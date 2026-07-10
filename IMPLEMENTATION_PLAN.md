# Implementation Plan

**Status**: Founding document. Locked decisions here are binding; changing one requires editing this file with a rationale.
**Lineage**: This project is the clean-slate implementation of the S1 research programme conducted in the `damson` repo. The research corpus is the design authority; this plan only consolidates it. Corpus pointers use `damson:` as shorthand for `../damson/`.

| Corpus document | Role here |
|---|---|
| `damson:docs/research/CLEAN_SLATE_S1_PROGRAMME.md` | Programme index |
| `damson:docs/research/s1/ARCHITECTURE_PROPOSAL.md` (P13) | Architecture synthesis — primary source |
| `damson:docs/research/s1/COORDINATION_AUTHORITY.md` (P14) | Authority model, sequencer ladder, gateway requirements |
| `damson:docs/research/s1/UC_A_CORRIDOR.md` (P11) | The vertical this plan builds |
| `damson:docs/research/s1/COMMITMENT_LAYER.md` (P05) | Commitment-layer decisions |
| `damson:docs/research/s1/COMPUTATION_GUARANTEES.md` (P06) | Predicate/computation decisions |
| `damson:docs/research/s1/CONFIDENTIAL_SETTLEMENT.md` (P07) | Confidentiality decisions |
| `damson:docs/research/s1/COORDINATION_LAYER.md` (P10) | Transport/receipt decisions |
| `damson:docs/research/s1/REGULATORY_MATRIX.md` (P03) | Regulatory checkpoints for UC-A |
| `damson:docs/BILATERAL_COMMITMENT_FORMAT.md` | BCF concept spec (input to `specs/bcf-core`) |
| `damson:docs/proposals/TRANSACTION_GATEWAY_SPECIFICATION.md` | TGS concept spec (input to `specs/tgs`) |

---

## 0. Decision 0 — repo, name, language

**Resolved as follows; the name remains overridable until anything is published.**

- **Location**: new clean repo under the dm0 organization, sibling of `damson`. The damson repo stays untouched as the research/prototyping substrate (one pointer line added to the programme doc).
- **Language**: **Rust confirmed** for the reference implementation. Reuses `damson-cryptography` (signing backends) and `damson-ethereum` (EVM rail) as dependencies, not forks. The spec suite, not the Rust code, is the canonical artifact.
- **Name: `greengage` — confirmed** (2026-06-10, resolving O7): a finer dessert plum of the same genus as the damson — clean lineage signal, "the polished one", unclaimed in the payments space. Runners-up for the record: `tally` (the medieval split tally stick — stock and foil with matching grain; crowded name), `chirograph` (the split deed cut through CHIROGRAPHUM; precise but obscure), `indent` (from indenture; collides with the programming word).
- **Remote**: the development repository is the provenance archive; the public repository is a scrubbed snapshot of it (procedure in `docs/publication.md`). PR and issue numbers cited in this document refer to the archive.

---

## 1. Locked strategy (from the kickoff session)

1. **Substrate — hybrid.** A language-neutral **spec suite + test vectors** is the canonical artifact. One mainstream **Rust reference implementation**. Unison/damson remains the research substrate.
2. **Deliverable — layered.** Spec suite → reference implementation → one runnable end-to-end demo (UC-A corridor). Each layer independently presentable.
3. **Audience — deliberately mixed.** Partners, expert adversarial reviewers, backers. The layering is what serves all three (see §6).
4. **First vertical — UC-A** (USD→MXN PSP corridor, P11), leaving research notes at every layer it cross-cuts (`NOTES_FROM_RESEARCH.md`) to guide later horizontal expansion.

## 2. Locked technical decisions

Each row cites the corpus document that closed it. These are not re-litigated during the build.

| # | Decision | Rationale (one line) | Source |
|---|---|---|---|
| L1 | BCF production profile = **COSE_Sign** (RFC 9052) multi-signature envelope | Mainstream, multi-signer native, hardware/HSM tooling exists | P13 §4, §9 |
| L2 | Claim encoding = **deterministic CBOR** (RFC 8949 §4.2.1); the claim hash is over this encoding | Closes the P13 §9 open item: one canonical byte-stream, no JSON canonicalization swamp | P13 §9 (locked here) |
| L3 | Evolving state = **hash-chained BCFs**, not state channels | Perun-class machinery rejected for S1: no contestation game needed between identified, regulated counterparties | P05 §recommendation |
| L4 | Authority model = **bilateral-first, no shared global network**; multilateral uniqueness via **issuer-as-registrar**; escalation only up the **light-sequencer ladder** (signed receipts → chain-head publication → witnessed log → session atomicity) | Network necessity decision rule: pay for prevent-mode only where detect-mode evidence is insufficient | P14 §8 |
| L5 | Atomic cross-rail hop = **single-hop adaptor signatures** + **signed-2PC evidence** | Prevent-mode for the one hop that needs it; everything else detect-mode | P14 §8.2, P13 §6 |
| L6 | Transport = **transport-agnostic envelope**; TGS-over-HTTP binds via **RFC 9421 HTTP message signatures**; every delivery answered by a **signed receipt** | BCF is self-ordering and self-authenticating, so transport reduces to delivery + receipts | P10 §recommendation, P14 §8.3 |
| L7 | Confidentiality default = **selective disclosure** (perimeter + routing), not global-state obscuring; obscuring toolkit (Firn-class) reserved for genuine bearer assets | The two-axis analysis: canonical-state authority and confidentiality mechanism decouple | P07 §conclusion |
| L8 | Computation guarantees = **content-addressed predicates** + replicated-execution evidence; TEE attestation optional (weight open, O1) | Five-class menu priced; cheapest classes carry UC-A | P06 §recommendation |
| L9 | Signatures = **Ed25519** primary protocol identity; **secp256k1** where rail-adjacent (EVM) | Reuse `damson-crypto`; both curves already in the dm0 stack | P13 §5 |
| L10 | Asset stance = **records-not-bearer** by default; bearer only where the asset is genuinely bearer, and then accompanied by chained BCF evidence | Regulatory matrix favors records; bearer+evidence covers the rest | P03, P14 §9 |
| L11 | Gateway behavior = the **four normative TGS gateway requirements** | The gateway is the trust seam of the corridor; requirements are normative, not advisory | P14 §8.3 |
| L12 | License = **Apache-2.0** | Matches `damson-cryptography`; standard for spec + reference-impl strategy | — |
| L13 | Positioning = **agreement layer among mature lineages** (CT logs = consistency, eVault/registries = control, rails = settlement), fully substrate-agnostic; never marketed as a blockchain adjunct | Adversarial review, 2026-07: the contribution survives best in the company of proven components, and substrate agnosticism is what lets it be judged on its merits inside anyone's stack | §4a |

### Implementation decisions (recorded at gate C, Epic 1 impl leg)

Locked during the `bcf-core` build; ratified in PR #4.

| # | Decision | Rationale |
|---|---|---|
| I1 | Signing via `ed25519-dalek` + `k256` **directly**, behind an internal `sig` module — not `damson-crypto` | `damson-crypto` is secp256k1-only and service-oriented; coupling the reviewer-artifact crate to a signing service is the wrong dependency. Consolidation deferred (NOTES). Refines L9's "reuse `damson-crypto`" |
| I2 | Deterministic CBOR is **hand-rolled** (no `ciborium`/`coset`) | The spec's re-encode-and-compare canonicality (L2) needs byte control no permissive serde codec gives; keeps the crate self-contained and the verifier readable |
| I3 | Chain verification (C1–C4) lives in a `chain` module **inside `bcf-core`** for now | The plan's separate `bcf-chain` crate splits out in Phase 2 with the log; premature to fix the boundary before the log exists (NOTES) |
| I4 | ES256K test-vector oracle = pure-Python `ecdsa` (RFC 6979), **independent of `k256`** | Vectors must cross-check the impl, not self-certify; closes the spec §12 freeze-blocker |

Epic 2 impl leg (PR #7) added:

| # | Decision | Rationale |
|---|---|---|
| I5 | `verify_chain` + the log live in a new **`bcf-chain`** crate; `bcf-core` exposes a reuse surface (`cbor`, `sig`, `party_entry`) and owns the shared `Error` | Executes I3's deferred split now that the log exists (NI.2); one flat error taxonomy across the vector namespace |
| I6 | Receipts/heads = **COSE_Sign1** (single-signer); `bcf-chain` is **verify-only** like `bcf-core` | A receipt/head has one signer (not a ≥2-party BCF artifact); signing stays with the parties' own keys |

## 3. Deliberately-open decisions

Tracked here with a decide-by phase. Detail and triggers live in `NOTES_FROM_RESEARCH.md`.

| # | Open decision | Decide by | Notes |
|---|---|---|---|
| O1 | TEE attestation weighting in the computation-guarantee menu | Phase 4 | Needed only when a gateway wants hardware-rooted predicate evidence |
| O2 | Selective-disclosure credential format: **BBS signatures vs SD-JWT-VC** | Phase 5 | Bites when KYC attestations travel the corridor; SD-JWT-VC currently ahead on standardization (P13 §9) |
| O3 | ~~Chain-head publication form~~ **Resolved**: RFC 6962 **Merkle root** | — | Epic 2 (§6.2). Folded/recursive proof documented as a future optimization, not built |
| O4 | ~~Witnessed-log witness-set composition and governance~~ **Resolved (client scope)**: the verify-only client enforces the caller-supplied `witness_set` + `threshold` and the distinct / in-set / non-publisher counting rule (§6.3.5, W4); witness provisioning, rotation, and revocation (P14 §7.5) remain a deployment concern | — | Epic 3 (§6.3) |
| O5 | `predicate_id` registry / naming scheme | Phase 4 | Prefixing rules exist in TGS spec; the registry mechanism is open (P06) |
| O6 | Mock-SPEI fidelity (message shapes vs full CEP/CoDi semantics) | Phase 5 | Demo-grade first; fidelity raised only if a partner needs it |
| O7 | ~~Final project name~~ **Resolved**: `greengage` | — | See §0 (2026-06-10) |

## 4. Build phases

Consolidates P13 §12 and P14 §11.2 into one sequence. Each phase ends with: spec section(s) frozen, test vectors committed, reference implementation passing them, removal table updated. **Spec-first discipline: no crate code lands before its spec stub has scope + vector plan.**

### Phase 1 — BCF envelope, verifier, chain — **COMPLETE** (Epic 1; spec PR #2, impl PR #4)
- Draft `specs/bcf-core.md` to normative quality: claim structure, deterministic-CBOR encoding (L2), domain separator, COSE_Sign profile (L1), envelope/payload separation, removal table.
- Draft chain semantics in `specs/bcf-chain-and-log.md` §chain: predecessor binding, heterogeneous-proof composition (KYC attestation riding a payment chain).
- `bcf-core` crate: types, encoding, signing (via `damson-crypto`), verifier. Verifier kept small enough to read in one sitting — it is the reviewer demo.
- **Exit**: cross-checked test vectors (encode/verify round-trips, negative vectors for every removal-table row).

### Phase 2 — Receipts, chain-head publication, witnessed-log client (ladder rungs 1–3) — **COMPLETE** (rungs 1–2: Epic 2, spec PR #6 / impl PR #7; rung 3 witnessed log: Epic 3, spec PR #9 / impl PR #11)
- `specs/bcf-chain-and-log.md` §log: signed receipt format, chain-head publication (resolve O3), witnessed-log client protocol, gap-detection.
- `bcf-chain` crate: chain construction/validation, receipt issuance/verification, chain-head publisher, witnessed-log client.
- **Exit**: two-party exchange with receipts; equivocation by one party is detectable from the other's evidence alone.

### Phase 3 — Session atomicity
- `specs/session-atomicity.md`: single-hop adaptor-signature exchange (L5), signed-2PC evidence trail, abort/timeout semantics, what is and is not guaranteed (no contestation game — L3).
- `session-atomicity` crate: adaptor signatures over secp256k1 (k256 reuse), 2PC coordinator/participant roles emitting BCF evidence at every transition. (O4 client scope resolved in Epic 3; witness deployment governance remains out of the verify-only client.)
- **Exit**: a two-rail hop that either completes atomically or leaves both parties with signed evidence of exactly where it stopped.

### Phase 4 — TGS lifecycle over signed HTTP
- Draft `specs/tgs.md` (lifecycle: Terms → Commit → Attest → Settle as rail events, binding chain, `offer_id` derivation, predicate model — resolve O5, O1) and `specs/profiles/tgs-over-http.md` (RFC 9421 binding — L6).
- Encode the four normative gateway requirements (L11) as spec MUSTs and as executable conformance checks.
- `tgs` + `tgs-http` crates: lifecycle state machine, gateway and client roles.
- **Exit**: conformance suite a third-party gateway implementation could run.

### Phase 5 — UC-A rail bindings
- `rail-evm` crate: stablecoin leg via `damson-ethereum` (lock/escrow/release mapped to TGS Commit/Settle).
- `rail-mock-spei` crate: MX leg simulator (O6). Resolve O2 for the KYC attestations that travel the corridor.
- **Exit**: each rail binding passes the Phase 4 conformance suite independently.

### Phase 6 — UC-A corridor demo
- `corridor-demo`: two PSP nodes, USD→MXN end-to-end per P11 — terms, KYC-attestation chaining, commit, attest, settle, with every artifact inspectable and independently verifiable offline.
- Scripted failure-mode runs from UC-A §8 (timeout, refusal-to-attest, equivocation) showing the evidence each party walks away with.
- **Exit**: demo runs from a clean checkout with one command; an offline verifier validates every artifact the run emits.

## 4a. Adoption track (A-phases)

Added 2026-07-05, following adversarial review of the project's positioning. Runs **parallel to the protocol phases** in §4 — neither track blocks the other. Protocol work (Phase 3 onward) continues through the epic gates unchanged; A-phases that produce spec text (A3, A4) go through those same gates.

**Positioning (locked, L13).** greengage is the **agreement layer**: a small, vectored profile for co-signed, hash-chained, offline-verifiable bilateral claims. It is positioned among mature lineages, not as a blockchain adjunct: CT-class transparency logs supply consistency over time (RFC 6962 machinery and its witness ecosystem); eVault/control registries supply uniqueness and legal control (the transferable-records lineage that UCC Article 12 generalizes); settlement stays on whatever rail the parties already use. Complete substrate agnosticism is the differentiator, not a compromise — the artifact must be judgeable on its merits inside anyone's stack.

### Phases

- **A0 — Publish properly.** Public repo seeded from a **scrubbed snapshot** (fresh history; this repo remains the provenance archive). Allowlist, scrub checklist, and procedure in `docs/publication.md`. LICENSE file (Apache-2.0 per L12), provenance statement stating plainly that internal AI red legs are not an independent audit. **Exit**: repo public, scrub checklist signed off.
- **A1 — Reposition the narrative.** OVERVIEW rewritten around the agreement-layer / three-lineage frame (CT = consistency, eVault = control, greengage = agreement); `INTEGRATIONS.md` with the seven integration notes (transparency logs, boring stack, control registries, Canton/Daml exit evidence, RWA token metadata, ISO 20022 companion artifacts, supply-chain counter-signing); site copy follows. **Exit**: an expert adversarial reader and a fund-admin CTO each recognize their own stack in the story.
- **A2 — Runnable examples.** Build two, write the rest as notes, in this order: **(i) the embeddable boring-stack ledger** ("an evidence-grade bilateral ledger in ~500 lines": `bcf-core` + Postgres + RFC 3161/OpenTimestamps anchor cron) — the minimum viable rigor for the most common case, embeddable in an existing platform without architectural change; **(ii) the transparency-log integration** — BCF leaves in a Tessera-based log, or a standalone log whose checkpoints the §6.3 client verifies ("CT machinery extended to two-party commitments"); **(iii)** the control-registry integration note deepened to design-partner quality (vaulted record = BCF, assignments = chained commitments, vault audit trail verifiable without trusting the vault). Daml exit-evidence and the rest stay as notes. **Exit**: both examples run from a clean checkout; the offline verifier validates everything they emit.
- **A3 — Input-attestation profile** (spec, through the normal gates). Attested external observations — rate captures, settlement confirmations, delivery events — as a claim type. The adversarial review's genuinely-missing piece; strengthens every integration above. **Exit**: spec section frozen with vectors, same discipline as §4.
- **A4 — Witness-ecosystem alignment** (spec bridge, through the normal gates). Checkpoint/witness format bridge to Sigsum/transparency.dev so the §6.3 client verifies the existing witness ecosystem's artifacts rather than requiring a parallel one. **Exit**: a public witness co-signature verifies under `bcf-chain` unchanged or via a thin adapter.
- **A5 — External validation.** Invite/seed a second independent implementation against the published vectors (what A0 enables); named-firm audit when there is budget. **Exit**: one artifact verified by code we didn't write.

## 5. Repository and crate map

```
<name>/
├── IMPLEMENTATION_PLAN.md      # this file
├── NOTES_FROM_RESEARCH.md      # cross-cut research backlog
├── specs/                      # CANONICAL artifact (language-neutral)
│   ├── README.md
│   ├── bcf-core.md
│   ├── bcf-chain-and-log.md
│   ├── session-atomicity.md
│   ├── tgs.md
│   ├── profiles/tgs-over-http.md
│   └── test-vectors/           # JSON/CBOR vectors, the conformance ground truth
└── crates/                     # Rust reference implementation
    ├── bcf-core                # Phase 1: envelope, deterministic CBOR, COSE profile, verifier
    ├── bcf-chain               # Phase 2: chains, receipts, chain-head, witnessed-log client
    ├── session-atomicity       # Phase 3: adaptor sigs + signed-2PC evidence
    ├── tgs                     # Phase 4: lifecycle state machine, gateway requirements
    ├── tgs-http                # Phase 4: RFC 9421 binding
    ├── rail-evm                # Phase 5: EVM stablecoin leg (uses damson-eth)
    ├── rail-mock-spei          # Phase 5: MX leg simulator
    └── corridor-demo           # Phase 6: two PSP nodes, UC-A end-to-end
```

**Reused, not forked**: `damson-crypto` (secp256k1 signing/keys; extend upstream with Ed25519 if absent rather than vendoring), `damson-eth` (EVM RPC + ERC-20). Protocol-type duplication across crates is treated as a defect (same ratchet rule as the rest of the dm0 stack).

## 6. Demo definitions per audience

| Audience | What they are shown | Layer exercised |
|---|---|---|
| **Expert adversarial reviewers** | The spec suite with removal tables; the negative test vectors (each one names the attack it encodes); the verifier read end-to-end in one sitting | specs + `bcf-core` |
| **Partners (PSPs, rails)** | The Phase 4 conformance suite run against their own gateway stub; the corridor demo with their rail substituted at Phase 5 boundaries | `tgs*`, `rail-*` |
| **Backers** | The UC-A narrative: a USD→MXN payment where compliance attestations travel with the money and every step leaves independently verifiable evidence — including a scripted failure run showing what each party can prove when the counterparty walks away | `corridor-demo` |

## 7. Working agreements

- **Specs are canon.** A behavior disagreement between spec and Rust is a spec bug or an implementation bug — decided explicitly, never silently.
- **Test vectors are the contract.** Every normative MUST gets at least one positive and one negative vector. Negative vectors name the attack they encode.
- **Removal tables are maintained.** Every spec carries one; a field that cannot name the attack its removal enables is deleted.
- **Research notes discharge or escalate.** When a phase hits an item in `NOTES_FROM_RESEARCH.md`, it is either resolved (and recorded in §2/§3) or explicitly deferred with a new decide-by.
- **Quality gates** follow the dm0 Rust standard: `cargo fmt --check && cargo clippy --all-targets && cargo test --all` clean before any commit.
- **Epic workflow.** Build phases are executed epic-at-a-time through four human gates (brief → spec PR → impl PR → closeout). The workflow is defined in `AGENTS.md`; the gates are the only places open decisions get resolved.
