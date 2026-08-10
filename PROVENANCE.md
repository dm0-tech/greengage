# Provenance and review status

This file explains how we built greengage, how we reviewed it, and what you should not rely on yet.

## Who builds this

greengage is a single-maintainer project (dm0). AI coding agents help draft the specifications, test vectors, and reference implementation. Every specification and implementation change follows the gated workflow in `AGENTS.md`. A human reviews and merges each pull request after an adversarial review.

## What the adversarial reviews are, and are not

Each spec and implementation pull request gets a fresh adversarial review. The reviewer sees the artifacts but not the author's notes or rationale. It argues for deleting each protocol element, constructs concrete attacks, checks the specification against the code, and looks for standard prior art.

The review memos live on pull requests in the private development repository, which is the provenance archive. The public repository is a scrubbed snapshot with fresh history; `docs/publication.md` describes the process. Memos are available on request, and we plan to publish them with the specs.

These reviews have found real defects, but they are **not an independent security audit**. The reviewing agents share a vendor and broad training lineage with the authoring agents. No named external firm has reviewed the protocol, and no independent team has implemented the specifications from scratch.

Use greengage for evaluation, prototypes, and integration experiments. Do not rely on it as the sole evidence layer for production value at risk.

## What would change that status

In order of weight:

1. **A second, independent implementation** that passes the published test vectors. A Python oracle generated the vectors without sharing code with the Rust implementation. However, the same team wrote both. The oracle is an independent *codebase*, not an independent *party*. One gap remains: an existing RFC 6962 implementation has not cross-checked the oracle's hand-written Merkle functions.
2. **An external audit** of the specification suite and the reference verifier by a named firm.
3. **Production exposure** through integrations where greengage artifacts are one evidence layer among several, so a defect is survivable and observable.

## Specification status

A spec section is *frozen* when every normative MUST has at least one positive and one negative conformance vector in `specs/test-vectors/`. Each negative vector names the attack it encodes.

| Document | Status |
|---|---|
| `specs/bcf-core.md` | Frozen (Epic 1): claim structure, deterministic CBOR encoding, COSE_Sign profile, verification procedure |
| `specs/bcf-chain-and-log.md` §1–§5 (chain) | Frozen (Epic 1) |
| `specs/bcf-chain-and-log.md` §6.1–§6.2 (receipts, chain-head) | Frozen (Epic 2) |
| `specs/bcf-chain-and-log.md` §6.3 (witnessed log) | Frozen (Epic 3) |
| `specs/session-atomicity.md` | Stub: scope and vector plan only |
| `specs/tgs.md`, `specs/profiles/tgs-over-http.md` | Stubs: scope and vector plans only |

## Known open items

Frozen does not mean beyond question. We track open items instead of changing frozen text silently. Two items remain from the Epic 3 adversarial review:

- **Witnessed-log vector geometry (§6.3)**: the current conformance vectors exercise a limited set of tree shapes; broader geometry coverage is queued.
- **§6.3.2 wording**: equal-size and empty-old consistency checks require an empty proof; the normative text says this less directly than it should.

Neither changes verifier behavior as vectored; both are wording/coverage improvements queued for the next protocol epic.

## Design authority

The specifications consolidate a private research corpus: the "S1 programme" in the sibling `damson` repository. The published work carries its own justification. Every locked decision in `IMPLEMENTATION_PLAN.md` §2 has a short rationale. Every protocol element has a removal-table row that names the attack its removal would enable.

References beginning with `P` point to the historical research record. They are not additional normative content. The specifications are self-contained.

## Cryptography

greengage invents no cryptography. It uses COSE_Sign and COSE_Sign1 (RFC 9052), deterministic CBOR (RFC 8949 §4.2.1), Ed25519 and ES256K signatures, and RFC 6962 Merkle proofs.

The `bcf-core` deterministic-CBOR encoder is hand-written. This gives the verifier byte-level control and lets it check canonical encoding by decoding and re-encoding. The encoder is small enough to read in one sitting, and an external audit should examine it first.
