# greengage — Overview

*The agreement layer, and the longer thesis behind it.*

greengage is the **agreement layer**: a small, vectored format for co-signed, hash-chained, offline-verifiable bilateral claims. Two or more identified counterparties sign a statement, producing a self-contained artifact that chains to what came before. On top of that primitive sits a detect-mode ladder (receipts, published chain-heads, and a witnessed commit log) that makes misbehavior provable and attributable rather than prevented by a global network.

It is deliberately substrate-agnostic. Bring your own consistency machinery, your own control registry, your own settlement rail: greengage supplies the one piece those systems all assume and none of them standardize, the portable record of *what the parties actually agreed*. (`INTEGRATIONS.md` shows the artifact living inside seven different host stacks.)

`IMPLEMENTATION_PLAN.md` covers *how* we build it; the canonical `specs/` define *what* it is. This document is the *why*, and the longer bet it implies.

## The honest premise

Trust cannot be removed from anything real. Pure trustlessness exists only for an asset native to a blockchain. The moment a dollar of stablecoin, a fiat wire, a megawatt, or a cargo of ore enters, you are trusting an issuer, a custodian, a sensor, or an oracle again. So the goal is not to eliminate trust but to make it **accountable**: to gather evidence around every claim and make it strong enough that, when something goes wrong, anyone can prove what was agreed, what happened, and who is responsible. We do not replace "trust me". We turn it into "trust, and here is the proof".

## Three problems, not one

The industry collapses three distinct problems into a single expensive answer, "put it on a chain":

- **Agreement.** *What did these parties commit to?* A signature settles it. Bilateral, offline, no network.
- **Consistency over time.** *Is a party telling everyone the same story, and not quietly rewriting its past?* A witnessed log settles it, without consensus.
- **Uniqueness and control.** *Who holds the one authoritative copy, and can it be transferred exactly once?* A control registry settles it, and has for decades.

Separating them is the whole design, and it matters because the second and third problems already have mature, battle-tested answers:

- **Consistency** is what certificate transparency solved. RFC 6962 Merkle logs and consistency proofs have run at internet scale for over a decade (Certificate Transparency since 2013), and a younger ecosystem of independent log witnesses is growing around them (Sigstore, Sigsum, the transparency.dev witness network). greengage's witnessed log is that machinery, profiled for bilateral commitments rather than certificates.
- **Control** is what the eVault and transferable-records lineage solved. eVault systems and electronic-note registries have carried court-accepted, transfer-exactly-once records for two decades (UETA §16 and ESIGN transferable records; a lineage with its share of litigation, which is itself evidence the records stand up in court); UCC Article 12's "controllable electronic records" generalizes exactly this. greengage does not compete with the vault; it makes the record *inside* the vault independently verifiable.
- **Agreement** is the missing standard. Existing attestation formats can carry multiple signatures, but their semantics are single-asserter: a CA asserts, a builder attests, a platform vouches. There is no small, portable, offline-verifiable standard for *two identified counterparties co-signing an evolving commitment*, where the history itself is tamper-evident. That gap is greengage.

This is the company the project intends to keep: transparency logs for consistency, control registries for uniqueness, existing rails for settlement, greengage for agreement. A blockchain is one possible checkpoint among several, not the frame. Heavy cryptography is reserved for the one instant value crosses between rails. The result is the property people actually wanted from a public ledger, minus the ledger:

> **the accountability of a public ledger, without the ledger.**

## Placement is the policy: the ladder

Every commitment makes a choice about *where its evidence lives*, and that placement is exactly what determines the guarantees it inherits. You climb only as far as the trust gap requires:

| Placement | Data availability | Finality inherited | Cost |
|---|---|---|---|
| Bilateral only | the two parties hold it | "both signed": instant, private | ~free |
| Published chain-head | any verifier given the root | withholding becomes visible | one signature |
| **Witnessed commit log** | a witness set attests retrievability + non-equivocation | fork-consistency, no consensus | a witness round-trip |
| Anchored into a checkpoint (a block, a BFT finalization, a notary) | the anchoring layer | that layer's hard finality | a checkpoint slot |

This is the modular decomposition the infrastructure world already names (consensus, data availability, execution), chosen per commitment instead of bundling all three into one substrate.

### A note on "data availability"

We mean **data availability** in its precise, modular sense: the guarantee that the data behind a commitment is published and retrievable, so anyone can download it to verify or challenge it. It is the property at stake in Celestia, danksharding, EIP-4844 blobs, and the validium-versus-rollup distinction. This is *not* the CAP-theorem sense of "availability" (a live system answering requests; liveness and uptime). greengage's move on this axis is to let each commitment **choose its DA assumption**, held bilaterally, attested by a witness set, or anchored publicly, instead of forcing every byte through one global availability layer. Most data never needs more than its witnesses.

## The bet: the checkpoint inverts

Here is the longer thesis.

Today, consensus is the substrate: everything is a transaction on a chain, and anything off-chain is the exception that must justify itself. We believe that is backwards for a semi-trusted world, and that the arrangement will invert.

**Permissionless BFT is expensive, and the cost is intrinsic.** Open, anonymous membership demands Sybil resistance, economic security, and global replication. That is the right price when you genuinely do not know the parties. But it has had a side effect: block space became a scarce, auctioned commodity, and *ordering itself* became a priced, adversarial market of gas auctions and MEV. Even granting that fee markets and MEV are the unavoidable cost of permissionless ordering, they disqualify the block as a clean, cheap, predictable distributed-computing primitive. The thing meant to be a coordination primitive became a congested toll road with an auctioneer at the gate.

**Most value transfer is not anonymous.** It happens between identified, licensed, accountable institutions, a *semi-trusted* setting. For them, "provable and attributable after the fact" deters misbehavior about as well as "prevented up front", at a fraction of the cost. The BFT premium is insurance against Sybil and anonymity; in a semi-trusted setting you are paying for insurance you do not need on every transaction.

**The database world already inverted.** Large-scale data systems do not run global consensus on every write. They append to a write-ahead log, serve reads from local and regional replicas, **checkpoint** periodically, and reconcile across regions at a coarse cadence; consensus is reserved for the narrow set of operations that genuinely need one global order. greengage is that architecture for multi-party value. The commit log is the write-ahead log, checkpoints are the snapshots and anchors, the witnessed log is cross-party reconciliation, and a blockchain (or a BFT finalization, or a regional notary) is the occasional global anchor.

So the prediction: **the checkpoints get lighter and rarer, and greengage-like technology becomes the workhorse.** Not because consensus gets weaker, but because we stop abusing it as a transaction bus. As trust graduates from anonymous adversaries to accountable institutions, the cadence lengthens. Checkpointing settles into a regional and global rhythm of *reconciliation* rather than of every transaction, and the overwhelming majority of value transfer happens bilaterally, accountably, off-consensus, anchoring to a checkpoint only when open-membership Sybil resistance or cross-domain hard finality is actually warranted.

This reframes "finality" itself. The common case gets instant **soft finality** (both parties signed) plus accountable detection: the witnessed log catches equivocation and withholding after the fact. **Hard finality** is borrowed from a checkpoint only when it is needed, for a cross-domain settlement or a dispute. Finality becomes a service you call, not a tax on every action.

## What consensus still does (honestly)

This is an inversion, not an abolition. A checkpoint, whether a chain, a finality gadget, or a notary, still provides three things greengage deliberately does not: **open-membership Sybil resistance** when you truly do not know the parties; a **neutral global order** for genuinely contended or anonymous settings; and a **hard-finality backstop** for cross-domain disputes. greengage does not replace these. It stops using them for everything else, and anchors to them when they are warranted, which in a semi-trusted world is rarely and coarsely.

## Where we are

The detect-mode ladder is specified, implemented, conformance-tested, and adversarially reviewed: bilateral commitments and the hash chain (the foundation), then escalation rungs 1 through 3 — receipts, published chain-heads, and the witnessed commit log. The reserved prevent-mode hop, atomic cross-rail settlement (rung 4), is the next frontier, followed by the transaction lifecycle, a signed-HTTP binding, and the first end-to-end vertical demonstration. In parallel, an adoption track carries the artifact into the host ecosystems above: integration profiles first, runnable examples next. See `IMPLEMENTATION_PLAN.md` for both tracks, `INTEGRATIONS.md` for the host-stack notes, `specs/` for the canonical definitions, and `PROVENANCE.md` for exactly what has and has not been independently reviewed.

## Lineage

greengage is the clean-slate "S1" implementation of designs developed and stress-tested in the **Damson** research corpus (the sibling `damson` repository). Damson explored distributed-ledger semantics through algebraic effects and event sourcing, and produced the bilateral commitment format, the detect-mode escalation ladder, and the clearing-by-construction model that greengage now formalizes. The S1 research corpus (`damson/docs/research/s1/`, notably `ARCHITECTURE_PROPOSAL.md`, `COMMITMENT_LAYER.md`, and `COORDINATION_LAYER.md`) is the design authority; `NOTES_FROM_RESEARCH.md` here carries its open items into the build.

greengage's contribution over the research is to freeze that design into a spec suite with conformance vectors and a reference implementation, replacing bespoke wire formats with standard constructions used as black boxes: COSE_Sign and COSE_Sign1 (RFC 9052) over deterministic CBOR (RFC 8949) for the commitment and checkpoint envelopes, RFC 6962 Merkle transparency-log proofs for the commit log, and RFC 9421 signed HTTP for the transport binding.

---

*This overview is narrative, not normative. The canonical artifacts are the specifications and their removal tables under `specs/`, the honest source this document only summarizes; review provenance is in `PROVENANCE.md`.*
