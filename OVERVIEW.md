# greengage — Overview

*Co-signed agreements you can verify offline.*

greengage is the **agreement layer**: a small format for co-signed, hash-chained claims. Two or more identified parties sign a statement. The result is a self-contained artifact that links to the claim before it and can be verified offline.

Parties can add stronger evidence when they need it: signed receipts, published chain-heads, and a witnessed commit log. These measures do not prevent bad behavior. They let a verifier prove it and identify who was responsible.

greengage works with the stack you already have. Your transparency log checks consistency. Your registry controls the authoritative copy. Your rail settles the payment. greengage keeps the portable record of *what the parties agreed*. See `INTEGRATIONS.md` for seven examples.

The canonical `specs/` define the protocol. `IMPLEMENTATION_PLAN.md` explains how we are building it. This document explains why.

## The honest premise

Trust cannot be removed from anything real. Pure trustlessness applies only to assets native to a blockchain. Bring in a stablecoin dollar, a fiat wire, a megawatt, or a cargo of ore and you trust an issuer, custodian, sensor, or oracle again.

Our goal is to make that trust **accountable**. We gather evidence around each claim so anyone can prove what the parties agreed, what happened, and who is responsible. "Trust me" becomes "trust, and here is the proof."

## Three problems, not one

The industry collapses three distinct problems into a single expensive answer, "put it on a chain":

- **Agreement.** *What did these parties commit to?* A signature settles it. Bilateral, offline, no network.
- **Consistency over time.** *Is a party telling everyone the same story, and not quietly rewriting its past?* A witnessed log settles it, without consensus.
- **Uniqueness and control.** *Who holds the one authoritative copy, and can it be transferred exactly once?* A control registry settles it, and has for decades.

greengage separates these problems because consistency and control already have proven answers:

- **Consistency** is what Certificate Transparency solved. RFC 6962 Merkle logs and consistency proofs have run at internet scale since 2013. Independent witnesses now support systems such as Sigstore, Sigsum, and the transparency.dev network. greengage applies this machinery to bilateral claims instead of certificates.
- **Control** is what eVaults and electronic-note registries solved. For two decades, these systems have held court-accepted records that can be transferred exactly once. UCC Article 12 extends this lineage through "controllable electronic records." greengage does not compete with the vault. It makes the record inside the vault independently verifiable.
- **Agreement** still lacks a standard. Existing attestation formats let one party assert, attest, or vouch for something. greengage gives identified parties a small, portable format for co-signing an evolving claim with a tamper-evident history.

Transparency logs handle consistency. Control registries handle uniqueness. Existing rails handle settlement. greengage handles agreement. A blockchain is one possible checkpoint, used when a deployment needs it.

> **the accountability of a public ledger, without the ledger.**

## Placement is the policy: the ladder

The place where evidence lives determines the guarantees it receives. Add only the safeguards that the trust gap requires:

| Placement | Data availability | Finality inherited | Cost |
|---|---|---|---|
| Bilateral only | the two parties hold it | "both signed": instant, private | ~free |
| Published chain-head | any verifier given the root | withholding becomes visible | one signature |
| **Witnessed commit log** | a witness set attests retrievability + non-equivocation | fork-consistency, no consensus | a witness round-trip |
| Anchored into a checkpoint (a block, a BFT finalization, a notary) | the anchoring layer | that layer's hard finality | a checkpoint slot |

This separates consensus, data availability, and execution. Each claim can use the level it needs instead of buying all three from one system.

### A note on "data availability"

Here, **data availability** means that the data behind a claim is published and retrievable. A verifier can download it to verify or challenge the claim. This is the modular meaning used by systems such as Celestia and EIP-4844. It is not CAP-theorem availability, which concerns whether a live system answers requests.

Each greengage claim can choose its data-availability assumption. The parties can hold the data themselves, ask witnesses to attest to it, or anchor it publicly. Most data needs no more than its parties and witnesses.

## The bet: the checkpoint inverts

Open BFT networks are built for anonymous membership. They pay for Sybil resistance, economic security, and global ordering on every transaction. That price makes sense when the parties do not know one another.

Most institutional transfers are different. They happen between identified, licensed, and accountable parties. These parties often need proof and attribution more than global prevention. They should not pay the BFT premium on every transaction.

Large data systems already work this way. They append local writes, serve nearby reads, and checkpoint when they need a shared order. greengage applies the same pattern to agreements between parties. The commit log records history. Witnesses check consistency. A blockchain, BFT finalization, or notary can provide an occasional global checkpoint.

Our bet is that checkpoints will become lighter and less frequent for identified parties. Most agreements will happen bilaterally and use consensus only when they need open-membership Sybil resistance or hard finality across domains.

The common case gets immediate **soft finality** when both parties sign. A witnessed log exposes equivocation and withholding. A deployment can borrow **hard finality** from a checkpoint for a cross-domain settlement or dispute.

## What checkpoints still do

A chain, finality gadget, or notary can provide three things greengage does not:

- **Open-membership Sybil resistance** when the parties do not know one another.
- **A neutral global order** for contested or anonymous settings.
- **Hard finality** for cross-domain settlement and disputes.

greengage uses a checkpoint when a claim needs one.

## Where we are

**Done:** bilateral claims, hash chains, receipts, published chain-heads, and the witnessed commit log. These parts are specified, implemented, conformance-tested, and adversarially reviewed.

**Next:** atomic cross-rail settlement, followed by the transaction lifecycle, a signed HTTP binding, and the first end-to-end demo. The adoption track will add integration profiles and runnable examples.

See `IMPLEMENTATION_PLAN.md` for both tracks, `INTEGRATIONS.md` for host-stack notes, `specs/` for canonical definitions, and `PROVENANCE.md` for the review record.

## Lineage

greengage is the clean-slate "S1" implementation of designs developed and stress-tested in the **Damson** research corpus, in the sibling `damson` repository. Damson explored distributed-ledger semantics through algebraic effects and event sourcing. It produced the bilateral commitment format, the detect-mode ladder, and the clearing-by-construction model that greengage now formalizes.

The S1 research corpus in `damson/docs/research/s1/` is the design authority. Start with `ARCHITECTURE_PROPOSAL.md`, `COMMITMENT_LAYER.md`, and `COORDINATION_LAYER.md`. `NOTES_FROM_RESEARCH.md` carries open items into this build.

greengage turns that research into a spec suite, conformance vectors, and a reference implementation. It uses standard constructions: COSE (RFC 9052), deterministic CBOR (RFC 8949), RFC 6962 Merkle proofs, and RFC 9421 signed HTTP.

---

*This overview is narrative, not normative. The canonical artifacts are the specifications and their removal tables under `specs/`, the honest source this document only summarizes; review provenance is in `PROVENANCE.md`.*
