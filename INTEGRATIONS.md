# Integrations

greengage is the agreement layer: a small format for co-signed, hash-chained, offline-verifiable claims between identified parties (`specs/bcf-core.md`), with a detect-mode ladder above it (`specs/bcf-chain-and-log.md`). It standardizes none of the things its hosts already do well — consistency, control, settlement, ordering — so the same artifact can live inside very different stacks.

These notes show how. Each answers three questions: what the host system provides, what a greengage artifact adds, and what the integration concretely is. The status line says what exists today; nothing below claims running code unless it names it. Runnable examples are the adoption track's next phase (`IMPLEMENTATION_PLAN.md` §4a, A2); the two marked *planned example* are being built first.

A common shape recurs throughout: the BCF claim carries an opaque `payload_hash`, so binding a commitment to any external artifact (a database row, an ISO message, an SBOM, a vaulted document) is always the same move — hash the artifact, co-sign the claim, chain the amendments.

---

## 1. The boring stack: Postgres + a timestamp anchor — *planned example (A2, first)*

**Host**: an ordinary application database. Most bilateral records that need evidence quality — accrual ledgers, servicing records, fee calculations shared between two firms — live in one party's Postgres, which means the other party is trusting a screenshot.

**What greengage adds**: each row both parties care about becomes a co-signed claim; claims chain, so the history cannot be quietly rewritten by either side; a nightly chain-head is anchored externally with RFC 3161 timestamps or OpenTimestamps, so neither party can later backdate a rewrite even if they collude with their own DBA.

**The integration**: an evidence-grade bilateral ledger in a few hundred lines — `bcf-core` + `bcf-chain` for the artifacts, two signing keys, a `claims` table, and a cron job that anchors the head. No new infrastructure, no network, no third party in the loop except a timestamp authority that never sees the data.

This is deliberately the first example: it is the minimum viable rigor for the most common case, and it is what an existing platform embeds without changing its architecture.

## 2. Transparency logs: BCF leaves in the CT lineage — *planned example (A2, second)*

**Host**: RFC 6962 Merkle transparency logs and their ecosystem — Certificate Transparency (running at internet scale since 2013), Sigstore's Rekor, Sigsum, and the newer transparency.dev tooling (Tessera) — with an emerging network of independent witnesses co-signing log checkpoints.

**What greengage adds**: today these logs carry single-publisher artifacts (certificates, signed software artifacts, single-asserter attestations). Logging BCF artifacts extends the same machinery to two-party commitments: the log leaf is a co-signed claim, and the log's consistency proofs and witness co-signatures supply exactly the non-equivocation guarantee greengage's witnessed-log client (`specs/bcf-chain-and-log.md` §6.3) is specified to verify.

**The integration**: a Tessera-based log carrying BCF leaves (Tessera is a library for building tiled RFC 6962 logs), or a standalone commit log whose checkpoints the §6.3 client verifies directly, plus a verifier profile mapping the log's checkpoint format onto §6.3's checkpoint verification. (Rekor itself has consolidated on a small fixed entry-type set in v2, so the near-term path is a dedicated log, not a new Rekor type.) Consistency machinery and witness conventions come from an ecosystem that already exists; greengage brings only the claim format. Alignment of checkpoint/witness formats with transparency.dev conventions is tracked as its own phase (A4).

## 3. Control registries: verifiable contents for the eVault lineage — *integration note, design-partner depth planned (A2, third)*

**Host**: eVault and electronic-note registry systems: the authoritative-copy machinery (UETA §16 / ESIGN transferable records) that has carried court-accepted, transfer-exactly-once electronic notes for two decades, and that UCC Article 12's "controllable electronic records" generalizes. Ratings agencies and courts accept these systems — a lineage tested in litigation, which is the point; their known structural weakness is that the *contents* of the vaulted record are platform-attested — the relying party trusts the vault's word about what the record says and how it changed.

**What greengage adds**: the vaulted record becomes a BCF artifact — obligor-co-signed, offline-checkable; amendments, assignments, and discharges become chained commitments, so the record's full history verifies without trusting the vault. The vault keeps doing what only it can do: control, uniqueness, transfer.

**The integration**: record-format adoption inside an existing vault product, not a new registry. Vaulted record = BCF; lifecycle events = chained BCFs; the vault's audit trail becomes independently verifiable evidence rather than an assertion. Control (Art. 12 / UETA §16 sense) stays exactly where it is.

## 4. Canton / Daml: exit evidence — *integration note*

**Host**: Canton's synchronized-ledger network, where Daml contracts give strong on-ledger privacy and integrity between participant nodes.

**What greengage adds**: portability of evidence *out* of the platform. A participant's proof of what happened is currently entangled with the platform: replaying it requires participant nodes, domain history, and the network's cooperation. Emitting a co-signed BCF at contract lifecycle points (create / exercise / archive) gives each party a self-contained exhibit that survives leaving the network — verifiable by a court, an auditor, or a counterparty with no Canton infrastructure at all.

**The integration**: a Daml library that renders lifecycle events as claims, collects both parties' signatures out-of-band or via the contract itself, and hands each party its own artifact. The ledger remains the system of record; the BCF is the system of proof that travels.

## 5. RWA token platforms: obligor-co-signed evidence behind the token — *integration note*

**Host**: tokenized real-world-asset platforms (the ERC-3643 class and its relatives) that mint tokens against off-chain assets — receivables, private credit, invoices.

**What greengage adds**: the evidence behind the token is today platform-asserted; the funder trusts the platform's API about the receivable's existence, terms, and performance — the failure mode that 2022's crypto-credit defaults (Maple/Orthogonal among them) made expensive. With BCF, the underlying obligation is co-signed by the obligor, its servicing history is a chain, and the token's metadata carries the chain-head hash. Mint, amendment, and burn events reference claim hashes; an investor verifies the underlying evidence offline, without trusting the platform.

**The integration**: a token-metadata / claim-registry convention (chain-head hash in metadata, claim hashes in events) plus off-chain artifact distribution. The chain provides what greengage deliberately does not — global double-spend prevention over the *token* — while greengage provides what the chain cannot see: whether the off-chain asset behind the token is real, agreed, and current.

## 6. ISO 20022 rails: non-repudiable confirmations without touching the rail — *integration note*

**Host**: bank payment rails speaking ISO 20022 (`pacs.008`, `camt.05x`), where bilateral disputes today resolve through correspondence and log reconciliation.

**What greengage adds**: a co-signed confirmation bound by hash to the exact rail message. `payload_hash` = hash of the ISO message; both institutions sign; each holds a self-contained artifact proving what both sides understood the payment to be. Amendments and investigations chain to the original.

**The integration**: a profile note, not a rail change. The rail carries what it always carried; the BCF travels alongside (or in an existing free-format field carrying only the artifact hash). Dispute evidence becomes cryptographic instead of archaeological.

## 7. Software supply chain: counter-signed acceptance — *integration note*

**Host**: the in-toto / SLSA / DSSE attestation stack (and C2PA for media provenance), which made single-signer attestation standard: a builder attests to provenance, a scanner attests to a result.

**What greengage adds**: the missing *bilateral* step — acceptance. A vendor asserts an SBOM or build; the customer's acceptance today is an email or a ticket. Co-signing the artifact hash turns delivery-and-acceptance into one offline-verifiable record, and the chain gives the amendment history (re-deliveries, waivers, exception approvals) that procurement and audit actually ask about.

**The integration**: a DSSE-adjacent profile where the BCF claim's payload hash is the in-toto statement or artifact digest; existing attestation machinery is unchanged, and the co-signed acceptance rides beside it.

---

## What greengage never brings

Reading the seven notes together, the boundary is consistent, and it is the design (`OVERVIEW.md`):

- **No consensus, no ordering, no double-spend prevention.** Where global uniqueness is needed, the host provides it (a chain in §5, a vault in §3, a log in §2).
- **No payload semantics.** Every host binds by `payload_hash`; greengage never interprets the ISO message, the SBOM, or the loan file.
- **No custody, no settlement.** Value moves on the rails that already move it.

What it always brings is the same three properties: co-signed agreement, a tamper-evident history, and artifacts that verify offline with no dependency on the host still existing, cooperating, or being trusted.
