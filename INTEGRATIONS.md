# Integrations

These notes show how greengage fits seven host systems. Each section covers what the host provides, what greengage adds, and how to connect them.

Status lines say what exists today. We name runnable code only when it exists. The two sections marked *planned example* come first in the adoption track (`IMPLEMENTATION_PLAN.md` §4a, A2).

Every integration uses the same pattern. Hash the external artifact, put the hash in the BCF claim's `payload_hash`, co-sign the claim, and chain later amendments. The artifact can be a database row, ISO message, SBOM, vaulted document, or any other byte string.

---

## 1. The boring stack: Postgres + a timestamp anchor — *planned example (A2, first)*

**Host:** Postgres or another application database. One party holds the ledger. The other party often has to trust an export or screenshot.

**What greengage adds:** Each important row becomes a co-signed claim. Claims form a hash chain, so neither party can rewrite the history quietly. A nightly RFC 3161 or OpenTimestamps anchor prevents either party from backdating a rewrite, even with help from its database administrator.

**The integration:** Use `bcf-core` and `bcf-chain`, two signing keys, a `claims` table, and a scheduled job that anchors the chain-head. The timestamp authority never sees the data.

This example comes first because an existing platform can embed it without changing its architecture.

## 2. Transparency logs: BCF leaves in the CT lineage — *planned example (A2, second)*

**Host:** RFC 6962 Merkle transparency logs and their ecosystem. Certificate Transparency has run at internet scale since 2013. Sigstore, Sigsum, and transparency.dev also use independent witnesses to co-sign log checkpoints.

**What greengage adds:** These logs usually carry artifacts from one publisher, such as certificates and software attestations. A BCF log leaf is different: it contains a claim signed by both parties. The existing consistency proofs and witness signatures provide the non-equivocation guarantee that the greengage client verifies (`specs/bcf-chain-and-log.md` §6.3).

**The integration:** Put BCF leaves in a Tessera-based RFC 6962 log, or use a standalone log whose checkpoints the §6.3 client can verify. A verifier profile maps the host checkpoint format to the greengage checks. Rekor v2 has a small fixed set of entry types, so the near-term path is a dedicated log rather than a new Rekor type. Phase A4 tracks alignment with transparency.dev checkpoint and witness formats.

## 3. Control registries: verifiable contents for the eVault lineage — *integration note, design-partner depth planned (A2, third)*

**Host:** eVaults and electronic-note registries control the authoritative copy of an electronic record. UETA §16 and ESIGN define transferable records; UCC Article 12 extends the model through "controllable electronic records." Courts and ratings agencies already accept this machinery. A relying party must still trust the vault's account of what the record says and how it changed.

**What greengage adds:** The obligor co-signs the vaulted record as a BCF artifact. Amendments, assignments, and discharges become chained claims. A verifier can check the full history offline without trusting the vault's account of it. The vault still provides control, uniqueness, and transfer.

**The integration:** Add BCF as a record format inside an existing vault. Store the vaulted record as a BCF and its lifecycle events as chained BCFs. The vault's audit trail becomes independently verifiable evidence. Legal control stays with the vault.

## 4. Canton / Daml: exit evidence — *integration note*

**Host:** Canton's synchronized ledger, where Daml contracts provide privacy and integrity between participant nodes.

**What greengage adds:** Portable evidence outside the platform. Replaying a Canton event requires participant nodes, domain history, and help from the network. A co-signed BCF at each contract lifecycle point gives both parties a self-contained record. A court, auditor, or party can verify it without Canton infrastructure.

**The integration:** A Daml library renders lifecycle events as claims and collects both signatures, either through the contract or out of band. Each party receives a copy. Canton remains the system of record; the BCF is the proof that travels.

## 5. RWA token platforms: obligor-co-signed evidence behind the token — *integration note*

**Host:** Real-world-asset platforms, including ERC-3643 systems, mint tokens against receivables, private credit, invoices, and other off-chain assets.

**What greengage adds:** The obligor co-signs the underlying obligation. Its servicing history forms a chain, and the token metadata carries the chain-head hash. Mint, amendment, and burn events refer to claim hashes. An investor can verify the evidence offline instead of relying only on the platform's API.

**The integration:** Define a token-metadata and claim-registry convention, then distribute the artifacts off-chain. Put the chain-head hash in metadata and claim hashes in events. The chain prevents double-spending of the token. greengage records whether the parties agreed that the underlying asset exists and is current.

## 6. ISO 20022 rails: non-repudiable confirmations without touching the rail — *integration note*

**Host:** Bank payment rails that use ISO 20022 messages such as `pacs.008` and `camt.05x`. Parties now resolve disputes through correspondence and log reconciliation.

**What greengage adds:** Both institutions sign a confirmation whose `payload_hash` is the hash of the ISO message. Each institution keeps a self-contained record of what both sides understood the payment to be. Amendments and investigations chain to the original.

**The integration:** Define a profile; do not change the rail. The BCF travels beside the rail message, or an existing free-format field carries only its hash. Dispute evidence becomes cryptographic instead of archaeological.

## 7. Software supply chain: counter-signed acceptance — *integration note*

**Host:** The in-toto, SLSA, and DSSE stack standardizes single-signer software attestations. C2PA does the same for media provenance. A builder attests to provenance; a scanner attests to a result.

**What greengage adds:** Bilateral acceptance. A vendor supplies an SBOM or build; the customer often accepts it by email or ticket. If both sign the artifact hash, delivery and acceptance become one offline-verifiable record. Later deliveries, waivers, and exceptions form a verifiable chain.

**The integration:** Define a profile in which the BCF `payload_hash` is the in-toto statement or artifact digest. Keep the existing attestation machinery and carry the co-signed acceptance beside it.

---

## What greengage never brings

The boundary is the same in every integration (`OVERVIEW.md`):

- **No consensus, no ordering, no double-spend prevention.** Where global uniqueness is needed, the host provides it (a chain in §5, a vault in §3, a log in §2).
- **No payload semantics.** Every host binds by `payload_hash`; greengage never interprets the ISO message, the SBOM, or the loan file.
- **No custody, no settlement.** Value moves on the rails that already move it.

greengage always adds the same three properties: both parties signed, the history is tamper-evident, and a verifier can check the artifacts offline. The host does not need to be available or trusted during verification.
