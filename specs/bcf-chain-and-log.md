# BCF Chain and Log

**Status**: chain sections (§1–§5) frozen (Epic 1); log rungs 1–2 (§6.1 receipts, §6.2 chain-head) frozen (Epic 2); witnessed log (§6.3, rung 3) frozen (Epic 3).
**Sources**: P05 (hash-chained BCFs over state channels, L3), P10 (signed receipts, L6), P14 §8 (light-sequencer ladder rungs 1–3, L4), open decisions O3/O4.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described in RFC 2119 / RFC 8174. This spec builds on `bcf-core.md`; "claim", "artifact", "claim_hash", and `prev` are as defined there.

## 1. Overview

Static BCF artifacts compose into evolving, auditable state by hash-linking: each claim's `prev` field (claim key 6) carries the `claim_hash`es of its predecessors. There is no contestation game and no shared network (L3/L4): a chain is **detect-mode** evidence — it cannot prevent a counterparty from misbehaving, but it makes every misbehavior attributable from the honest party's evidence alone. The log machinery (§6) extends detection to withholding.

## 2. Chain structure

- **Genesis.** A claim with `prev = []` is a genesis claim. Its `claim_hash` is the **chain id**. The mandatory `nonce` (bcf-core §2) guarantees distinct sessions have distinct chain ids even under identical terms.
- **Successor.** A claim with `h ∈ prev` is a *successor of* the claim whose hash is `h`. A claim MAY have multiple `prev` entries (a **join**), e.g. binding a payment step to both the prior step and an attestation artifact.
- **Member.** An artifact is a **member** of chain `C` if it is `C`'s genesis or it reaches `C`'s genesis by following `prev` edges (transitively). Members are the chain's succession — by §5 they form a single line per party.
- **Import.** An artifact in the verifier's input set that is referenced by some member's `prev` but is not itself a member (it does not reach the genesis — typically it is the genesis of *another* chain, e.g. a KYC attestation issued long before the session). An import is **evidence referenced by the chain, not part of its succession**: it is imported without re-signing, its own `prev` entries are foreign context and are NOT required to resolve, and §4 limits what it proves.
  - *Imports are single-level.* An import's own ancestors are NOT acceptable input to this `verify_chain` call — including them is E_CHAIN_UNREACHABLE (deliberate anti-smuggling strictness). To validate imported evidence in depth, run a **separate** `verify_chain` rooted at the import's own chain id; in *this* call, the import stands for exactly the referenced hash.
  - *Import classification is presenter-influenced.* Nothing requires an import to be foreign-signed; a chain party can place history of its own behind an import boundary, where C3's gap check does not follow (§3). Applications MUST therefore treat imports as opaque referenced evidence — never as part of the parties' succession — and SHOULD treat a **self-import** (an import signed by the same parties as the chain's members) as a signal to demand that import's chain be verified separately.
- **Duplicate `prev` entries** MUST be rejected (E_CHAIN_STRUCTURE).

## 3. Chain verification

```
verify_chain(artifacts, chain_id, expected_domain) -> ordered DAG | error
```

Input is a set of envelopes plus any payloads to be checked, a `chain_id`, and an optional caller-policy list `external_refs` of accepted absent references. Checks, in order:

| # | Check | Failure |
|---|---|---|
| C1 | Every artifact in the input set — members *and* imports — passes `verify_bcf` (bcf-core §8) | (propagated) |
| C2 | Exactly one input artifact has `claim_hash == chain_id`, and it is a genesis. Partition the rest per §2: every input artifact MUST be a member or an import; an artifact that is neither (unrelated to this chain) MUST be rejected | E_CHAIN_ROOT / E_CHAIN_UNREACHABLE |
| C3 | Every **member's** `prev` entry resolves to an input artifact or appears in `external_refs`. Imports' `prev` entries are exempt (§2: foreign context) | E_CHAIN_GAP |
| C4 | No equivocation (§5) among the input artifacts — members and imports alike | E_EQUIVOCATION |

A member's `prev` entry that resolves to nothing is a **gap**: the verifier MUST NOT silently skip it — a gap is either missing evidence (retransmission needed; protocol in §6) or deliberate withholding. `external_refs` is caller policy, not a default.

**Implementation note (not a check).** A true `prev` cycle would require a hash preimage and cannot be constructed; no vector for it is possible, and "acyclicity" is not a priced protocol element. Implementations MUST nonetheless bound traversal (visited set) so hostile *input sets* — duplicate hashes, dense joins — cannot drive superlinear work.

## 4. Heterogeneous composition

Claims of different `claim_type`s — signed by *different party sets* — ride one chain. This is the composability that motivates BCF: a KYC attestation between (issuer, subject) chains into a payment session between (PSP-A, PSP-B) by reference, travels through a gateway, and remains verifiable at exit.

What a verifier may conclude from a mixed chain, exactly:

1. Each artifact individually carries the bilateral commitment of *its own* listed parties — nothing more. Referencing an artifact does not extend its signers' commitment.
2. A successor's signers committed to the *identity* (`claim_hash`) of every `prev` entry: they signed "this exact prior evidence is what we build on". They did not sign the referenced claim's truth — they bound their agreement to its bytes.
3. Ordering: an artifact referencing `h` was signed after the artifact with hash `h` existed (hash precedence). No other temporal conclusion is licensed; per-signer `iat` values are each signer's own assertion.

Whether referenced evidence (e.g. the KYC attestation's issuer) is *acceptable* is application/TGS policy, evaluated over the verified DAG — never folded into chain verification itself.

## 5. Forks and equivocation

- **Equivocation**: party `P` equivocates if `P`'s signature appears on two distinct claims that share a `prev` entry. **Any branching is equivocation by every party that signed both branches.** There is no type- or role-based exemption.
- *Why so strict.* Any softer definition keys "same position" on fields the signer chooses (`claim_type`, `prev` placement), and a cheater evades it by renaming the type or interposing a throwaway bridge claim before forking — both demonstrated in this spec's R-B review. The strict rule is evasion-proof for single-presentation detection: a divergence between two stories must branch *somewhere*, and at that branch point one party has signed two successors of one node. Note the bridge maneuver is caught precisely because the bridge itself is a second successor of the fork point. This is the split-view/equivocation notion of accountable distributed systems (PeerReview; transparency logs, RFC 6962/CONIKS), applied per-signer.
- *Boundary, stated exactly:* "must branch somewhere" excludes the genesis node. A cheater who tells the second story as a **fresh genesis** (`prev = []`) shares no `prev` entry with anything; within one presentation such an artifact is rejected as unrelated (C2), and detecting it as the *same session retold* is the cross-presentation problem — owned by the log machinery (§6), not by C4.
- *The cost, stated honestly:* a chain is **linear per party**. Concurrent workstreams cannot branch inside one chain; they run as **separate chains** (own genesis each) and are composed by a later join claim that references their heads — the joined artifacts enter as imports or members per §2. Receipts (§6) MUST NOT be chain successors for the same reason; their binding to delivered artifacts is by content, not by `prev` (design owed in Epic 2, note N2.1).
- The **equivocation proof** is the pair of complete envelopes. It is self-contained: any third party runs `verify_bcf` twice and observes `P`'s signature on two distinct claims sharing a `prev` entry. By construction (each claim multilaterally signed), the cheated counterparty always holds one half and obtains the other the moment the conflicting artifact is presented anywhere.
- C4 detects equivocation *within the presented set*. Detecting equivocation across presentations — where `P` shows different chains to different audiences — requires the log machinery (§6): receipts force `P` to leave signed evidence of what it delivered, and chain-head publication forces a single public commitment. (This single-presentation/cross-presentation split is exactly the transparency-log gossip problem.)
- What happens *after* an equivocation proof (recovery, restitution, default clauses) is out of technologist scope — notes N3.3/N8.4.

### 5.1 Why "conflict is a fault" (and what it is *not*)

A reviewer will reach for linearizability — "this is just a strong ordering you pay for with concurrency." That intuition crosses two axes and the comparison should be retired before it misleads.

- **Wrong axis.** Linearizability is a *consistency model*: what a **correct** (crash-stop, benign) system lets a client observe, ordered against a real-time clock. The equivocation rule is a *Byzantine-accountability* property: what can be **proven** about a participant who lies about its own history. Linearizability has no notion of a node signing two versions of its own operation; it is the wrong neighbour because it assumes nobody lies and pays for its strength with **coordination** (quorum/leader round-trips, lost availability under partition). This rule assumes someone *will* lie, requires **no coordination** (a party extends its own chain unilaterally, offline), and pays only in **expressiveness** — which it recovers for free via separate chains + joins. The CAP reflex ("strong ordering is expensive, weaken it to scale") therefore does not transfer: the strict rule is cheap *because* it is per-writer and detect-mode.
- **Right kin.** The precise prior art is **fork consistency / fork\*** (Mazières & Shasha 2002; SUNDR, Li et al. 2004): an untrusted party may equivocate and show different audiences different histories, but the moment two honest views are compared the fork is evident and they can never reconverge. That is exactly the C4 (single-presentation) vs §6-log (cross-presentation) split, which is the transparency-log gossip problem (RFC 6962, CONIKS) and accountable-systems equivocation (PeerReview). Structurally the artifact is a **per-author hash chain with cross-author references** — the Secure Scuttlebutt / Git shape, where forking one's own feed is the cardinal, detectable sin. Globally the DAG is **causal** (Lamport happens-before via hash links); per signer it is **sequential** (a single line). It never aspires to a global real-time total order, and ordering conclusions are limited to hash precedence (§4.3), not wall-clock.
- **The real strong-vs-weak dial.** The genuine ordering-strength choice is not linearizable-vs-sequential; it is *what a self-conflict means*:

| Policy on a self-conflict | Realm analog | Greengage |
|---|---|---|
| Conflict is a **fault** — branching is equivocation, no merge | strict / fork-detection | **chosen** |
| Conflict is a **mergeable state** — multi-value register, reconcile later | CRDT / eventual consistency | rejected |
| Conflict resolved by a **dispute game** — highest version wins after a challenge window | optimistic concurrency / state-channel (Perun) contestation | rejected (P05, L3) |

  The two weaker neighbours are exactly the merge-on-conflict (CRDT) and litigate-on-conflict (Perun contestation window) designs the programme already evaluated and dropped. Conflict-as-fault is the strong end *of that dial*: simplest to reason about, no merge semantics, no dispute machinery, no version-number race — and a fork is unambiguous misbehaviour rather than a state to resolve.

## 6. Log: receipts and chain heads (ladder rungs 1–2)

The chain (§§2–5) is detect-mode *within one presentation*: C4 catches equivocation only when both halves reach one verifier. The log extends detection across presentations and to withholding. This section specifies the two rungs that need no standing infrastructure: **receipts** (the recipient leaves signed evidence of what it received) and **chain-head publication** (the holder publishes one signed commitment to its view). Rung 3 (a witnessed append-only log) is §6.3, deferred to a later epic.

### 6.1 Signed receipts (rung 1)

A **receipt** is a unilateral, content-bound acknowledgement: "party R held the artifact whose `claim_hash` is H, at time T." Its job is purely evidentiary, and the evidence is **asymmetric**: a *presented* receipt is non-repudiable proof that R held those exact bytes; the *absence* of a receipt proves nothing against either party — it is equally consistent with non-delivery, loss in transit, and a recipient who received the artifact but declined to acknowledge it. A rational party intending to later deny receipt simply never issues one, so receipts catch only the party who acknowledges and then recants. Turning silence into an attributable signal needs fair-exchange or witnessed delivery (bcf-core §10; rung 3), which rungs 1–2 do not provide. This is the long-standing non-repudiation-of-receipt asymmetry (ISO/IEC 13888). A receipt attributes to a **key** (`recipient.pub`), never to the self-asserted `id` (bcf-core N1.7).

A receipt is **not a BCF artifact**: a BCF artifact requires ≥ 2 parties (bcf-core §2.2), and a receipt has exactly one signer. It is therefore a **COSE_Sign1** (RFC 9052 §4.2, CBOR tag 18) over a deterministic-CBOR receipt body. It binds the acknowledged artifact **by content** (`artifact_hash`), and carries **no `prev`** — a receipt is never a chain member (the §5 constraint: a receipt extending a chain would be branching, hence equivocation by its signer).

**Receipt body** — a CBOR map with integer keys, deterministic-CBOR encoded (bcf-core §3):

| Key | Name | Type | Meaning |
|---|---|---|---|
| 1 | `domain` | tstr | MUST be exactly `"BCF-RECEIPT/1"` — a distinct domain so a receipt can never be confused with a BCF claim |
| 2 | `artifact_hash` | bstr (32) | The `claim_hash` of the acknowledged artifact (content binding, never `prev`) |
| 3 | `recipient` | party entry | The single signer, as a bcf-core §2.2 party entry (`id`, `pub`, `alg`) — inline key keeps the receipt self-contained |
| 4 | `received_at` | int | The recipient's asserted receipt time (POSIX seconds); the receipt's only timestamp |

**Envelope** — tagged COSE_Sign1 (tag 18): `[ protected : bstr .cbor {1: alg, 4: kid}, unprotected: {}, payload: bstr = receipt_body, signature ]`. `kid` MUST equal `SHA-256(recipient.pub)`; `alg` MUST equal `recipient.alg`. The signing input is the COSE_Sign1 `Sig_structure` (context `"Signature1"`, body protected, empty `external_aad`, payload = receipt_body).

**`verify_receipt(bytes, expected_domain) -> receipt | error`**, ordered:

| # | Check | Failure |
|---|---|---|
| R1 | decode deterministic CBOR (recursive into the protected `bstr .cbor`), tag 18, COSE_Sign1 shape, unprotected empty | E_DECODE / E_NONCANONICAL |
| R2 | body decodes as a deterministic-CBOR map with exactly keys {1,2,3,4}, correct types/lengths | E_RECEIPT_STRUCTURE |
| R3 | `domain == expected_domain` (`"BCF-RECEIPT/1"`) | E_RECEIPT_DOMAIN |
| R4 | `recipient` well-formed (bcf-core V5 rules for a single entry: alg/pub length agree); header `alg == recipient.alg`; `kid == SHA-256(recipient.pub)` | E_RECEIPT_STRUCTURE |
| R5 | signature verifies over the Sig_structure under `recipient.pub` (ES256K low-s) | E_RECEIPT_SIG |

A verifier MAY then check `receipt.artifact_hash` against an artifact it holds; the binding is the recipient's signed assertion, nothing more. (`kid` here is a *deterministic-error* device, not an attribution control: COSE_Sign1 has exactly one inline key, so R5 already verifies under the only candidate — the `kid` check just keeps "wrong signer" a clean E_RECEIPT_STRUCTURE rather than an opaque E_RECEIPT_SIG. Same honest pricing as bcf-core's `kid`.)

**Idempotence and duplicate delivery (N2.6).** Receipts are keyed by `(artifact_hash, recipient.pub)`. A second receipt for the same pair — e.g. the same artifact redelivered over a second transport — is redundant, not equivocation: receipts are not chain members and have no `prev`, so they cannot fork. Verifiers dedup by the key; a differing `received_at` is merely the second delivery's time.

**Gap-detection and repair (N2.2).** Given a held set of artifacts, a **gap** is any `prev` entry of a held member that resolves to no held artifact and no accepted external reference (the C3 condition, applied to what one party holds). The standard repair: the holder sends a **retransmission request** naming the missing `claim_hash`; the counterparty returns the artifact (which the holder answers with a receipt) or it is withholding. The request and its receipt are ordinary deliveries; the protocol adds no new artifact type. Note the asymmetry above: a gap with no further evidence is unresolved, not attributable — what *is* attributable is a counterparty that holds the holder's receipt for an artifact it now claims never to have sent, or (via §6.2) a published head committing to an artifact the counterparty later withholds.

**Poison-message handling (N2.3).** Because `claim_hash` commits to exact bytes, an artifact that fails `verify_bcf` cannot be silently quarantined: any party that signed a successor referencing that hash signed onto a predecessor whose bytes do not verify. Resolution is by content, not by deletion — the holder presents the malformed bytes plus the successor that references them; the referencing party either produces verifying bytes for that hash (impossible if the bytes are genuinely malformed, since the hash is over those bytes) or is attributably at fault. A poison artifact is thus evidence against whoever built on it, not a denial-of-service on the chain.

### 6.2 Chain-head publication (rung 2)

A **chain head** is a periodic, signed, 32-byte commitment to the set of member `claim_hash`es a party attests to for a chain. Publishing one head forces the publisher to a single story: a counterparty holding the head plus an inclusion proof can prove the publisher committed to an artifact, so **withholding** it becomes attributable; and two conflicting signed heads for one chain are a head-level fork — the across-presentation analog of C4.

**O3 is resolved to a Merkle root.** The head commits via an RFC 6962 Merkle tree, chosen for its auditability, 32-byte head, and independent reference implementations (so vectors cross-check). The folded/recursive-proof variant — which would let a head prove the chain *valid*, not merely commit to *membership*, in O(1) verification — is a documented future optimization, triggered only when a verifier cannot afford to re-check the chain behind an inclusion proof. It is **not** built in this rung.

**Tree construction.** Leaves are the member `claim_hash`es, **deduplicated and sorted bytewise ascending** (a set commitment: the root is a function of *which* artifacts, not the order they arrived). Hashing is RFC 6962 §2.1 with domain separation: `leaf = SHA-256(0x00 ‖ claim_hash)`, `node = SHA-256(0x01 ‖ left ‖ right)`, the empty set `= SHA-256("")` (RFC 6962 §2.1). Domain separation blocks the second-preimage attack where a leaf is reinterpreted as an internal node. Edge cases are RFC 6962 verbatim: a single-leaf tree's root is `SHA-256(0x00 ‖ claim_hash)` (no node level), and a `count = 0` head commits to nothing and supports no inclusion proof.

**Head body** — deterministic-CBOR map:

| Key | Name | Type | Meaning |
|---|---|---|---|
| 1 | `domain` | tstr | MUST be `"BCF-HEAD/1"` |
| 2 | `chain_id` | bstr (32) | The chain this head commits to (genesis `claim_hash`) |
| 3 | `root` | bstr (32) | The Merkle root over the sorted member set |
| 4 | `count` | int | Number of distinct leaves (member artifacts committed) |
| 5 | `published_at` | int | Publication time (POSIX seconds) |
| 6 | `publisher` | party entry | The signer, as a bcf-core §2.2 party entry |

The head is wrapped in a COSE_Sign1 exactly as a receipt (tag 18, `kid = SHA-256(publisher.pub)`, context `"Signature1"`). **`verify_head`** mirrors R1–R5 with `domain == "BCF-HEAD/1"` and body keys {1..6} (failures E_HEAD_STRUCTURE / E_HEAD_DOMAIN / E_HEAD_SIG).

**Inclusion proof.** An audit path (RFC 6962 §2.1.1) proves a given `claim_hash`'s leaf sits under a head's `root`. Verification is position-dependent, so it MUST take the leaf's index and the tree size:

```
verify_inclusion(claim_hash, proof, leaf_index, tree_size, root) -> bool
```

| # | Check | Failure |
|---|---|---|
| P1 | `leaf_index < tree_size`; `proof` length equals the RFC 6962 audit-path length for `(leaf_index, tree_size)` | E_HEAD_INCLUSION |
| P2 | recompute the root from `leaf = SHA-256(0x00 ‖ claim_hash)` and the path per RFC 6962 §2.1.1 (the index/size drive left/right at each level) | E_HEAD_INCLUSION |
| P3 | recomputed root equals `root` | E_HEAD_INCLUSION |

**Binding to the signed head is normative**: `tree_size` MUST be the verified head's `count` and `root` MUST be its `root` — both taken from a head that passed `verify_head`, never supplied independently. This is what makes `count` load-bearing (it is the authoritative tree size; without it a forged `(leaf_index, tree_size)` reshapes the path geometry). A counterparty holding `(head, inclusion proof for X)` then has non-repudiable evidence that the publisher committed to X — so a later presentation that omits X is provably withholding.

**Head-fork detection (the cross-presentation guard).** The presented member lists are attacker-supplied, so they MUST be pinned to the signed roots before any superset reasoning:

```
detect_head_fork(head_a, members_a, head_b, members_b) -> fork | no-fork | error
```

| # | Check | Result |
|---|---|---|
| F1 | both heads pass `verify_head` | else propagate E_HEAD_* |
| F2 | `head_a.chain_id == head_b.chain_id` and `head_a.publisher.pub == head_b.publisher.pub` | else **not comparable** (no-fork: different chains or publishers are not one party's two stories) |
| F3 | for each side, `merkle_root(sorted_dedup(members_x)) == head_x.root` | else E_HEAD_STRUCTURE (the member list does not match the signed commitment) |
| F4 | if `head_a.root == head_b.root` → **no-fork**; elif one member set ⊇ the other → **no-fork** (honest growth); else → **fork** | — |

F3 is the load-bearing check: without it, fabricated member lists can frame an honest publisher (present non-superset lists for two superset heads) or hide a real fork (present superset lists for two forking heads). The fork proof is the pair of signed heads plus the member lists that F3 pins to them. *Honest limit:* proving the superset relation non-interactively from heads alone (an append-only **consistency proof**, RFC 6962 §2.1.2) requires the publisher to maintain a stable structure and is the natural province of the witnessed log — deferred to rung 3 (§6.3). Until then, fork detection requires the member lists, pinned by F3.

**Cadence vs the equivocation window (N2.7).** Between two publications, a publisher can equivocate without the heads contradicting it; the inter-publication interval *is* the equivocation window heads leave open. Cadence is a deployment parameter traded against publication cost; a witnessed log (rung 3) closes the window to the witnessing interval. This spec fixes the head format, not the cadence.

### 6.3 Witnessed-log client (rung 3)

§6.2 left two gaps open, both stated there: a publisher can equivocate *between* head publications (the cadence window, N2.7), and fork detection needs the attacker-supplied member lists (the F3 dependency). Rung 3 closes both by binding a publisher to **one monotonically-growing history that independent witnesses vouch for** — the transparency-log pattern (RFC 6962; Sigsum). This is a **client** protocol: it verifies checkpoints, consistency proofs, and witness co-signatures, and detects split views. Operating the log or the witnesses is deployment, not this spec.

The model is **fork-consistency, detect-mode** (its justification is §6.3.6): witnesses are independent and uncoordinated; equivocation is made *accountable*, never *prevented*. No consensus, no quorum agreement, no standing network is introduced.

#### 6.3.1 The head-log and checkpoints

For a chain published by a party `P`, the **head-log** is an append-only log whose entries are `P`'s successive signed chain-heads (§6.2), in publication (epoch) order. Each entry is reduced to a 32-byte **head hash** so the tree is structurally identical to §6.2's (a 32-byte-leaf RFC 6962 tree, reusing the same Merkle code):

```
head_hash_i = SHA-256(head_bytes_i)               ; head_bytes_i = the COSE_Sign1 head of epoch i
head_leaf_i = SHA-256(0x00 ‖ head_hash_i)         ; RFC 6962 §2.1 leaf hash
node        = SHA-256(0x01 ‖ left ‖ right)         ; RFC 6962 §2.1
```

This tree is **append-ordered**, distinct from the §6.2 chain-head's *sorted-set* tree: there, leaf order is membership-canonical (sorted); here, leaf order is the publisher's commitment sequence (epoch 0, 1, 2, …). The hashing rules are identical; the semantics differ — the chain-head commits to *which artifacts*, the head-log commits to *the ordered history of those commitments*.

A **checkpoint** (a signed tree head, Sigsum-style) is a deterministic-CBOR map:

| Key | Name | Type | Meaning |
|---|---|---|---|
| 1 | `domain` | tstr | MUST be `"BCF-CKPT/1"` |
| 2 | `chain_id` | bstr (32) | The chain whose head-log this commits to |
| 3 | `tree_size` | int | Number of head leaves in the log (epochs published) |
| 4 | `log_root` | bstr (32) | RFC 6962 root over the head leaves in epoch order |
| 5 | `published_at` | int | Checkpoint time (POSIX seconds; advisory) |
| 6 | `publisher` | party entry | The log owner and signer |

The checkpoint is wrapped in a COSE_Sign1 (tag 18, `"Signature1"`, `kid = SHA-256(publisher.pub)`) exactly as a head. The **log identity** is the pair `(publisher.pub, chain_id)` — there is no separate id field; two checkpoints belong to the same log iff their `publisher.pub` and `chain_id` match.

A **witness co-signature** is a witness's independent attestation that it observed a checkpoint. It is itself a COSE_Sign1 by the witness over a deterministic-CBOR body:

| Key | Name | Type | Meaning |
|---|---|---|---|
| 1 | `domain` | tstr | MUST be `"BCF-COSIG/1"` |
| 2 | `checkpoint_hash` | bstr (32) | `SHA-256` of the checkpoint's COSE_Sign1 bytes (content binding) |
| 3 | `witness` | party entry | The co-signing witness |
| 4 | `observed_at` | int | The witness's observation time (advisory) |

A co-signature binds the checkpoint **by content** (`checkpoint_hash`), exactly as a receipt binds an artifact — so a co-signature cannot be transplanted onto a different checkpoint.

#### 6.3.2 Consistency proof

`verify_log_consistency(old_size, old_root, new_size, new_root, proof) -> bool` is the RFC 6962 §2.1.2 consistency-proof check: it proves the size-`old_size` log is a **prefix** of the size-`new_size` log — the publisher only appended, never rewrote or removed a past head. The algorithm is RFC 6962 §2.1.2 verbatim (cited, not re-derived). Boundaries: `old_size <= new_size` (else fail); `old_size == 0` is trivially consistent (the empty log is a prefix of everything); `old_size == new_size` requires `old_root == new_root`. Failure is `E_LOG_CONSISTENCY`. As with §6.2 inclusion, `old_size`/`new_size`/the roots MUST come from checkpoints that passed `verify_checkpoint`, never supplied independently.

#### 6.3.3 Head-in-log inclusion

A chain-head `H` published at epoch `i` is the `i`-th leaf under a checkpoint's `log_root`. This is the §6.2 RFC 6962 inclusion check applied to the head-log, over the head hash: `verify_inclusion(SHA-256(head_bytes), proof, i, tree_size, log_root)`, with `tree_size`/`log_root` taken from a verified checkpoint (failure `E_HEAD_INCLUSION`, the same Merkle-inclusion code — the proof obligation is identical, only the tree differs). A counterparty holding `(witnessed checkpoint, inclusion proof for H_i)` proves `P` committed to `H_i` at position `i` in its witnessed history.

#### 6.3.4 Client protocol and split-view detection

`verify_checkpoint(bytes, expected_domain, witness_cosigs, witness_set, threshold) -> Checkpoint | error`, ordered:

| # | Check | Failure |
|---|---|---|
| W1 | checkpoint is a valid COSE_Sign1 (R1-style), body keys exactly {1..6}, types/lengths, `publisher` well-formed, header `alg`/`kid` bind to `publisher.pub` | E_DECODE / E_NONCANONICAL / E_CKPT_STRUCTURE |
| W2 | `domain == "BCF-CKPT/1"` | E_CKPT_DOMAIN |
| W3 | checkpoint signature verifies under `publisher.pub` (ES256K low-s) | E_CKPT_SIG |
| W4 | at least `threshold` co-signatures that count, where a co-signature **counts** iff: it is a valid COSE_Sign1; its body decodes as a `"BCF-COSIG/1"` co-signature (keys {1..4}); it binds this checkpoint's `checkpoint_hash`; its `witness.pub ∈ witness_set`; and its `witness.pub ≠ publisher.pub`. Counting is by **distinct `witness.pub`** — multiple co-signatures from one witness count once | E_CKPT_WITNESS |

W4 is the whole accountability surface, so each clause prices a concrete bypass: the **domain/structure** clause stops a same-shaped artifact (a receipt body is keys {1..4} too) being counted as a witness attestation; **`witness.pub ∈ witness_set`** stops an unauthorized witness; **`≠ publisher.pub`** stops the publisher self-witnessing toward its own threshold (the least-independent party); **distinct-by-`pub`** stops one witness manufacturing a quorum with several co-signatures (e.g. differing only in the advisory `observed_at`). The caller's roster is its trust decision (§6.3.5), and it MUST NOT place `publisher.pub` in the witness set.

A checkpoint that passes W1–W4 is *witnessed*. Cross-presentation **equivocation** is then detected over witnessed checkpoints. Detection is **interactive** for differently-sized checkpoints — it is the Certificate-Transparency auditor exchange (RFC 6962 §2.1.2): the verifier *requests* a consistency proof from the smaller checkpoint to the larger, and a proof that is absent or fails to verify is itself the fork evidence.

`detect_log_equivocation(ckpt_a, ckpt_b, consistency_proof) -> fork | no-fork`, over two *witnessed* checkpoints (each already passed W1–W4):

| # | Check | Result |
|---|---|---|
| L1 | `ckpt_a.publisher.pub == ckpt_b.publisher.pub` and `ckpt_a.chain_id == ckpt_b.chain_id` | else **no-fork** (different chains or publishers are not one party's two stories) |
| L2 | if `tree_size_a == tree_size_b`: **fork** iff `log_root_a ≠ log_root_b`, else no-fork | — |
| L3 | if `tree_size_a ≠ tree_size_b`: let (s_lo, r_lo) be the smaller and (s_hi, r_hi) the larger; **no-fork** iff `verify_log_consistency(s_lo, r_lo, s_hi, r_hi, consistency_proof)` succeeds (honest growth); otherwise **fork** | — |

The fork proof is the pair of witnessed checkpoints (each with its co-signatures) plus, for the cross-size case, the demonstrated *failure* to produce a bridging consistency proof. Detect-mode: the conflict is not prevented; it is caught the moment both halves reach one verifier or a gossip/audit exchange. Honest limit (and the only claim §6.3.6 may make): the witnessed log makes equivocation **provable once two witnessed checkpoints meet**; it does not force them to meet — that is the gossip dependency it shares with all transparency logs.

#### 6.3.5 Witness-set governance (O4) — caller policy

The client takes the witness set (a list of witness public keys) and `threshold` as **caller policy**, exactly as `verify_chain` takes `external_refs`. This spec fixes the co-signature format (§6.3.1) and the `≥ threshold` distinct-witness check (W4); it does **not** fix the roster mechanism — who runs witnesses, how the set is provisioned, rotated, or revoked (P14 §7.5) is a deployment decision, out of the verify-only client. **Honest trust statement:** a client that trusts a witness set inherits its threshold assumption — `threshold` colluding or compromised witnesses can co-sign a fork undetected by W4 alone (though still caught by §6.3.4 if an honest witnessed checkpoint surfaces). Choosing the set and threshold is the deployment's security decision; O4 is resolved here only to the extent the client enforces it.

#### 6.3.6 Why detect-mode witnessing (and the sequencer / CQRS analogy)

A reviewer may ask why the witnessed log does not simply *prevent* equivocation — a quorum of witnesses that refuses to co-sign a second head per epoch would give a single, authoritative, linearizable history. The answer is that prevention is the one thing this framework has consistently declined to buy, and declining it here is not a weakness but the point.

- **It introduces no new authority.** A preventing quorum is a consensus protocol: the witnesses must agree, in real time, on one ordering — a standing, coordinated, governed network, precisely the "join our chain" ask that P14 identifies as the adoption-killer and that §5.1 already refused for the per-author chain. Detect-mode witnesses are independent and offline-composable; each one's co-signature is a local, uncoordinated observation. The log gains accountability without anyone becoming the source of truth.
- **It is the same guarantee, one layer up.** §5.1 made the per-author chain *fork-consistent* (SUNDR; Mazières–Shasha): a cheater can show different histories, but the moment two honest views meet, the fork is evident and irreconcilable. C4 delivers that *within one presentation*; the witnessed log delivers it *across presentations and across time*. Witnesses + RFC 6962 consistency proofs are exactly the Certificate-Transparency gossip mechanism that turns fork-consistency into practically-detected equivocation. We never assert a single global truth; we make divergence **provable once two witnessed checkpoints meet** (the gossip/audit dependency made precise in §6.3.4 — detection is interactive for cross-size checkpoints, never a prevention). That is the morally honest claim for a system whose whole thesis is that trust is irreducible and the achievable goal is *accountable* trust.
- **The honest limit, stated.** Detect-mode does not stop a publisher acting on a forked view in the gap before detection; it guarantees the fork becomes attributable evidence. Where a specific hop genuinely needs prevention, that is the reserved prevent-mode primitive (session atomicity, Phase 3), spent there and nowhere else — not smeared across the log as a standing quorum.

**The sequencer / CQRS framing.** The shape here is familiar from high-throughput data architectures, and naming the resemblance helps — with one decisive difference. The head-log is an **append-only journal**; the chain-heads are periodic **checkpoints / snapshots** over the artifact stream; the publisher is the **command side** that appends, and clients are the **query side** that read against witnessed checkpoints. That is event-sourcing / CQRS, and the "log of commitments, not of content" is the transparency-log **sequencer** pattern. The decisive difference: in LMAX/CQRS the sequencer (the journal's single writer) is **trusted** — it *is* the authority. Here the sequencer is **untrusted**; witnesses and consistency proofs convert a trusted-sequencer architecture into an *accountable-untrusted-sequencer* one. That conversion is what lets a familiar, fast, single-writer pattern survive between mutually-distrustful parties — the same move §5.1 made for ordering (a per-writer sequential log, globally causal), now carried to the publish layer. The CQRS/LMAX tie-in is positioning; the normative guarantee remains fork-consistency.

## 7. Removal table (chain sections)

| Element | Attack if removed |
|---|---|
| `prev` as claim content (signed) | A relay reorders or re-parents artifacts: session history becomes whatever the presenter arranges, with no signature contradicting it |
| Chain id = genesis `claim_hash` (with mandatory nonce upstream) | Two sessions with identical terms merge: artifacts from one replay into the other (cross-session replay) |
| C2 member/import partition (every input artifact classified) | Evidence smuggling: arbitrary unrelated artifacts ride in the input set and acquire the appearance of belonging to the session; or — the inverse failure — legitimate imported attestations are unrepresentable and implementations diverge on the spec's own composition examples |
| C3 gap rejection (members) | Withholding becomes invisible: a presenter omits inconvenient artifacts and the chain still "verifies" |
| C3 import exemption (imports' `prev` not required) | If removed: composition becomes transitively unbounded — importing one attestation drags in its entire foreign chain, recursively. **Cost of keeping it, priced honestly**: the exemption is a withholding boundary — a presenter (even a chain party, via self-import) can park history behind an import where C3's gap check does not follow. The mitigation is §2's import rules: imports are opaque single-level references, never succession; depth comes from a separate rooted `verify_chain` |
| C4 strict equivocation (any branching by one signer) | Evasion by renaming or re-parenting: a cheater forks the session under a fresh `claim_type` or behind a bridge claim and the double-story is undetectable from both halves in hand (demonstrated in R-B review) |
| Linearity-per-party consequence (accepted, not removed) | If softened to readmit in-chain branching, the evasion above returns; concurrency lives in separate chains + joins instead |
| Conclusion limits of §4 (reference ≠ endorsement) | Verifiers over-trust: importing a KYC attestation is read as the payment parties *vouching* for it, an unsigned and unintended liability |
| Self-contained equivocation proof (pair of envelopes) | Adjudication requires trusting the accuser's narrative or a third-party log even in the bilateral case |
| Receipt is COSE_Sign1, not a BCF artifact (exact keys {1..4}, no `prev`) | Structural: a receipt is tag 18 / one signer, so `verify_chain` (tag 98, ≥2 parties) can never admit it as a member; the exact-keys rule rejects a smuggled `prev`. The row exists to state the type boundary, not to price a reachable attack |
| Receipt `domain` = `"BCF-RECEIPT/1"` (distinct from BCF) | Cross-confusion: a single-signer receipt is replayed as (or mistaken for) a half-signed BCF artifact, or vice versa |
| Receipt binds `artifact_hash` (content), recipient inline | Without the content binding a receipt acknowledges nothing checkable; without the inline recipient key it is not self-contained and needs a directory to attribute |
| `received_at` (receipt) / `published_at` (head) | Advisory, unverifiable assertions, deliberately excluded from receipt dedup (N2.6) and from fork detection (which decides on set superset, not time). Priced honestly: they carry **no** security check; they exist for audit-trail readability and MAY inform application-level freshness policy. If a future rule needs verifiable time it must come from a witness (rung 3), not these fields |
| Merkle leaf/node domain separation (`0x00`/`0x01`) | Second-preimage: a leaf value is reinterpreted as an internal node (or vice versa), forging an inclusion proof for an artifact never committed |
| Head leaves sorted + deduplicated (set commitment) | Without a canonical leaf order the same membership yields different roots — heads stop being comparable, defeating fork detection and inclusion |
| Head `count` = authoritative tree size (bound at P-checks) | A forged `(leaf_index, tree_size)` reshapes the audit-path geometry; binding `tree_size` to the signed `count` stops an inclusion proof being verified against a tree shape the publisher never committed to |
| Signed head (`publisher` inline, COSE_Sign1) | An unsigned head is repudiable: the publisher denies committing to it, so withholding evidence and head-forks attribute to no one |
| F3 member-set ↔ root binding (fork detection) | Without it, attacker-supplied member lists either frame an honest publisher (non-superset lists over two superset heads) or hide a real fork (superset lists over two forking heads) |
| Head-fork = two non-superset roots by one publisher for one `chain_id` | Across-presentation equivocation goes undetected: the publisher shows different views to different audiences with nothing tying them to one commitment |
| Head-log append-order leaves (vs §6.2 sorted-set) | Without an order the "log" is just a set and a *consistency* (prefix/append-only) proof is undefined — a publisher could drop or reorder a past head with no contradiction |
| Checkpoint = signed (`publisher` inline) COSE_Sign1 | An unsigned checkpoint is repudiable: the publisher denies committing to a `log_root`, so consistency and split-view evidence attribute to no one |
| Witness co-signature binds `checkpoint_hash` + `"BCF-COSIG/1"` domain | Without the content binding a co-signature is transplantable onto a different checkpoint (a witness's attestation of head-log A is replayed as attestation of B); without the domain it is confusable with a receipt/head signature |
| W4 threshold of ≥ T **distinct** in-set witnesses | One co-signature (or T copies of one witness, or an out-of-set witness) rubber-stamps a fork: the whole accountability rests on independent observers, so below-threshold or non-distinct acceptance defeats it |
| Consistency proof (RFC 6962 §2.1.2) bound to verified checkpoints | A publisher rewrites or truncates its past history and presents a fresh checkpoint as if it extended the old one; without the prefix proof the rewrite is invisible |
| Log identity = `(publisher.pub, chain_id)` | Cross-log confusion: a checkpoint for one chain or publisher is presented as another's history; consistency/equivocation reasoning silently spans unrelated logs |

## 8. Test vectors

`specs/test-vectors/bcf-chain-and-log/` — chain vectors (Epic 1), log rungs 1–2 (Epic 2), and rung 3 / witnessed-log vectors under `log/` (Epic 3), per `specs/test-vectors/README.md`. All log vectors are generated by the same independent oracle (COSE_Sign1 + RFC 6962 Merkle and consistency proofs in Python), then cross-checked by the Rust implementation.

| Vector class | What it pins down |
|---|---|
| Chain: positive | Linear chain; mixed claim-type chain importing a foreign-genesis KYC attestation via a join (the C2 member/import partition's flagship case) |
| Chain: negative | E_CHAIN_GAP (member's unresolvable `prev`), E_CHAIN_ROOT (chain_id matches nothing), E_CHAIN_UNREACHABLE (unrelated artifact in input set), duplicate `prev` entry, E_EQUIVOCATION ×3 (same-type fork; renamed-type fork; re-parenting via bridge claim) |
| Receipt: positive | Valid Ed25519 receipt; valid ES256K receipt |
| Receipt: negative | wrong `domain` (E_RECEIPT_DOMAIN); `artifact_hash` mismatch / bad body keys (E_RECEIPT_STRUCTURE); `kid` ≠ SHA-256(pub) (E_RECEIPT_STRUCTURE); tampered signature (E_RECEIPT_SIG); `prev`-bearing body (E_RECEIPT_STRUCTURE — receipts have no `prev`) |
| Head: positive | Signed head over a multi-leaf sorted set (golden root); single-leaf head; empty-set head; valid inclusion proof for a committed leaf; valid single-leaf inclusion |
| Head: negative | wrong `domain` (E_HEAD_DOMAIN); tampered root/signature (E_HEAD_SIG); unknown body key (E_HEAD_STRUCTURE); inclusion proof for a non-committed leaf (E_HEAD_INCLUSION); flipped path node (E_HEAD_INCLUSION); wrong `leaf_index` for an otherwise-valid path (E_HEAD_INCLUSION) |
| Head-fork | non-superset roots → fork; superset growth → not a fork; different publisher → not comparable; member list not matching the signed root → E_HEAD_STRUCTURE (frame and evade cases) |
| Checkpoint: positive | Witnessed checkpoint meeting threshold (publisher sig + ≥ T distinct in-set witness co-signatures) |
| Checkpoint: negative | wrong `domain` (E_CKPT_DOMAIN); bad publisher sig (E_CKPT_SIG); unknown body key (E_CKPT_STRUCTURE); negative `tree_size` (E_CKPT_STRUCTURE); below-threshold co-signatures (E_CKPT_WITNESS); out-of-set witness (E_CKPT_WITNESS); two **byte-distinct** co-signatures from one witness, not distinct by `pub` (E_CKPT_WITNESS); co-signature binding a different `checkpoint_hash` (E_CKPT_WITNESS); co-signature with wrong/absent `BCF-COSIG/1` domain (E_CKPT_WITNESS); publisher self-witnessing toward threshold (E_CKPT_WITNESS) |
| Consistency: positive | Valid extension (size n prefix of size m); `old_size == 0` trivially consistent; equal size + equal root |
| Consistency: negative | non-monotone size (`old_size > new_size`, E_LOG_CONSISTENCY); tampered proof node (E_LOG_CONSISTENCY); equal size, different root (E_LOG_CONSISTENCY) |
| Head-in-log inclusion | head is the i-th log leaf under a checkpoint's `log_root` (valid); wrong epoch index (E_HEAD_INCLUSION) |
| Split-view (log) | same `tree_size`, different `log_root` → fork; honest extension (smaller is a prefix of larger, with consistency proof) → no-fork; cross-size fork (smaller not a prefix of larger) → fork; different publisher/chain → not comparable |
