# greengage

The **agreement layer**: a small, vectored format for co-signed, hash-chained, offline-verifiable commitments between identified parties, with a detect-mode evidence ladder above it (receipts, published chain-heads, a witnessed commit log) — delivered as a **spec suite + test vectors** (canonical) with a **Rust reference implementation**.

greengage is substrate-agnostic by design: transparency logs supply consistency, control registries supply uniqueness, existing rails supply settlement, and greengage supplies the record of what the parties actually agreed. It is the clean-slate implementation of the S1 research programme, with a USD→MXN payment corridor (UC-A) as its target end-to-end vertical.

New here? Start with [`OVERVIEW.md`](OVERVIEW.md) — the thesis and the longer bet. Then [`INTEGRATIONS.md`](INTEGRATIONS.md) — the same artifact living inside seven host stacks. [`PROVENANCE.md`](PROVENANCE.md) states plainly what has and has not been independently reviewed. [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) is the founding document: locked decisions, open decisions, build phases, crate map. Agents (and humans steering them) read [`AGENTS.md`](AGENTS.md) for the epic-at-a-time workflow and its human gates.

| Artifact | Purpose |
|---|---|
| [`OVERVIEW.md`](OVERVIEW.md) | The thesis: what greengage is, and the longer bet it implies |
| [`INTEGRATIONS.md`](INTEGRATIONS.md) | Integration notes: transparency logs, control registries, rails, and more |
| [`PROVENANCE.md`](PROVENANCE.md) | How this was built and reviewed; what not to rely on yet |
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | The rigid plan; binding decisions; protocol + adoption tracks |
| [`AGENTS.md`](AGENTS.md) | The epic workflow: gates A–D, decision discipline, conventions |
| [`specs/`](specs/README.md) | The canonical spec suite (frozen through the witnessed log) |
| [`NOTES_FROM_RESEARCH.md`](NOTES_FROM_RESEARCH.md) | Research backlog the UC-A vertical leaves at each layer |
| `crates/` | Rust reference implementation, conformance-tested against `specs/test-vectors/` |

Design authority: the S1 research corpus in the sibling `damson` repo (`damson/docs/research/`). License: [Apache-2.0](LICENSE).
