# greengage

greengage is a specification for **co-signed agreements between identified parties**. Parties sign a claim, link amendments by hash, and keep an artifact that anyone can verify offline.

When parties need stronger evidence, they can add signed receipts, published chain-heads, and a witnessed commit log. The repository contains the canonical spec suite and test vectors, plus a Rust reference implementation.

greengage works with the stack you already have. Transparency logs provide consistency, registries provide control, and existing rails settle payments. greengage records what the parties agreed.

New here? Read [`OVERVIEW.md`](OVERVIEW.md) for the design rationale, then [`INTEGRATIONS.md`](INTEGRATIONS.md) for seven examples. [`PROVENANCE.md`](PROVENANCE.md) explains what has and has not been independently reviewed.

| Artifact | Purpose |
|---|---|
| [`OVERVIEW.md`](OVERVIEW.md) | What greengage is and why it exists |
| [`INTEGRATIONS.md`](INTEGRATIONS.md) | How greengage fits seven host stacks |
| [`PROVENANCE.md`](PROVENANCE.md) | How the work was built and reviewed |
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | Decisions, phases, and repository map |
| [`AGENTS.md`](AGENTS.md) | Gated workflow and contribution rules |
| [`specs/`](specs/README.md) | Canonical specifications and test vectors |
| [`NOTES_FROM_RESEARCH.md`](NOTES_FROM_RESEARCH.md) | Open research items |
| `crates/` | Rust reference implementation |

Design authority: the S1 research corpus in the sibling `damson` repo (`damson/docs/research/`). License: [Apache-2.0](LICENSE).
