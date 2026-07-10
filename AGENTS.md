# AGENTS.md — how agents work in this repo

Read this first, every session. Then read `IMPLEMENTATION_PLAN.md` (the binding plan) and the **current epic issue** on GitHub (`gh issue list --label epic --state open`).

## What this repo is

The clean-slate S1 implementation: a **spec suite + test vectors** (canonical, in `specs/`) with a **Rust reference implementation** (`crates/`), built phase by phase per `IMPLEMENTATION_PLAN.md` §4, to be proven end-to-end on the UC-A corridor. Design authority is the S1 research corpus in the sibling `damson` repo; `NOTES_FROM_RESEARCH.md` carries its open items. Specs outrank code: a disagreement between them is a bug resolved explicitly, never silently.

## The epic loop

Work proceeds **one epic at a time**. An epic is one coherent slice of a build phase (most phases are one epic; a phase may split). Each epic is a GitHub issue labeled `epic`, and runs through four human gates:

| Gate | What happens | Human action |
|---|---|---|
| **A — Brief** | Agent drafts the epic brief as a GitHub issue: scope, exit criteria (quoted from the plan), spec sections to freeze, O\* decisions to resolve, `NOTES_FROM_RESEARCH.md` items that bite | Edit / approve the issue (comment `approved-A`) |
| **B — Spec** | Agent drafts spec sections + test vectors on the epic branch; opens the **spec PR**; the **R-B red leg** (see *Adversarial review*) runs and its memo is posted to the PR with Breaks fixed and Underpriced items dispositioned. Specs are canon, so this merge is never delegated | Review the PR *and the R-B memo*; merge |
| **C — Impl** | Agent implements crates against the now-frozen spec; vectors are the conformance harness; CI green; opens the **impl PR**; the **R-C red leg** runs and its memo is posted likewise | Review the PR *and the R-C memo*; merge |
| **D — Closeout** | Agent updates the plan's decision tables, discharges or re-defers NOTES items, posts a closeout comment (decisions moved, evidence, leftovers, red-leg residue), proposes the next epic | Close the issue; name the next epic |

**Autonomy boundary**: within a leg (between gates), run as autonomously as you like — research, draft, iterate, test. **Never cross a gate without the human**: don't merge PRs, don't close epic issues, don't start spec work before gate A, don't start impl before gate B.

## Adversarial review (red legs)

Self-applied discipline (removal tables, negative vectors) is the author grading its own homework: the author's removal table prices only the attacks the author thought of. So each PR-bearing leg ends with a **red leg** run by a **fresh-context agent that is not the authoring session**, before the human gate.

**Authorship blindness.** The red agent receives the artifacts under review (specs, vectors, code) and nothing else — not the PR description, not the author's decision narrative, not this epic's brief. It must reconstruct the design's justification from the artifacts alone; where it cannot, that is itself a finding.

**R-B (spec red leg)** — four passes over the spec PR:

1. **Removal audit** — the minimality test, run in reverse: for every protocol element, argue *for* its deletion. Verify each removal-table attack is concrete (could be encoded as a vector) and actually vectored. Flag rows whose attack is abstract or circular — the "pointless cryptography" smell. Propose simpler elements that would prevent the same attack.
2. **Five Questions** — who knows what, when? who checks what? what can go wrong (can, not would)? what are we assuming? what's the actual primitive? (per `damson` critical-thinking framework).
3. **Attack synthesis** — construct attacks concretely, with tooling: forge envelopes, probe check-order, compose across specs. Report attempted-and-blocked attacks too — negative results are evidence.
4. **Prior-art audit** — anything re-derived in prose that should be a citation; anything invented where a standard construction exists.

**R-C (impl red leg)** — spec↔implementation divergence hunting; vector evasion (inputs the implementation accepts but the spec forbids, and vice versa); panic/DoS paths on hostile input; differential testing against the vector oracle; dependency review.

**Memo format.** Findings classified three ways, mirroring "separate genuine bugs from preferences":

- **Break** — a real attack or spec contradiction. Blocks the gate until fixed.
- **Underpriced** — element survives, but its removal-table row or vector coverage doesn't justify it. Fixed before merge.
- **Preference** — structure/style. Recorded in the memo, never blocks.

Plus an *attacks attempted* table (attack, method, outcome). The memo is posted as a PR comment labeled `R-B memo` / `R-C memo`; the authoring agent triages every finding in a reply (fix, disposition, or argue — arguing a Break escalates it to the human gate rather than dismissing it).

**Mechanics in Cursor**: the authoring session dispatches the red leg as a fresh subagent (or the human runs it as a separate chat). The red agent gets file paths and the memo format, never the rationale. It may write scratch outside the repo; it never commits.

## Decision discipline

- `IMPLEMENTATION_PLAN.md` §2 (locked, L\*) and §3 (open, O\*) are the decision registers. **L\* decisions are not re-litigated**; if evidence demands a change, stop and raise it at the next gate with the evidence — do not code around it.
- **O\* decisions are resolved only at gates**, recorded in the PR under a `## Decisions` heading and moved from §3 to §2 in the same PR.
- A discovery that changes epic scope mid-leg: pause that thread, surface it (gate comment or ask directly). Don't absorb scope silently.

## Branch, commit, PR conventions

- One branch per epic: `epic/<phase>-<slug>` (e.g. `epic/1-bcf-core`). Spec PR and impl PR both come from it (impl PR follows the spec merge; rebase as needed). `main` is protected in spirit: nothing lands except by reviewed PR.
- Conventional commits: `spec(bcf-core): ...`, `feat(bcf-core): ...`, `test(vectors): ...`, `docs(plan): ...`. Spec commits separate from impl commits; refactors separate from features.
- Every PR uses the template: **Decisions** (L/O moved), **Evidence** (test output, vector coverage), **Notes discharged** (N\* items resolved/re-deferred), **Gate** (which gate this PR is).
- Use `gh` for all GitHub operations (issues, PRs, labels).

## Quality gates (mechanical, before any PR)

- Specs: removal table present and current; every normative MUST has a positive + negative vector planned or landed; negative vectors name their attack; deterministic CBOR for everything signed/hashed; cite known constructions, never re-derive them.
- Rust: `cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --all` clean. No `unwrap()` in library code; typed errors (`thiserror`). Reuse `damson-crypto` / `damson-eth` upstream — extend them there rather than vendoring.
- Docs ratchet: touching a file means leaving it better — stale comments fixed, vague names renamed, duplication extracted.

## Session start checklist

1. Read this file, `IMPLEMENTATION_PLAN.md` §2–§4, and the open epic issue.
2. Confirm which **leg** the epic is in (A→B spec, B→C impl, C→D closeout) and work only that leg.
3. If no epic is open: draft the next epic brief (gate A) and stop for approval.
