# Publication procedure and scrub checklist

How the public greengage repository is produced from this private one. Decided at Epic 4 gate A: the public repo is a **fresh repository seeded from a scrubbed snapshot**, with fresh history. This private repository stays private permanently and serves as the provenance archive (full history, PR reviews, red-leg memos, epic issues).

## Why a fresh repo

The private history contains material that must never be public: investor and strategy documents, client-adjacent working notes, and internal review chatter that names engagements. Rewriting history (`git filter-repo`) leaves the burden of proving the rewrite caught everything; a fresh snapshot makes the public tree the *only* thing that ever existed publicly. Publication is a fresh start anyway.

## What ships

The public tree is an allowlist, not a denylist. Only these paths are copied into the snapshot:

```
LICENSE
PROVENANCE.md
README.md
OVERVIEW.md
INTEGRATIONS.md
IMPLEMENTATION_PLAN.md
NOTES_FROM_RESEARCH.md
AGENTS.md
.gitignore
.github/          (CI workflow)
Cargo.toml
specs/            (all, excluding build artifacts)
crates/           (all)
docs/publication.md
```

Explicitly excluded, now and always:

- internal business and site material, in its entirety (the public website is deployed from its own repo)
- commercial analysis: buyer targeting, go-to-market sequencing, pricing, and anything referencing a client, an engagement, or commercial terms. These live in documents outside the allowlist, never inline in the working documents above
- build artifacts (`target/`, `__pycache__/`, `*.pyc`), editor state, credentials of any kind

## Scrub checklist (run per release, signed off before push)

1. **Allowlist sweep.** Build the snapshot from the allowlist above; diff the snapshot tree against the allowlist; anything unexpected fails the release.
2. **Name sweep.** Search the snapshot for client names, engagement codenames, and personal email addresses. The search list is maintained privately (it is itself sensitive); it must be re-run whenever a new engagement starts.
3. **Cross-reference sweep.** Search for paths that leak internal structure: references to `site/`, to sibling private repos other than the cited `damson` research corpus, or to internal strategy documents. Fix the referring text, do not just drop the file.
4. **Claims check.** README, OVERVIEW, and INTEGRATIONS must not claim more than PROVENANCE.md supports (no "audited", no "production-ready", no implied multi-party review).
5. **Link and metadata check.** `Cargo.toml`'s `repository` field, rustdoc links, and any in-doc GitHub links point at the **public** repo URL, not this one. No links into private artifacts (issues, PRs, `site/`).
6. **Fresh-history check.** The public repo is initialized with `git init` in the snapshot directory; it never shares objects with this repo. Verify with `git log --oneline` (single seed commit on first release) and `git remote -v` (public remote only).
7. **Build check.** `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --all` passes in the snapshot on a clean checkout.

## Release cadence

Re-publication is a manual, human-gated action, expected at epic closeouts that change public-facing artifacts. Each release is one commit on the public repo ("sync from provenance archive, <date>, epic N"), so the public history stays a coarse, reviewable sequence of published states.
