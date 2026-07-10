# Session Atomicity (stub)

**Status**: stub — scope + vector plan. Normative drafting: Phase 3.
**Sources**: P14 §8.2 (session atomicity as ladder rung 4, L5), P13 §6, P05 (no contestation game, L3).

## Scope

Defines the single prevent-mode primitive in the architecture: an atomic single-hop exchange between two parties on two rails, built from adaptor signatures, wrapped in a signed two-phase-commit evidence trail. Everything outside this hop is detect-mode (see `bcf-chain-and-log.md`).

Normative contents when drafted:

1. **Setup** — what both parties must hold before the hop begins (terms BCF, rail addresses, timeout parameters); the session is itself a BCF chain.
2. **Adaptor-signature exchange** — the single-hop construction over secp256k1: pre-signature issuance, adaptor reveal, completion. Cited as a known construction; the spec fixes message order and encodings, not the cryptography.
3. **Signed-2PC evidence** — prepare/commit/abort messages as BCF claim types, so every transition leaves bilateral evidence; what each party can prove at every possible stopping point.
4. **Abort and timeout semantics** — exact timeout ladder; which party is safe by default in each window; what "safe" means per window (funds-safe vs evidence-safe).
5. **Guarantee statement** — precisely what is guaranteed (hop atomicity between two identified parties) and what is not (no multi-hop routing, no third-party contestation, no global ordering).
6. **Removal table** — per element, the theft, hostage, or evidence-loss scenario its removal enables.

## Out of scope

Multi-hop payment routing (out of S1 scope entirely); watchtowers; channel networks.

## Test-vector plan

| Vector class | What it pins down |
|---|---|
| Happy path | Full transcript: setup → pre-signatures → reveal → completion, all evidence artifacts byte-exact |
| Abort at each phase | One transcript per stopping point; for each, the evidence set each party holds and what it proves |
| Adversarial | Stale pre-signature replay; reveal withheld past timeout; commit message forged without matching prepare evidence |
| Timeout boundaries | Action exactly at window edges; clock-skew tolerance |
