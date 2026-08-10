# Test Vectors

These vectors are the conformance ground truth for the spec suite. An implementation conforms to a specification only if it passes that specification's vectors. The Rust crates under `crates/` have no authority beyond passing them.

## Status

Vectors land with their specifications, phase by phase (`IMPLEMENTATION_PLAN.md` §4). The `bcf-core/` and `bcf-chain-and-log/` sets are complete for their frozen sections. A specification is not *frozen* until its vector set exists and has been cross-checked.

## Layout (one directory per spec, populated in its phase)

```
test-vectors/
├── bcf-core/              # Phase 1
├── bcf-chain-and-log/     # Phases 1–2
├── session-atomicity/     # Phase 3
├── tgs/                   # Phase 4
└── tgs-over-http/         # Phase 4
```

## Rules

1. **Format**: each vector is a JSON file with a `description`, `inputs` (hex/base64-encoded byte strings for all binary material, including any CBOR), an `expected` outcome, and for negative vectors an `attack` field.
2. **Negative vectors name their attack.** The `attack` field states the concrete attack the vector encodes, mirroring the spec's removal-table row. A negative vector without an attack name is rejected in review.
3. **Coverage**: every normative MUST has at least one positive and one negative vector. Coverage is tracked in each spec's test-vector plan table.
4. **Determinism**: all signed/hashed structures appear as exact bytes (golden vectors). Keys used in vectors are fixed, documented test keys — never real ones.
5. **Cross-checking**: where an independent implementation of an underlying standard exists (COSE, deterministic CBOR, RFC 9421), at least one vector per spec is generated or verified with it, not with the reference implementation.
