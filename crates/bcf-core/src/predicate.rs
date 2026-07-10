//! Predicate-identity syntax (`specs/bcf-core.md` §9).
//!
//! The `predicate` field binds an agreement to specific computation(s). Only
//! three schemes are valid, and the verifier enforces the whitelist at V3 —
//! notably `tee:` is rejected, because a TEE measurement attests *where* code
//! ran, not *what* the algorithm is (it belongs in an Attest payload, not as
//! algorithm identity). Registry/resolution of these URIs is out of scope (O5).

/// Accepted predicate URI scheme prefixes.
const SCHEMES: [&str; 3] = ["src:", "unison:", "oci:"];

/// Maximum length of a single predicate entry, in bytes.
const MAX_ENTRY_LEN: usize = 256;

/// True if `entry` is a syntactically valid predicate URI for the profile:
/// a known scheme prefix followed by non-empty content, within the length cap.
/// A bare scheme (`"src:"`) asserts the identity of nothing and is rejected.
pub fn is_valid_entry(entry: &str) -> bool {
    entry.len() <= MAX_ENTRY_LEN
        && SCHEMES
            .iter()
            .any(|s| entry.len() > s.len() && entry.starts_with(s))
}
