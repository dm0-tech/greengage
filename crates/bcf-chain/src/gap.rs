//! Gap-detection (`specs/bcf-chain-and-log.md` §6.1).
//!
//! A holder-side utility: over the set of artifacts a party holds, a **gap** is
//! any predecessor referenced by a held artifact that the party does not hold
//! and has not accepted as an external reference. Gaps drive retransmission
//! requests; an unresolved gap is not by itself attributable (§6.1 asymmetry).

use bcf_core::{verify_bcf, Error};
use std::collections::HashSet;

/// Return the sorted, deduplicated set of predecessor hashes referenced by the
/// held artifacts but neither held nor listed in `external_refs`. Every
/// envelope must be a valid BCF artifact (propagates the first failure).
pub fn find_gaps(
    envelopes: &[Vec<u8>],
    expected_domain: &str,
    external_refs: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, Error> {
    let mut held: HashSet<[u8; 32]> = HashSet::new();
    let mut referenced: Vec<[u8; 32]> = Vec::new();
    for envelope in envelopes {
        let verified = verify_bcf(envelope, expected_domain, None)?;
        held.insert(verified.claim_hash);
        referenced.extend(verified.claim.prev);
    }
    let mut gaps: Vec<[u8; 32]> = referenced
        .into_iter()
        .filter(|p| !held.contains(p) && !external_refs.contains(p))
        .collect();
    gaps.sort_unstable();
    gaps.dedup();
    Ok(gaps)
}
