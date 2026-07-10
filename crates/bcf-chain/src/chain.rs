//! Chain verification (`specs/bcf-chain-and-log.md` §2–§5, checks C1–C4).
//!
//! A chain is a per-author hash-linked DAG: each claim's `prev` carries the
//! `claim_hash`es of its predecessors. Verification is detect-mode — it proves
//! misbehaviour, it does not prevent it. The two subtle decisions encoded here
//! are the member/import partition (C2) and the strict equivocation rule (C4):
//! any signer on two distinct claims that share a predecessor.
//!
//! Moved verbatim from `bcf-core` in the Epic 2 crate split; it now reaches the
//! single-artifact verifier through the public `bcf_core` API.

use bcf_core::{verify_bcf, Error};
use std::collections::HashSet;

/// The chain-relevant facts of one verified artifact.
struct Artifact {
    hash: [u8; 32],
    prev: Vec<[u8; 32]>,
    pubkeys: Vec<Vec<u8>>,
}

/// Verify a set of BCF artifacts as a chain rooted at `chain_id`.
///
/// `external_refs` lists predecessor hashes the caller accepts as legitimately
/// absent (caller policy, not a default). Returns the first `E_*` failure in
/// C1–C4 order, or `Ok(())`.
pub fn verify_chain(
    envelopes: &[Vec<u8>],
    chain_id: &[u8; 32],
    expected_domain: &str,
    external_refs: &[[u8; 32]],
) -> Result<(), Error> {
    // C1 — every artifact (members and imports alike) is a valid BCF artifact.
    let mut artifacts = Vec::with_capacity(envelopes.len());
    for envelope in envelopes {
        let verified = verify_bcf(envelope, expected_domain, None)?;
        artifacts.push(Artifact {
            hash: verified.claim_hash,
            prev: verified.claim.prev,
            pubkeys: verified
                .claim
                .parties
                .into_iter()
                .map(|p| p.pubkey)
                .collect(),
        });
    }

    // §2 structural — a claim must not list the same predecessor twice.
    for a in &artifacts {
        for i in 0..a.prev.len() {
            for j in (i + 1)..a.prev.len() {
                if a.prev[i] == a.prev[j] {
                    return Err(Error::ChainStructure);
                }
            }
        }
    }

    // C2 — exactly one input artifact matches chain_id, and it is a genesis.
    let mut matches = artifacts.iter().filter(|a| &a.hash == chain_id);
    let genesis = matches.next().ok_or(Error::ChainRoot)?;
    if matches.next().is_some() {
        return Err(Error::ChainRoot); // chain_id matched more than once
    }
    if !genesis.prev.is_empty() {
        return Err(Error::ChainRoot); // matched, but not a genesis
    }

    let members = compute_members(&artifacts, chain_id);

    // An artifact referenced by a member's prev but not itself a member is an
    // import; an artifact that is neither is unrelated to this chain.
    let mut referenced_by_members: HashSet<[u8; 32]> = HashSet::new();
    for a in &artifacts {
        if members.contains(&a.hash) {
            referenced_by_members.extend(a.prev.iter().copied());
        }
    }
    for a in &artifacts {
        let is_member = members.contains(&a.hash);
        let is_import = !is_member && referenced_by_members.contains(&a.hash);
        if !is_member && !is_import {
            return Err(Error::ChainUnreachable);
        }
    }

    // C3 — every member's prev resolves to an input artifact or external_refs.
    // Imports' prev entries are foreign context and are exempt.
    let input_hashes: HashSet<[u8; 32]> = artifacts.iter().map(|a| a.hash).collect();
    for a in &artifacts {
        if !members.contains(&a.hash) {
            continue;
        }
        for p in &a.prev {
            if !input_hashes.contains(p) && !external_refs.contains(p) {
                return Err(Error::ChainGap);
            }
        }
    }

    // C4 — no equivocation: no signer appears on two distinct claims that
    // share a predecessor entry.
    check_equivocation(&artifacts)?;

    Ok(())
}

/// Least fixpoint of "reaches the genesis via prev edges": the genesis, plus
/// any artifact with a predecessor already known to be a member. Bounded by the
/// artifact count (each pass adds at least one member, or halts).
fn compute_members(artifacts: &[Artifact], chain_id: &[u8; 32]) -> HashSet<[u8; 32]> {
    let mut members: HashSet<[u8; 32]> = HashSet::new();
    members.insert(*chain_id);
    loop {
        let mut added = false;
        for a in artifacts {
            if members.contains(&a.hash) {
                continue;
            }
            if a.prev.iter().any(|p| members.contains(p)) {
                members.insert(a.hash);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    members
}

/// C4 / §5: equivocation is any signer whose key appears on two distinct claims
/// (by hash) that share at least one predecessor entry. Type and role are
/// irrelevant by design — that is what makes the rule evasion-proof.
fn check_equivocation(artifacts: &[Artifact]) -> Result<(), Error> {
    // Distinct claims only: same hash is the same claim, not equivocation.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut distinct: Vec<&Artifact> = Vec::new();
    for a in artifacts {
        if seen.insert(a.hash) {
            distinct.push(a);
        }
    }

    for i in 0..distinct.len() {
        for j in (i + 1)..distinct.len() {
            if shares_prev_entry(distinct[i], distinct[j])
                && shares_signer(distinct[i], distinct[j])
            {
                return Err(Error::Equivocation);
            }
        }
    }
    Ok(())
}

fn shares_prev_entry(a: &Artifact, b: &Artifact) -> bool {
    a.prev.iter().any(|p| b.prev.contains(p))
}

fn shares_signer(a: &Artifact, b: &Artifact) -> bool {
    a.pubkeys.iter().any(|k| b.pubkeys.contains(k))
}
