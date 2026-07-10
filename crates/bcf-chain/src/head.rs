//! Chain-head publication (`specs/bcf-chain-and-log.md` §6.2).
//!
//! A head is a single-signer COSE_Sign1 commitment to the set of member
//! `claim_hash`es a party attests to for a chain, via an RFC 6962 Merkle root
//! over the sorted, deduplicated member set. Inclusion proofs make withholding
//! attributable; head-fork detection is the across-presentation equivocation
//! guard. Like the rest of the reference crates this is verify-only — the
//! Merkle helpers are pure functions; producing/signing a head is the
//! publisher's job with its own key.

use crate::cose1;
use crate::util::sha256;
use bcf_core::cbor::{decode_canonical, Value};
use bcf_core::{party_entry, Error, Party};

/// The expected chain-head domain separator.
pub const HEAD_DOMAIN: &str = "BCF-HEAD/1";

/// A verified chain head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The chain this head commits to (genesis `claim_hash`).
    pub chain_id: [u8; 32],
    /// The Merkle root over the sorted member set.
    pub root: [u8; 32],
    /// Number of distinct committed leaves — the authoritative tree size,
    /// validated in `verify_head` to fit `u64` (so it binds inclusion proofs
    /// without a lossy conversion at the call site).
    pub count: u64,
    /// Publication time (POSIX seconds).
    pub published_at: i128,
    /// The signer.
    pub publisher: Party,
}

/// The verdict of [`detect_head_fork`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkVerdict {
    /// Two irreconcilable signed views by one publisher for one chain.
    Fork,
    /// Not a fork: equal roots, honest growth, or not comparable.
    NoFork,
}

// -- RFC 6962 Merkle tree over a sorted, deduplicated leaf set --

fn leaf_hash(claim_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(33);
    buf.push(0x00);
    buf.extend_from_slice(claim_hash);
    sha256(&buf)
}

pub(crate) fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(65);
    buf.push(0x01);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

/// Largest power of two strictly less than `n` (RFC 6962 split point), for
/// `n >= 2`. Computed via `leading_zeros` rather than a doubling loop: the loop
/// form shifts its high bit out to zero and never terminates once `n` exceeds
/// `2^(BITS-1)` (R-C Break 1).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// The RFC 6962 §2.1 Merkle root over `leaves`, which MUST already be sorted and
/// deduplicated (the head's canonical leaf order — use [`sorted_dedup`]). The
/// root is order-dependent, so an unsorted slice yields a wrong but confident
/// root; the debug assertion makes that misuse loud in development. The empty
/// set hashes to `SHA-256("")`.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    debug_assert!(
        leaves.windows(2).all(|w| w[0] < w[1]),
        "merkle_root requires sorted, deduplicated leaves",
    );
    match leaves.len() {
        0 => sha256(b""),
        1 => leaf_hash(&leaves[0]),
        n => {
            let k = split(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// Sort and deduplicate member hashes into the head's canonical leaf order.
pub fn sorted_dedup(members: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut v = members.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

/// The RFC 6962 audit-path length for a leaf at `index` in a tree of `size`.
fn audit_path_len(index: u64, size: u64) -> usize {
    if size <= 1 {
        0
    } else {
        let k = split_u64(size);
        if index < k {
            audit_path_len(index, k) + 1
        } else {
            audit_path_len(index - k, size - k) + 1
        }
    }
}

fn split_u64(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1u64 << (u64::BITS - 1 - (n - 1).leading_zeros())
}

/// Verify an RFC 6962 inclusion proof (§6.2 P1–P3). `tree_size` and `root` MUST
/// come from a head that passed [`verify_head`] — never supplied independently.
pub fn verify_inclusion(
    claim_hash: &[u8; 32],
    proof: &[[u8; 32]],
    leaf_index: u64,
    tree_size: u64,
    root: &[u8; 32],
) -> Result<(), Error> {
    // P1 — index in range, proof length matches the tree geometry.
    if leaf_index >= tree_size || proof.len() != audit_path_len(leaf_index, tree_size) {
        return Err(Error::HeadInclusion);
    }
    // P2 — recompute the root from the leaf and the path (RFC 6962 §2.1.1).
    let computed = recompute_root(leaf_hash(claim_hash), leaf_index, tree_size - 1, proof)?;
    // P3 — must equal the committed root.
    if &computed == root {
        Ok(())
    } else {
        Err(Error::HeadInclusion)
    }
}

/// Fold a leaf and its audit path to a root (RFC 6962 §2.1.1). The terminal
/// `sn == 0` check is kept as belt-and-suspenders alongside P1's length check:
/// the path must exactly consume the tree, independent of that precheck.
fn recompute_root(
    leaf: [u8; 32],
    mut fan: u64,
    mut sn: u64,
    proof: &[[u8; 32]],
) -> Result<[u8; 32], Error> {
    let mut r = leaf;
    for p in proof {
        if sn == 0 {
            return Err(Error::HeadInclusion); // path longer than the tree height
        }
        if fan & 1 == 1 || fan == sn {
            r = node_hash(p, &r);
            while fan != 0 && fan & 1 == 0 {
                fan >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fan >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return Err(Error::HeadInclusion); // path shorter than the tree height
    }
    Ok(r)
}

/// Verify a chain head against `expected_domain` (`"BCF-HEAD/1"`), mirroring the
/// receipt's R1–R5 with head body keys {1..6}.
pub fn verify_head(bytes: &[u8], expected_domain: &str) -> Result<Head, Error> {
    let sign1 = cose1::parse(bytes)?;

    let body = decode_canonical(&sign1.payload)?;
    let map = body.as_map().ok_or(Error::HeadStructure)?;
    let mut domain = None;
    let mut chain_id = None;
    let mut root = None;
    let mut count = None;
    let mut published_at = None;
    let mut publisher_value = None;
    for (k, v) in map {
        match k.as_int() {
            Some(1) => domain = Some(v.as_text().ok_or(Error::HeadStructure)?.to_string()),
            Some(2) => chain_id = Some(fixed32(v)?),
            Some(3) => root = Some(fixed32(v)?),
            Some(4) => count = Some(v.as_int().ok_or(Error::HeadStructure)?),
            Some(5) => published_at = Some(v.as_int().ok_or(Error::HeadStructure)?),
            Some(6) => publisher_value = Some(v.clone()),
            _ => return Err(Error::HeadStructure),
        }
    }
    let domain = domain.ok_or(Error::HeadStructure)?;
    let chain_id = chain_id.ok_or(Error::HeadStructure)?;
    let root = root.ok_or(Error::HeadStructure)?;
    // count is the authoritative tree size: it MUST be a non-negative integer
    // that fits u64, or a forged count later reshapes inclusion-proof geometry.
    let count =
        u64::try_from(count.ok_or(Error::HeadStructure)?).map_err(|_| Error::HeadStructure)?;
    let published_at = published_at.ok_or(Error::HeadStructure)?;
    let publisher_value = publisher_value.ok_or(Error::HeadStructure)?;

    if domain != expected_domain {
        return Err(Error::HeadDomain);
    }

    let publisher = party_entry(&publisher_value).map_err(|_| Error::HeadStructure)?;
    let (alg_id, kid) = cose1::protected_alg_kid(&sign1, Error::HeadStructure)?;
    if alg_id != publisher.alg.cose_id() || kid != sha256(&publisher.pubkey) {
        return Err(Error::HeadStructure);
    }
    if !cose1::signature_ok(&sign1, publisher.alg, &publisher.pubkey) {
        return Err(Error::HeadSig);
    }

    Ok(Head {
        chain_id,
        root,
        count,
        published_at,
        publisher,
    })
}

/// Detect a head-level fork (§6.2 F1–F4). The member lists are attacker-supplied
/// and pinned to the signed roots (F3) before any superset reasoning.
pub fn detect_head_fork(
    head_a: &[u8],
    members_a: &[[u8; 32]],
    head_b: &[u8],
    members_b: &[[u8; 32]],
    expected_domain: &str,
) -> Result<ForkVerdict, Error> {
    // F1 — both heads verify.
    let a = verify_head(head_a, expected_domain)?;
    let b = verify_head(head_b, expected_domain)?;

    // F2 — one party's two stories about one chain, or not comparable.
    if a.chain_id != b.chain_id || a.publisher.pubkey != b.publisher.pubkey {
        return Ok(ForkVerdict::NoFork);
    }

    // F3 — each presented member list must hash to its signed root.
    let leaves_a = sorted_dedup(members_a);
    let leaves_b = sorted_dedup(members_b);
    if merkle_root(&leaves_a) != a.root || merkle_root(&leaves_b) != b.root {
        return Err(Error::HeadStructure);
    }

    // F4 — equal roots or an honest superset are not forks.
    if a.root == b.root || is_superset(&leaves_a, &leaves_b) || is_superset(&leaves_b, &leaves_a) {
        Ok(ForkVerdict::NoFork)
    } else {
        Ok(ForkVerdict::Fork)
    }
}

/// True if `big` contains every element of `small` (both sorted-deduplicated).
fn is_superset(big: &[[u8; 32]], small: &[[u8; 32]]) -> bool {
    small.iter().all(|x| big.binary_search(x).is_ok())
}

fn fixed32(v: &Value) -> Result<[u8; 32], Error> {
    v.as_bytes()
        .ok_or(Error::HeadStructure)?
        .try_into()
        .map_err(|_| Error::HeadStructure)
}
