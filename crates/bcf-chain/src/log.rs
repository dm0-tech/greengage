//! Witnessed-log client (`specs/bcf-chain-and-log.md` §6.3, ladder rung 3).
//!
//! §6.2 left two gaps: a publisher can equivocate *between* head publications
//! (the cadence window), and head-fork detection needs the attacker-supplied
//! member lists. Rung 3 closes both by binding a publisher to one
//! monotonically-growing history that independent witnesses vouch for — the
//! transparency-log pattern (RFC 6962; Sigsum). This is a **client**: it verifies
//! checkpoints, consistency proofs, and witness co-signatures, and detects split
//! views. Operating the log or the witnesses is deployment, not this crate, so —
//! like the rest of bcf-chain — everything here is verify-only.
//!
//! The witness set and threshold are *caller policy* (§6.3.5): the client only
//! enforces the format and the distinct-witness count. A caller trusting a set of
//! `threshold` witnesses inherits that trust assumption.

use crate::cose1;
use crate::head::{node_hash, ForkVerdict};
use crate::util::sha256;
use bcf_core::cbor::{decode_canonical, Value};
use bcf_core::{party_entry, Error, Party};

/// The expected checkpoint domain separator.
pub const CKPT_DOMAIN: &str = "BCF-CKPT/1";
/// The expected witness co-signature domain separator.
pub const COSIG_DOMAIN: &str = "BCF-COSIG/1";

/// A witnessed checkpoint (a signed tree head over a publisher's head-log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The chain whose head-log this checkpoint commits to.
    pub chain_id: [u8; 32],
    /// Number of head leaves (epochs) the log has published.
    pub tree_size: u64,
    /// RFC 6962 root over the head leaves, in epoch order.
    pub log_root: [u8; 32],
    /// Checkpoint time (POSIX seconds; advisory).
    pub published_at: i128,
    /// The log owner and signer — half of the log identity `(publisher, chain)`.
    pub publisher: Party,
}

/// Verify a witnessed checkpoint (§6.3.4, W1–W4). On success the checkpoint's
/// `tree_size`/`log_root` are safe to bind inclusion and consistency proofs to;
/// before that they are attacker-controlled and MUST NOT be trusted.
///
/// `witness_set` and `threshold` are caller policy (§6.3.5). A co-signature
/// counts toward the threshold only if it is a valid `"BCF-COSIG/1"` COSE_Sign1
/// that binds *this* checkpoint by hash, signed by a key in `witness_set` that is
/// not the publisher; counting is by distinct `witness.pub`, so a Sybil-of-one
/// (several co-signatures from one witness) cannot manufacture a quorum.
///
/// `threshold` is caller policy in the literal sense: choosing `0` opts out of
/// witnessing entirely (any well-formed checkpoint then satisfies W4). The
/// `cosignatures` slice is a caller-bounded resource — each structurally valid
/// entry costs one signature verification — so callers should cap untrusted
/// bundles.
pub fn verify_checkpoint(
    checkpoint_bytes: &[u8],
    expected_domain: &str,
    cosignatures: &[Vec<u8>],
    witness_set: &[Vec<u8>],
    threshold: usize,
) -> Result<Checkpoint, Error> {
    // W1 — COSE_Sign1 envelope, deterministic CBOR, tag 18, unprotected empty.
    let sign1 = cose1::parse(checkpoint_bytes)?;

    // W1 — body is a deterministic-CBOR map with exactly keys {1..6}.
    let body = decode_canonical(&sign1.payload)?;
    let map = body.as_map().ok_or(Error::CkptStructure)?;
    let mut domain = None;
    let mut chain_id = None;
    let mut tree_size = None;
    let mut log_root = None;
    let mut published_at = None;
    let mut publisher_value = None;
    for (k, v) in map {
        match k.as_int() {
            Some(1) => domain = Some(v.as_text().ok_or(Error::CkptStructure)?.to_string()),
            Some(2) => chain_id = Some(fixed32(v)?),
            Some(3) => tree_size = Some(v.as_int().ok_or(Error::CkptStructure)?),
            Some(4) => log_root = Some(fixed32(v)?),
            Some(5) => published_at = Some(v.as_int().ok_or(Error::CkptStructure)?),
            Some(6) => publisher_value = Some(v.clone()),
            _ => return Err(Error::CkptStructure),
        }
    }
    let domain = domain.ok_or(Error::CkptStructure)?;
    let chain_id = chain_id.ok_or(Error::CkptStructure)?;
    // tree_size is the authoritative log size: a negative or oversized value must
    // be rejected here, before it can drive the Merkle/consistency recursion.
    let tree_size =
        u64::try_from(tree_size.ok_or(Error::CkptStructure)?).map_err(|_| Error::CkptStructure)?;
    let log_root = log_root.ok_or(Error::CkptStructure)?;
    let published_at = published_at.ok_or(Error::CkptStructure)?;
    let publisher_value = publisher_value.ok_or(Error::CkptStructure)?;

    // W1 (cont) — publisher well-formed (bcf-core V5 single entry); header binds.
    // §6.3.4 places these in W1, ahead of the W2 domain check (unlike receipts/
    // heads, whose spec orders domain first): a checkpoint that is both
    // wrong-domain and malformed-publisher must fail as E_CKPT_STRUCTURE.
    let publisher = party_entry(&publisher_value).map_err(|_| Error::CkptStructure)?;
    let (alg_id, kid) = cose1::protected_alg_kid(&sign1, Error::CkptStructure)?;
    if alg_id != publisher.alg.cose_id() || kid != sha256(&publisher.pubkey) {
        return Err(Error::CkptStructure);
    }

    // W2 — domain separator.
    if domain != expected_domain {
        return Err(Error::CkptDomain);
    }

    // W3 — publisher signature verifies (ES256K low-s enforced in bcf-core::sig).
    if !cose1::signature_ok(&sign1, publisher.alg, &publisher.pubkey) {
        return Err(Error::CkptSig);
    }

    // W4 — at least `threshold` distinct in-set non-publisher witnesses, each
    // binding this checkpoint by content. Non-counting co-signatures (bad shape,
    // wrong domain, wrong binding, out of set, self-witness) are silently skipped
    // — a hostile co-signature bundle weakens to "not enough witnesses", never an
    // exploitable accept.
    let checkpoint_hash = sha256(checkpoint_bytes);
    let mut distinct: Vec<Vec<u8>> = Vec::new();
    for cosig in cosignatures {
        if let Some(witness_pub) =
            counting_witness(cosig, &checkpoint_hash, witness_set, &publisher.pubkey)
        {
            if !distinct.contains(&witness_pub) {
                distinct.push(witness_pub);
            }
        }
    }
    if distinct.len() < threshold {
        return Err(Error::CkptWitness);
    }

    Ok(Checkpoint {
        chain_id,
        tree_size,
        log_root,
        published_at,
        publisher,
    })
}

/// If `cosig_bytes` is a co-signature that counts toward the threshold for the
/// checkpoint identified by `checkpoint_hash`, return the witness public key;
/// otherwise `None`. Counting requires (§6.3.4 W4): a valid COSE_Sign1; a
/// `"BCF-COSIG/1"` body with exactly keys {1..4} binding this `checkpoint_hash`;
/// a header that binds the witness key; a verifying witness signature; and a
/// witness that is in `witness_set` but is not the publisher.
fn counting_witness(
    cosig_bytes: &[u8],
    checkpoint_hash: &[u8; 32],
    witness_set: &[Vec<u8>],
    publisher_pub: &[u8],
) -> Option<Vec<u8>> {
    let sign1 = cose1::parse(cosig_bytes).ok()?;
    let body = decode_canonical(&sign1.payload).ok()?;
    let map = body.as_map()?;
    let mut domain = None;
    let mut bound_hash = None;
    let mut witness_value = None;
    let mut has_observed_at = false;
    for (k, v) in map {
        match k.as_int() {
            Some(1) => domain = Some(v.as_text()?.to_string()),
            Some(2) => bound_hash = Some(<[u8; 32]>::try_from(v.as_bytes()?).ok()?),
            Some(3) => witness_value = Some(v.clone()),
            Some(4) => {
                v.as_int()?;
                has_observed_at = true;
            }
            _ => return None,
        }
    }
    if domain.as_deref() != Some(COSIG_DOMAIN) || !has_observed_at {
        return None;
    }
    // Content binding: a co-signature for another checkpoint cannot be transplanted.
    if bound_hash? != *checkpoint_hash {
        return None;
    }
    let witness = party_entry(&witness_value?).ok()?;
    let (alg_id, kid) = cose1::protected_alg_kid(&sign1, Error::CkptWitness).ok()?;
    if alg_id != witness.alg.cose_id() || kid != sha256(&witness.pubkey) {
        return None;
    }
    if !cose1::signature_ok(&sign1, witness.alg, &witness.pubkey) {
        return None;
    }
    // Independence: the publisher cannot witness itself, even if mis-listed in
    // the set; and only keys the caller trusts count.
    if witness.pubkey.as_slice() == publisher_pub {
        return None;
    }
    if !witness_set
        .iter()
        .any(|w| w.as_slice() == witness.pubkey.as_slice())
    {
        return None;
    }
    Some(witness.pubkey.clone())
}

/// Verify an RFC 6962 §2.1.2 consistency proof that the size-`old_size` head-log
/// is a prefix of the size-`new_size` head-log (§6.3.2). `old_root`/`new_root`
/// and the sizes MUST come from checkpoints that passed [`verify_checkpoint`] —
/// never supplied independently, or the proof attests to nothing.
///
/// Boundaries: a shrunk log (`old_size > new_size`) is never consistent; the
/// empty log is a prefix of anything (empty proof); equal sizes require equal
/// roots and an empty proof. Otherwise the standard CT folding algorithm
/// reconstructs both roots from the proof and checks them against the inputs.
pub fn verify_log_consistency(
    old_size: u64,
    old_root: &[u8; 32],
    new_size: u64,
    new_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> Result<(), Error> {
    if old_size > new_size {
        return Err(Error::LogConsistency);
    }
    if old_size == new_size {
        return ok_if(proof.is_empty() && old_root == new_root);
    }
    if old_size == 0 {
        // The empty tree is a prefix of every tree; the proof carries nothing.
        return ok_if(proof.is_empty());
    }

    // 0 < old_size < new_size — RFC 6962 §2.1.2 verification (transparency-log
    // standard counterpart to the prover in the vector oracle).
    let mut node = old_size - 1;
    let mut last = new_size - 1;
    while node & 1 == 1 {
        node >>= 1;
        last >>= 1;
    }

    let mut path = proof.iter();
    // When `node` is non-zero the old tree is not a left-complete subtree, so its
    // root is reconstructed from the proof's seed; otherwise the seed is old_root.
    let (mut old_hash, mut new_hash) = if node != 0 {
        let seed = *path.next().ok_or(Error::LogConsistency)?;
        (seed, seed)
    } else {
        (*old_root, *old_root)
    };

    while node != 0 {
        if node & 1 == 1 {
            let sib = path.next().ok_or(Error::LogConsistency)?;
            old_hash = node_hash(sib, &old_hash);
            new_hash = node_hash(sib, &new_hash);
        } else if node < last {
            let sib = path.next().ok_or(Error::LogConsistency)?;
            new_hash = node_hash(&new_hash, sib);
        }
        // node == last: a left child with no right sibling — consume nothing.
        node >>= 1;
        last >>= 1;
    }
    while last != 0 {
        let sib = path.next().ok_or(Error::LogConsistency)?;
        new_hash = node_hash(&new_hash, sib);
        last >>= 1;
    }
    // Reject leftover proof nodes: the proof must be exactly the tree geometry.
    if path.next().is_some() {
        return Err(Error::LogConsistency);
    }
    ok_if(&old_hash == old_root && &new_hash == new_root)
}

/// Detect cross-presentation equivocation between two checkpoints (§6.3.4,
/// L1–L3). Both checkpoints MUST be witnessed first (each passes W1–W4 with its
/// own co-signatures); a checkpoint that fails verification is an error, not a
/// `no-fork`. The verdict is detect-mode: a `Fork` is accountable evidence, never
/// a prevention.
///
/// L1 — different `(publisher, chain)` are unrelated logs (`NoFork`). L2 — same
/// size with different roots is a `Fork`. L3 — different sizes are a `Fork` unless
/// `consistency_proof` bridges the smaller into the larger; an absent or failing
/// proof *is* the fork evidence.
#[allow(clippy::too_many_arguments)]
pub fn detect_log_equivocation(
    checkpoint_a: &[u8],
    cosignatures_a: &[Vec<u8>],
    checkpoint_b: &[u8],
    cosignatures_b: &[Vec<u8>],
    consistency_proof: &[[u8; 32]],
    expected_domain: &str,
    witness_set: &[Vec<u8>],
    threshold: usize,
) -> Result<ForkVerdict, Error> {
    let a = verify_checkpoint(
        checkpoint_a,
        expected_domain,
        cosignatures_a,
        witness_set,
        threshold,
    )?;
    let b = verify_checkpoint(
        checkpoint_b,
        expected_domain,
        cosignatures_b,
        witness_set,
        threshold,
    )?;

    // L1 — one publisher's two stories about one chain, or not comparable.
    if a.publisher.pubkey != b.publisher.pubkey || a.chain_id != b.chain_id {
        return Ok(ForkVerdict::NoFork);
    }

    // L2 — same epoch count: divergent roots are an outright fork.
    if a.tree_size == b.tree_size {
        return Ok(if a.log_root == b.log_root {
            ForkVerdict::NoFork
        } else {
            ForkVerdict::Fork
        });
    }

    // L3 — different sizes: honest growth iff the smaller is a prefix of the larger.
    let (lo_size, lo_root, hi_size, hi_root) = if a.tree_size < b.tree_size {
        (a.tree_size, a.log_root, b.tree_size, b.log_root)
    } else {
        (b.tree_size, b.log_root, a.tree_size, a.log_root)
    };
    match verify_log_consistency(lo_size, &lo_root, hi_size, &hi_root, consistency_proof) {
        Ok(()) => Ok(ForkVerdict::NoFork),
        Err(_) => Ok(ForkVerdict::Fork),
    }
}

fn ok_if(cond: bool) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::LogConsistency)
    }
}

fn fixed32(v: &Value) -> Result<[u8; 32], Error> {
    v.as_bytes()
        .ok_or(Error::CkptStructure)?
        .try_into()
        .map_err(|_| Error::CkptStructure)
}
