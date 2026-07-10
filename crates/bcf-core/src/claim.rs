//! The claim: the unit of agreement (`specs/bcf-core.md` §2).
//!
//! This module owns the V3 structural check (claim shape, field types and
//! syntax) and the V5 party-set check (well-formed, unique, sorted, ≥2). It
//! imposes only the *syntactic* rules of §2; it never reads meaning into
//! `claim_type`, `prev`, or `predicate` — that is the application's job.

use crate::cbor::{encode, Value};
use crate::error::Error;
use crate::predicate;
use crate::sig::Alg;

/// A party named in the claim's required signer set (§2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Party {
    /// Identity URI (≤ 256 bytes). Binding `id` to `pubkey` is a trust-list
    /// concern outside this spec.
    pub id: String,
    /// Raw public key bytes (32 for Ed25519, 33 for secp256k1 compressed).
    pub pubkey: Vec<u8>,
    /// The algorithm this party signs with.
    pub alg: Alg,
}

/// A fully validated claim (returned once V1–V9 pass).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// Domain separator; `"BCF/1"` for this version.
    pub domain: String,
    /// Application claim type (lowercase, `[a-z0-9:/.-]+`, ≤ 64 bytes).
    pub claim_type: String,
    /// Proposer-chosen 16-byte freshness nonce.
    pub nonce: [u8; 16],
    /// SHA-256 of the opaque application payload.
    pub payload_hash: [u8; 32],
    /// The required signer set (≥ 2, sorted, unique by key).
    pub parties: Vec<Party>,
    /// Predecessor claim hashes; empty for a genesis claim.
    pub prev: Vec<[u8; 32]>,
    /// Optional predicate-identity set.
    pub predicate: Option<Vec<String>>,
}

/// Fields extracted by the V3 structural check, before V5 validates parties.
pub(crate) struct ClaimFields {
    pub domain: String,
    pub claim_type: String,
    pub nonce: [u8; 16],
    pub payload_hash: [u8; 32],
    pub prev: Vec<[u8; 32]>,
    pub predicate: Option<Vec<String>>,
    /// Raw party-entry values, kept so V5 can judge their sort order by encoding.
    pub parties_raw: Vec<Value>,
}

/// V3: the claim is a CBOR map with exactly the keys of §2, correct types and
/// lengths, and valid `claim_type` / `predicate` syntax. Unknown keys are an
/// unagreed field and are rejected.
pub(crate) fn structure(claim: &Value) -> Result<ClaimFields, Error> {
    let map = claim.as_map().ok_or(Error::Structure)?;

    // Exactly keys {1..6} required, {7} optional, nothing else.
    let mut domain = None;
    let mut claim_type = None;
    let mut nonce = None;
    let mut payload_hash = None;
    let mut parties_raw = None;
    let mut prev = None;
    let mut predicate = None;
    for (k, v) in map {
        match k.as_int() {
            Some(1) => domain = Some(text(v)?),
            Some(2) => claim_type = Some(claim_type_field(v)?),
            Some(3) => nonce = Some(fixed_bytes::<16>(v)?),
            Some(4) => payload_hash = Some(fixed_bytes::<32>(v)?),
            Some(5) => parties_raw = Some(v.as_array().ok_or(Error::Structure)?.to_vec()),
            Some(6) => prev = Some(prev_field(v)?),
            Some(7) => predicate = Some(predicate_field(v)?),
            _ => return Err(Error::Structure), // unknown / non-int key
        }
    }
    // Duplicate keys cannot reach here: the canonical decoder requires strictly
    // ascending map keys, so a repeated key is already E_NONCANONICAL (cbor.rs).
    Ok(ClaimFields {
        domain: domain.ok_or(Error::Structure)?,
        claim_type: claim_type.ok_or(Error::Structure)?,
        nonce: nonce.ok_or(Error::Structure)?,
        payload_hash: payload_hash.ok_or(Error::Structure)?,
        prev: prev.ok_or(Error::Structure)?,
        predicate,
        parties_raw: parties_raw.ok_or(Error::Structure)?,
    })
}

/// V5: every party entry has exactly keys {1,2,3} with valid types, alg/pub
/// length agree, the set is unique by key and sorted by encoded entry, and
/// there are at least two parties.
pub(crate) fn parties(parties_raw: &[Value]) -> Result<Vec<Party>, Error> {
    if parties_raw.len() < 2 {
        return Err(Error::Party);
    }

    let mut parties = Vec::with_capacity(parties_raw.len());
    for entry in parties_raw {
        parties.push(party_entry(entry)?);
    }

    // Unique by public key.
    for i in 0..parties.len() {
        for j in (i + 1)..parties.len() {
            if parties[i].pubkey == parties[j].pubkey {
                return Err(Error::Party);
            }
        }
    }

    // Sorted by the deterministic encoding of the entry (§2.2). Canonical CBOR
    // does not reorder array elements, so this check is the sole guard.
    for window in parties_raw.windows(2) {
        if encode(&window[0]) > encode(&window[1]) {
            return Err(Error::Party);
        }
    }

    Ok(parties)
}

/// Parse and validate a single party entry (bcf-core §2.2): a CBOR map with
/// exactly keys {1: id, 2: pub, 3: alg}, alg/pub lengths agreeing, no unknown
/// keys. Exposed so sibling crates (receipts, heads) can embed a single party
/// entry under the same V5 rules rather than re-deriving them.
pub fn party_entry(entry: &Value) -> Result<Party, Error> {
    let map = entry.as_map().ok_or(Error::Party)?;
    let mut id = None;
    let mut pubkey = None;
    let mut alg_id = None;
    for (k, v) in map {
        match k.as_int() {
            Some(1) => id = Some(v.as_text().ok_or(Error::Party)?.to_string()),
            Some(2) => pubkey = Some(v.as_bytes().ok_or(Error::Party)?.to_vec()),
            Some(3) => alg_id = Some(v.as_int().ok_or(Error::Party)?),
            _ => return Err(Error::Party), // unknown / non-int key
        }
    }
    let id = id.ok_or(Error::Party)?;
    let pubkey = pubkey.ok_or(Error::Party)?;
    let alg = Alg::from_cose(alg_id.ok_or(Error::Party)?).ok_or(Error::Party)?;

    if id.len() > 256 {
        return Err(Error::Party);
    }
    // alg and pub length must agree (§2.2).
    if pubkey.len() != alg.pubkey_len() {
        return Err(Error::Party);
    }
    Ok(Party { id, pubkey, alg })
}

// -- field helpers (V3 type/length/syntax checks) --

fn text(v: &Value) -> Result<String, Error> {
    Ok(v.as_text().ok_or(Error::Structure)?.to_string())
}

fn claim_type_field(v: &Value) -> Result<String, Error> {
    let s = v.as_text().ok_or(Error::Structure)?;
    // Non-empty, ≤ 64 bytes, charset [a-z0-9:/.-] — enforced here so that case
    // or exotic-character aliases cannot masquerade as distinct types.
    if s.is_empty() || s.len() > 64 {
        return Err(Error::Structure);
    }
    if !s
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b':' | b'/' | b'.' | b'-'))
    {
        return Err(Error::Structure);
    }
    Ok(s.to_string())
}

fn fixed_bytes<const N: usize>(v: &Value) -> Result<[u8; N], Error> {
    let b = v.as_bytes().ok_or(Error::Structure)?;
    b.try_into().map_err(|_| Error::Structure)
}

fn prev_field(v: &Value) -> Result<Vec<[u8; 32]>, Error> {
    let arr = v.as_array().ok_or(Error::Structure)?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(fixed_bytes::<32>(item)?);
    }
    Ok(out)
}

fn predicate_field(v: &Value) -> Result<Vec<String>, Error> {
    let arr = v.as_array().ok_or(Error::Structure)?;
    if arr.is_empty() {
        return Err(Error::Structure); // present-but-empty is vacuous (§9)
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.as_text().ok_or(Error::Structure)?;
        if !predicate::is_valid_entry(s) {
            return Err(Error::Structure);
        }
        out.push(s.to_string());
    }
    Ok(out)
}
