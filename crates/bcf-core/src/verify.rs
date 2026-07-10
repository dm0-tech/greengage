//! The verification procedure (`specs/bcf-core.md` §8).
//!
//! This is the project's reviewer artifact: the V1–V9 checks run in spec order,
//! top to bottom, each labelled with its V-number, stopping at the first
//! failure. The order is normative — each step may rely on everything before
//! it, and the conformance vectors pin which error a given bad input yields.

use crate::cbor::{self, Value};
use crate::claim::{self, Claim, Party};
use crate::envelope::{self, Envelope, SignatureEntry};
use crate::error::Error;
use crate::sig;
use sha2::{Digest, Sha256};

/// A verified artifact: the decoded claim and its identity hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The validated claim.
    pub claim: Claim,
    /// `SHA-256(claim_bytes)` — the identity of the agreement (§4).
    pub claim_hash: [u8; 32],
}

/// Verify a BCF artifact against `expected_domain`, optionally checking that
/// `payload` is the committed payload. Returns the claim and its hash, or the
/// first `E_*` failure in V1–V9 order.
pub fn verify_bcf(
    envelope_bytes: &[u8],
    expected_domain: &str,
    payload: Option<&[u8]>,
) -> Result<Verified, Error> {
    // V1 — decode the envelope and every nested bstr .cbor protected header.
    let env: Envelope = envelope::parse(envelope_bytes)?;

    // V2 — body protected header, empty unprotected maps, non-nil payload.
    if !envelope::is_body_protected_ok(&env.body_protected) {
        return Err(Error::Envelope);
    }
    if !envelope::is_empty_map(&env.body_unprotected) {
        return Err(Error::Envelope);
    }
    let claim_bytes = match &env.payload {
        Some(bytes) => bytes,
        None => return Err(Error::Envelope), // detached payload not allowed
    };

    // V3 — claim decodes canonically and has exactly the structure of §2.
    let claim_value = cbor::decode_canonical(claim_bytes)?;
    let fields = claim::structure(&claim_value)?;

    // V4 — domain separator matches the caller's expectation.
    if fields.domain != expected_domain {
        return Err(Error::Domain);
    }

    // V5 — party set well-formed, unique, sorted, ≥ 2.
    let parties: Vec<Party> = claim::parties(&fields.parties_raw)?;

    // V6 — signatures correspond 1:1 to parties via kid = SHA-256(pub).
    let sig_for_party = match_signatures(&parties, &env.signatures)?;

    // V7 — every signature's headers conform; alg equals the party's claim alg.
    // V8 — every signature verifies over the Sig_structure. The two are
    // distinct ordered steps: all headers are checked before any crypto, so a
    // header fault on one signature outranks a crypto fault on another.
    for (party_idx, sig_idx) in sig_for_party.iter().enumerate() {
        check_signature_headers(&env.signatures[*sig_idx], &parties[party_idx])?;
        // V7
    }
    for (party_idx, sig_idx) in sig_for_party.iter().enumerate() {
        verify_signature(
            &env,
            claim_bytes,
            &env.signatures[*sig_idx],
            &parties[party_idx],
        )?; // V8
    }

    // V9 — if a payload was supplied, it must hash to claim.payload_hash.
    if let Some(payload) = payload {
        if sha256(payload) != fields.payload_hash {
            return Err(Error::PayloadHash);
        }
    }

    Ok(Verified {
        claim: Claim {
            domain: fields.domain,
            claim_type: fields.claim_type,
            nonce: fields.nonce,
            payload_hash: fields.payload_hash,
            parties,
            prev: fields.prev,
            predicate: fields.predicate,
        },
        claim_hash: sha256(claim_bytes),
    })
}

/// V6: match each signature to a party by `kid = SHA-256(pub)`. Returns, for
/// each party (by index), the index of its signature. A signature matching no
/// party, or a party matched twice, is `E_SIG_EXTRA`; an unmatched party is
/// `E_SIG_MISSING`.
fn match_signatures(parties: &[Party], signatures: &[SignatureEntry]) -> Result<Vec<usize>, Error> {
    let kids: Vec<[u8; 32]> = parties.iter().map(|p| sha256(&p.pubkey)).collect();
    let mut sig_for_party: Vec<Option<usize>> = vec![None; parties.len()];

    for (sig_idx, entry) in signatures.iter().enumerate() {
        let kid = signature_kid(&entry.protected).ok_or(Error::SigExtra)?;
        let party_idx = kids.iter().position(|k| k == &kid).ok_or(Error::SigExtra)?;
        if sig_for_party[party_idx].is_some() {
            return Err(Error::SigExtra); // party signed for twice
        }
        sig_for_party[party_idx] = Some(sig_idx);
    }

    sig_for_party
        .into_iter()
        .map(|opt| opt.ok_or(Error::SigMissing))
        .collect()
}

/// V7: the protected header has exactly keys {1: alg, 4: kid, 15: {6: iat}}, the
/// unprotected header is empty, and the header `alg` equals the party's claim
/// `alg`. Header-shape problems are `E_HEADER`; the alg mismatch is `E_ALG`.
fn check_signature_headers(entry: &SignatureEntry, party: &Party) -> Result<(), Error> {
    if !envelope::is_empty_map(&entry.unprotected) {
        return Err(Error::Header);
    }
    let map = entry.protected.as_map().ok_or(Error::Header)?;
    if map.len() != 3 {
        return Err(Error::Header);
    }

    let mut alg_id = None;
    let mut has_kid = false;
    let mut has_iat = false;
    for (k, v) in map {
        match k.as_int() {
            Some(1) => alg_id = Some(v.as_int().ok_or(Error::Header)?),
            Some(4) => {
                v.as_bytes().ok_or(Error::Header)?;
                has_kid = true;
            }
            Some(15) => {
                // The CWT-claims map is exactly {6: iat} — no extra parameters.
                let cwt = v.as_map().ok_or(Error::Header)?;
                match cwt {
                    [(ck, cv)] if ck.as_int() == Some(6) => {
                        cv.as_int().ok_or(Error::Header)?;
                    }
                    _ => return Err(Error::Header),
                }
                has_iat = true;
            }
            _ => return Err(Error::Header), // unknown header parameter
        }
    }
    if !has_kid || !has_iat {
        return Err(Error::Header);
    }

    // alg is taken from the claim (which every party signed); the header copy
    // must agree, or verification could run under a different scheme (V7→E_ALG).
    if alg_id != Some(party.alg.cose_id()) {
        return Err(Error::Alg);
    }
    Ok(())
}

/// V8: the signature verifies over the RFC 9052 Sig_structure for context
/// "Signature", with empty external_aad and the claim bytes as payload.
fn verify_signature(
    env: &Envelope,
    claim_bytes: &[u8],
    entry: &SignatureEntry,
    party: &Party,
) -> Result<(), Error> {
    let sig_structure = cbor::encode(&Value::Array(vec![
        Value::Text("Signature".to_string()),
        Value::Bytes(env.body_protected_bytes.clone()),
        Value::Bytes(entry.protected_bytes.clone()),
        Value::Bytes(Vec::new()), // external_aad MUST be empty
        Value::Bytes(claim_bytes.to_vec()),
    ]));
    sig::verify(party.alg, &party.pubkey, &sig_structure, &entry.signature)
}

/// Read the `kid` (protected header key 4) for V6 matching.
fn signature_kid(protected: &Value) -> Option<[u8; 32]> {
    protected
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_int() == Some(4))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|b| b.try_into().ok())
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
