//! COSE_Sign1 (RFC 9052 §4.2, CBOR tag 18) — the single-signer envelope shared
//! by receipts (§6.1) and chain heads (§6.2).
//!
//! Distinct from bcf-core's COSE_Sign (tag 98, context "Signature", ≥2 signers):
//! here there is exactly one signer, the Sig_structure context is "Signature1",
//! and there is no per-signature protected header — the body protected header is
//! the signer's. We build it directly on bcf-core's deterministic CBOR so the
//! signed bytes are byte-exact.

use bcf_core::cbor::{decode_canonical, encode, Value};
use bcf_core::sig::{verify, Alg};
use bcf_core::Error;

/// A parsed COSE_Sign1 message.
pub struct Sign1 {
    /// Decoded protected header (canonical-validated).
    pub protected: Value,
    /// Raw protected-header bytes (the signed `bstr`).
    pub protected_bytes: Vec<u8>,
    /// Body bytes (the receipt or head body).
    pub payload: Vec<u8>,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

/// Parse a tagged COSE_Sign1: tag 18 wrapping `[protected, unprotected, payload,
/// signature]`, with `protected` a canonical `bstr .cbor`, `unprotected` an
/// empty map, and `payload` a non-nil `bstr`. All shape problems are `E_DECODE`;
/// non-canonical bytes (recursively, into the protected header) are
/// `E_NONCANONICAL`. This is the shared R1 step.
pub fn parse(bytes: &[u8]) -> Result<Sign1, Error> {
    let top = decode_canonical(bytes)?;
    let inner = match top {
        Value::Tag(18, inner) => *inner,
        _ => return Err(Error::Decode),
    };
    let items = match inner {
        Value::Array(items) if items.len() == 4 => items,
        _ => return Err(Error::Decode),
    };
    let mut it = items.into_iter();
    let protected_bytes = take_bstr(it.next())?;
    let unprotected = it.next().ok_or(Error::Decode)?;
    let payload = take_bstr(it.next())?;
    let signature = take_bstr(it.next())?;

    if !matches!(unprotected.as_map(), Some([])) {
        return Err(Error::Decode); // unprotected MUST be empty
    }
    let protected = decode_canonical(&protected_bytes)?; // recursive canonical
    Ok(Sign1 {
        protected,
        protected_bytes,
        payload,
        signature,
    })
}

/// True if the signature verifies over the COSE_Sign1 Sig_structure (context
/// `"Signature1"`, empty `external_aad`) under `pubkey`. The caller maps a
/// `false` to its domain-specific signature error (E_RECEIPT_SIG / E_HEAD_SIG).
pub fn signature_ok(s: &Sign1, alg: Alg, pubkey: &[u8]) -> bool {
    let sig_structure = encode(&Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(s.protected_bytes.clone()),
        Value::Bytes(Vec::new()), // external_aad MUST be empty
        Value::Bytes(s.payload.clone()),
    ]));
    verify(alg, pubkey, &sig_structure, &s.signature).is_ok()
}

/// Read the protected header's `{1: alg, 4: kid}` — exactly those two keys, the
/// COSE_Sign1 profile for receipts/heads. `struct_err` is the caller's
/// structure error (E_RECEIPT_STRUCTURE / E_HEAD_STRUCTURE).
pub fn protected_alg_kid(s: &Sign1, struct_err: Error) -> Result<(i128, Vec<u8>), Error> {
    let map = s.protected.as_map().ok_or(struct_err)?;
    if map.len() != 2 {
        return Err(struct_err);
    }
    let mut alg = None;
    let mut kid = None;
    for (k, v) in map {
        match k.as_int() {
            Some(1) => alg = Some(v.as_int().ok_or(struct_err)?),
            Some(4) => kid = Some(v.as_bytes().ok_or(struct_err)?.to_vec()),
            _ => return Err(struct_err),
        }
    }
    Ok((alg.ok_or(struct_err)?, kid.ok_or(struct_err)?))
}

fn take_bstr(v: Option<Value>) -> Result<Vec<u8>, Error> {
    match v {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(Error::Decode),
    }
}
