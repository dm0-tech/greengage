//! The COSE_Sign envelope (`specs/bcf-core.md` §5).
//!
//! Parsing is the V1 step: decode the tagged COSE_Sign structure, and decode
//! every `bstr .cbor` protected header in turn so non-canonical inner bytes are
//! caught (the recursion §3 demands). Profile content — the content-type, empty
//! unprotected maps, non-nil payload — is the V2 step, kept separate so the
//! error codes (E_DECODE for shape, E_ENVELOPE for profile) match the spec.

use crate::cbor::{decode_canonical, Value};
use crate::error::Error;

/// One `COSE_Signature` (§5).
pub struct SignatureEntry {
    /// Raw protected-header bytes (the signed `bstr`).
    pub protected_bytes: Vec<u8>,
    /// Decoded protected header (canonical-validated at V1).
    pub protected: Value,
    /// The signature's unprotected header (must be empty; checked at V7).
    pub unprotected: Value,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

/// A parsed COSE_Sign envelope (V1 output; not yet profile-checked).
pub struct Envelope {
    /// Raw body protected-header bytes (the signed `bstr`).
    pub body_protected_bytes: Vec<u8>,
    /// Decoded body protected header (canonical-validated at V1).
    pub body_protected: Value,
    /// Body unprotected header (must be empty; checked at V2).
    pub body_unprotected: Value,
    /// Payload bytes, or `None` if the CBOR `null` (detached) — rejected at V2.
    pub payload: Option<Vec<u8>>,
    /// The signatures.
    pub signatures: Vec<SignatureEntry>,
}

/// V1: decode the envelope and every nested `bstr .cbor` protected header.
/// Gross shape errors are `E_DECODE`; non-canonical bytes are `E_NONCANONICAL`.
pub fn parse(envelope_bytes: &[u8]) -> Result<Envelope, Error> {
    let top = decode_canonical(envelope_bytes)?;

    // Outer structure MUST be tag 98 wrapping a 4-element array.
    let inner = match top {
        Value::Tag(98, inner) => *inner,
        _ => return Err(Error::Decode),
    };
    let items = match inner {
        Value::Array(items) if items.len() == 4 => items,
        _ => return Err(Error::Decode),
    };
    let mut it = items.into_iter();
    let body_protected_bytes = take_bstr(it.next())?;
    let body_unprotected = it.next().ok_or(Error::Decode)?;
    let payload = match it.next().ok_or(Error::Decode)? {
        Value::Bytes(b) => Some(b),
        Value::Null => None,
        _ => return Err(Error::Decode),
    };
    let signatures_value = it.next().ok_or(Error::Decode)?;

    // Recursively validate the body protected header bytes.
    let body_protected = decode_canonical(&body_protected_bytes)?;

    let sig_array = match signatures_value {
        Value::Array(a) => a,
        _ => return Err(Error::Decode),
    };
    let mut signatures = Vec::with_capacity(sig_array.len());
    for sig in sig_array {
        signatures.push(parse_signature(sig)?);
    }

    Ok(Envelope {
        body_protected_bytes,
        body_protected,
        body_unprotected,
        payload,
        signatures,
    })
}

fn parse_signature(sig: Value) -> Result<SignatureEntry, Error> {
    let items = match sig {
        Value::Array(items) if items.len() == 3 => items,
        _ => return Err(Error::Decode),
    };
    let mut it = items.into_iter();
    let protected_bytes = take_bstr(it.next())?;
    let unprotected = it.next().ok_or(Error::Decode)?;
    let signature = take_bstr(it.next())?;
    // Recursively validate the per-signature protected header bytes.
    let protected = decode_canonical(&protected_bytes)?;
    Ok(SignatureEntry {
        protected_bytes,
        protected,
        unprotected,
        signature,
    })
}

fn take_bstr(v: Option<Value>) -> Result<Vec<u8>, Error> {
    match v {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(Error::Decode),
    }
}

/// The body protected header the profile mandates: `{3: content-type}`.
pub const CONTENT_TYPE: &str = "application/bcf-claim+cbor";

/// True if `header` is exactly `{3: "application/bcf-claim+cbor"}`.
pub fn is_body_protected_ok(header: &Value) -> bool {
    match header.as_map() {
        Some([(k, v)]) => k.as_int() == Some(3) && v.as_text() == Some(CONTENT_TYPE),
        _ => false,
    }
}

/// True if `header` is an empty map.
pub fn is_empty_map(header: &Value) -> bool {
    matches!(header.as_map(), Some([]))
}
