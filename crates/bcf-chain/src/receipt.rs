//! Signed receipts (`specs/bcf-chain-and-log.md` §6.1).
//!
//! A receipt is a single-signer COSE_Sign1 acknowledgement that a party held a
//! given artifact, bound to it by content (`artifact_hash`), never by `prev`.
//! Verification is the R1–R5 procedure; the evidence is asymmetric — a presented
//! receipt is non-repudiable, an absent one proves nothing (§6.1).

use crate::cose1;
use crate::util::sha256;
use bcf_core::cbor::{decode_canonical, Value};
use bcf_core::{party_entry, Error, Party};

/// The expected receipt domain separator.
pub const RECEIPT_DOMAIN: &str = "BCF-RECEIPT/1";

/// A verified receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// `claim_hash` of the acknowledged artifact.
    pub artifact_hash: [u8; 32],
    /// The single signer.
    pub recipient: Party,
    /// The recipient's asserted receipt time (POSIX seconds).
    pub received_at: i128,
}

/// Verify a receipt against `expected_domain` (`"BCF-RECEIPT/1"`), running
/// R1–R5 in order. Returns the receipt or the first failure.
pub fn verify_receipt(bytes: &[u8], expected_domain: &str) -> Result<Receipt, Error> {
    // R1 — COSE_Sign1 envelope, deterministic CBOR, tag 18, unprotected empty.
    let sign1 = cose1::parse(bytes)?;

    // R2 — body is a deterministic-CBOR map with exactly keys {1,2,3,4}.
    let body = decode_canonical(&sign1.payload)?;
    let map = body.as_map().ok_or(Error::ReceiptStructure)?;
    let mut domain = None;
    let mut artifact_hash = None;
    let mut recipient_value = None;
    let mut received_at = None;
    for (k, v) in map {
        match k.as_int() {
            Some(1) => domain = Some(v.as_text().ok_or(Error::ReceiptStructure)?.to_string()),
            Some(2) => artifact_hash = Some(fixed32(v)?),
            Some(3) => recipient_value = Some(v.clone()),
            Some(4) => received_at = Some(v.as_int().ok_or(Error::ReceiptStructure)?),
            _ => return Err(Error::ReceiptStructure),
        }
    }
    let domain = domain.ok_or(Error::ReceiptStructure)?;
    let artifact_hash = artifact_hash.ok_or(Error::ReceiptStructure)?;
    let recipient_value = recipient_value.ok_or(Error::ReceiptStructure)?;
    let received_at = received_at.ok_or(Error::ReceiptStructure)?;

    // R3 — domain separator.
    if domain != expected_domain {
        return Err(Error::ReceiptDomain);
    }

    // R4 — recipient well-formed (bcf-core V5 single entry); header alg/kid bind.
    let recipient = party_entry(&recipient_value).map_err(|_| Error::ReceiptStructure)?;
    let (alg_id, kid) = cose1::protected_alg_kid(&sign1, Error::ReceiptStructure)?;
    if alg_id != recipient.alg.cose_id() || kid != sha256(&recipient.pubkey) {
        return Err(Error::ReceiptStructure);
    }

    // R5 — signature verifies under the recipient key (ES256K low-s enforced).
    if !cose1::signature_ok(&sign1, recipient.alg, &recipient.pubkey) {
        return Err(Error::ReceiptSig);
    }

    Ok(Receipt {
        artifact_hash,
        recipient,
        received_at,
    })
}

fn fixed32(v: &Value) -> Result<[u8; 32], Error> {
    v.as_bytes()
        .ok_or(Error::ReceiptStructure)?
        .try_into()
        .map_err(|_| Error::ReceiptStructure)
}
