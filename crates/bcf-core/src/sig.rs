//! Signature verification backends.
//!
//! Two curves, behind one `verify` entry point: Ed25519 (the primary protocol
//! identity) and ES256K (secp256k1 ECDSA + SHA-256, where rail-adjacent). The
//! spec cares only *that* parties sign and that verification is unambiguous —
//! so this module is deliberately thin, and the algorithm a verifier runs is
//! always taken from the signed claim, never asserted by the backend.
//!
//! Reuse note: the dm0 stack's `damson-crypto` is secp256k1-only and oriented
//! around a signing service; consolidating onto it is deferred (see the impl
//! leg's NOTES item) rather than coupling this reviewer-artifact crate to it.

use crate::error::Error;

/// COSE algorithm identifiers used by the BCF profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// EdDSA over Ed25519, COSE alg `-8`.
    Eddsa,
    /// ECDSA over secp256k1 with SHA-256, COSE alg `-47`.
    Es256k,
}

impl Alg {
    /// Map a COSE algorithm id to a supported algorithm, if any.
    pub fn from_cose(id: i128) -> Option<Alg> {
        match id {
            -8 => Some(Alg::Eddsa),
            -47 => Some(Alg::Es256k),
            _ => None,
        }
    }

    /// The COSE algorithm id.
    pub fn cose_id(self) -> i128 {
        match self {
            Alg::Eddsa => -8,
            Alg::Es256k => -47,
        }
    }

    /// The public-key length this algorithm requires, in bytes.
    /// Ed25519 raw key is 32 bytes; secp256k1 SEC1-compressed is 33.
    pub fn pubkey_len(self) -> usize {
        match self {
            Alg::Eddsa => 32,
            Alg::Es256k => 33,
        }
    }
}

/// Verify `signature` over `message` under `pubkey` for the given algorithm.
///
/// For ES256K the signature MUST be low-s (`specs/bcf-core.md` §5): a high-s
/// signature is a second, malleable encoding of the same logical signature and
/// is rejected as `E_SIG_INVALID`.
pub fn verify(alg: Alg, pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    match alg {
        Alg::Eddsa => verify_ed25519(pubkey, message, signature),
        Alg::Es256k => verify_es256k(pubkey, message, signature),
    }
}

fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let key_bytes: [u8; 32] = pubkey.try_into().map_err(|_| Error::SigInvalid)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| Error::SigInvalid)?;
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| Error::SigInvalid)?;
    let sig = Signature::from_bytes(&sig_bytes);
    // verify_strict rejects small-order keys and non-canonical R components.
    verifying_key
        .verify_strict(message, &sig)
        .map_err(|_| Error::SigInvalid)
}

fn verify_es256k(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| Error::SigInvalid)?;
    let sig = Signature::from_slice(signature).map_err(|_| Error::SigInvalid)?;
    // Low-s is mandatory: normalize_s() returns Some only when the input was
    // high-s, i.e. the malleable form — reject it.
    if sig.normalize_s().is_some() {
        return Err(Error::SigInvalid);
    }
    verifying_key
        .verify(message, &sig)
        .map_err(|_| Error::SigInvalid)
}
