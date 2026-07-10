//! The failure taxonomy.
//!
//! Every variant maps 1:1 to an `E_*` code named in the spec
//! (`specs/bcf-core.md` §8, `specs/bcf-chain-and-log.md` §2–§3). The codes are
//! normative: the conformance vectors assert *which* error a given bad input
//! produces, so the mapping here is part of the contract, not a convenience.

use thiserror::Error;

/// A verification failure, identified by its normative `E_*` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    // -- bcf-core §8 (V1–V9) --
    /// Not well-formed CBOR for this profile, or wrong top-level shape (V1).
    #[error("E_DECODE")]
    Decode,
    /// Well-formed but not the deterministic encoding of its content (V1/V3).
    #[error("E_NONCANONICAL")]
    Noncanonical,
    /// COSE_Sign envelope content violates the profile (V2).
    #[error("E_ENVELOPE")]
    Envelope,
    /// Claim map structure, key set, types, or field syntax wrong (V3).
    #[error("E_STRUCTURE")]
    Structure,
    /// `claim.domain` does not equal the caller's `expected_domain` (V4).
    #[error("E_DOMAIN")]
    Domain,
    /// Party-entry set malformed: duplicate pub, bad alg/pub, unsorted,
    /// unknown key, or fewer than two parties (V5).
    #[error("E_PARTY")]
    Party,
    /// A party named in the claim has no corresponding signature (V6).
    #[error("E_SIG_MISSING")]
    SigMissing,
    /// A signature matches no party, or a party is signed for twice (V6).
    #[error("E_SIG_EXTRA")]
    SigExtra,
    /// A signature's header `alg` disagrees with the party's claim `alg` (V7).
    #[error("E_ALG")]
    Alg,
    /// A signature's protected/unprotected headers violate the profile (V7).
    #[error("E_HEADER")]
    Header,
    /// A signature fails to verify, or an ES256K signature is not low-s (V8).
    #[error("E_SIG_INVALID")]
    SigInvalid,
    /// Supplied payload does not hash to `claim.payload_hash` (V9).
    #[error("E_PAYLOAD_HASH")]
    PayloadHash,

    // -- bcf-chain-and-log §2–§3 (C1–C4) --
    /// A claim lists the same predecessor hash more than once (§2).
    #[error("E_CHAIN_STRUCTURE")]
    ChainStructure,
    /// No single genesis artifact matches `chain_id` (C2).
    #[error("E_CHAIN_ROOT")]
    ChainRoot,
    /// An input artifact is neither a chain member nor an import (C2).
    #[error("E_CHAIN_UNREACHABLE")]
    ChainUnreachable,
    /// A member's predecessor resolves to nothing and is not an accepted
    /// external reference (C3).
    #[error("E_CHAIN_GAP")]
    ChainGap,
    /// One signer put their signature on two distinct claims that share a
    /// predecessor (C4, §5).
    #[error("E_EQUIVOCATION")]
    Equivocation,

    // -- bcf-chain-and-log §6 (log rungs 1–2; raised by the bcf-chain crate) --
    /// Receipt body malformed: wrong keys/types, or recipient/header mismatch (R2/R4).
    #[error("E_RECEIPT_STRUCTURE")]
    ReceiptStructure,
    /// Receipt `domain` is not the expected `"BCF-RECEIPT/1"` (R3).
    #[error("E_RECEIPT_DOMAIN")]
    ReceiptDomain,
    /// Receipt signature fails to verify under the recipient key (R5).
    #[error("E_RECEIPT_SIG")]
    ReceiptSig,
    /// Head body malformed: wrong keys/types, or publisher/header mismatch.
    #[error("E_HEAD_STRUCTURE")]
    HeadStructure,
    /// Head `domain` is not the expected `"BCF-HEAD/1"`.
    #[error("E_HEAD_DOMAIN")]
    HeadDomain,
    /// Head signature fails to verify under the publisher key.
    #[error("E_HEAD_SIG")]
    HeadSig,
    /// A Merkle inclusion proof does not recompute the committed root (P1–P3).
    #[error("E_HEAD_INCLUSION")]
    HeadInclusion,

    // -- bcf-chain-and-log §6.3 (witnessed log rung 3) --
    /// Checkpoint body malformed: wrong keys/types, `tree_size` not a
    /// non-negative `u64`, or publisher/header mismatch (W1).
    #[error("E_CKPT_STRUCTURE")]
    CkptStructure,
    /// Checkpoint `domain` is not the expected `"BCF-CKPT/1"` (W2).
    #[error("E_CKPT_DOMAIN")]
    CkptDomain,
    /// Checkpoint signature fails to verify under the publisher key (W3).
    #[error("E_CKPT_SIG")]
    CkptSig,
    /// Fewer than `threshold` distinct, in-set, non-publisher witnesses
    /// co-signed this checkpoint's hash (W4).
    #[error("E_CKPT_WITNESS")]
    CkptWitness,
    /// A consistency proof does not bridge the old root to the new one, or a
    /// boundary case (shrunk/diverged log) makes them inconsistent (§6.3.2).
    #[error("E_LOG_CONSISTENCY")]
    LogConsistency,
}

impl Error {
    /// The normative `E_*` string, as it appears in the conformance vectors.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Decode => "E_DECODE",
            Error::Noncanonical => "E_NONCANONICAL",
            Error::Envelope => "E_ENVELOPE",
            Error::Structure => "E_STRUCTURE",
            Error::Domain => "E_DOMAIN",
            Error::Party => "E_PARTY",
            Error::SigMissing => "E_SIG_MISSING",
            Error::SigExtra => "E_SIG_EXTRA",
            Error::Alg => "E_ALG",
            Error::Header => "E_HEADER",
            Error::SigInvalid => "E_SIG_INVALID",
            Error::PayloadHash => "E_PAYLOAD_HASH",
            Error::ChainStructure => "E_CHAIN_STRUCTURE",
            Error::ChainRoot => "E_CHAIN_ROOT",
            Error::ChainUnreachable => "E_CHAIN_UNREACHABLE",
            Error::ChainGap => "E_CHAIN_GAP",
            Error::Equivocation => "E_EQUIVOCATION",
            Error::ReceiptStructure => "E_RECEIPT_STRUCTURE",
            Error::ReceiptDomain => "E_RECEIPT_DOMAIN",
            Error::ReceiptSig => "E_RECEIPT_SIG",
            Error::HeadStructure => "E_HEAD_STRUCTURE",
            Error::HeadDomain => "E_HEAD_DOMAIN",
            Error::HeadSig => "E_HEAD_SIG",
            Error::HeadInclusion => "E_HEAD_INCLUSION",
            Error::CkptStructure => "E_CKPT_STRUCTURE",
            Error::CkptDomain => "E_CKPT_DOMAIN",
            Error::CkptSig => "E_CKPT_SIG",
            Error::CkptWitness => "E_CKPT_WITNESS",
            Error::LogConsistency => "E_LOG_CONSISTENCY",
        }
    }
}
