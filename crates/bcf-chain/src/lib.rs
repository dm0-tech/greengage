//! # bcf-chain
//!
//! Chain verification and the detect-mode log (greengage Epic 2), built on the
//! `bcf-core` artifact. The canonical artifact is `specs/bcf-chain-and-log.md`;
//! this crate claims no authority beyond passing its conformance vectors.
//!
//! - [`verify_chain`] — a set of artifacts as a chain (§2–§5, C1–C4).
//! - [`verify_receipt`] — a signed delivery acknowledgement (§6.1, R1–R5).
//! - [`verify_head`] / [`verify_inclusion`] / [`detect_head_fork`] — Merkle
//!   chain-head publication (§6.2).
//! - [`verify_checkpoint`] / [`verify_log_consistency`] / [`detect_log_equivocation`]
//!   — the witnessed-log client, ladder rung 3 (§6.3, greengage Epic 3).
//! - [`find_gaps`] — holder-side gap-detection (§6.1).
//!
//! Like `bcf-core`, this crate is verify-only: producing and signing artifacts
//! is the parties' job with their own keys. The Merkle helper [`merkle_root`] is
//! a pure function, exposed because fork detection and callers need it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod chain;
mod cose1;
mod gap;
mod head;
mod log;
mod receipt;
mod util;

pub use chain::verify_chain;
pub use gap::find_gaps;
pub use head::HEAD_DOMAIN;
pub use head::{
    detect_head_fork, merkle_root, sorted_dedup, verify_head, verify_inclusion, ForkVerdict, Head,
};
pub use log::{
    detect_log_equivocation, verify_checkpoint, verify_log_consistency, Checkpoint, CKPT_DOMAIN,
    COSIG_DOMAIN,
};
pub use receipt::{verify_receipt, Receipt, RECEIPT_DOMAIN};
