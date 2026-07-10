//! # bcf-core
//!
//! Reference implementation of the BCF core envelope, verifier, and chain
//! (greengage Epic 1). The canonical artifact is the spec suite in
//! [`specs/`](https://github.com/dm0-tech/greengage/tree/main/specs); this crate
//! claims no authority beyond passing its conformance vectors. Where this code
//! and the spec disagree, the spec wins and the disagreement is a bug.
//!
//! Entry point: [`verify_bcf`] validates a single artifact (`specs/bcf-core.md`
//! §8, V1–V9). Chain and log verification live in the sibling `bcf-chain` crate,
//! which reuses this crate's [`cbor`], [`sig`], and [`party_entry`] surface.
//!
//! Everything is offline and self-contained: verification needs only the
//! artifact bytes (public keys travel inline), no key directory and no network.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cbor;
pub mod sig;

mod claim;
mod envelope;
mod error;
mod predicate;
mod verify;

pub use claim::{party_entry, Claim, Party};
pub use error::Error;
pub use sig::Alg;
pub use verify::{verify_bcf, Verified};
