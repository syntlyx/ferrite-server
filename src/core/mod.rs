//! Shared bottom-layer types and utilities — the future `ferrite-core` crate.
//!
//! Everything above (dns, storage, stats, clients, proxy, …) may depend on this
//! module; nothing here may depend on any other ferrite module except
//! [`crate::error`] and [`crate::config`], which move here with it.

pub mod net;
pub mod types;
