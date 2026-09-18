//! The bottom layer of the ferrite workspace: errors, configuration, shared
//! record types, the privacy switches over what a query records, IP/MAC
//! utilities, the in-memory log ring and allocator counters. Depends on no
//! other ferrite crate.

pub mod config;
pub mod error;
pub mod logbuf;
pub mod memstats;
pub mod net;
pub mod recording;
pub mod types;
