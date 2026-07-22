//! The bottom layer of the ferrite workspace: errors, configuration, shared
//! record types, IP/MAC utilities, the in-memory log ring and allocator
//! counters. Depends on no other ferrite crate.

pub mod config;
pub mod error;
pub mod logbuf;
pub mod memstats;
pub mod net;
pub mod types;
