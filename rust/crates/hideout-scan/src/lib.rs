//! hideout-scan: where malware hides on a Windows PC. READ-ONLY.
//!
//! It never deletes, moves, disables, runs or uploads anything. It reads through
//! hideout-win, the one crate allowed to touch Windows directly; this crate has no
//! `unsafe` at all.

#![forbid(unsafe_code)]

pub mod quick;
pub mod report;
pub mod rules;
