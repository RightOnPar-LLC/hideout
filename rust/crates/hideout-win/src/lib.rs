//! hideout-win: the one place Hideout talks to Windows directly.
//!
//! Everything in here is READ-ONLY. Nothing in this crate can delete, move, rename,
//! disable, stop, start or upload anything: the only write it exposes is the named pipe
//! a second Hideout launch uses to say "show". That is a promise checked by a test
//! (`tests/read_only.rs`) that scans this crate's source for the Windows calls that
//! change things.
//!
//! Every `unsafe` block in Hideout lives in this crate. Each one says why it is sound.
//! The other crates are `#![forbid(unsafe_code)]`.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod admin;
pub mod authenticode;
pub mod com;
pub mod crypto;
pub mod env;
pub mod links;
pub mod pipe;
pub mod registry;
pub mod services;
pub mod tasks;
pub mod time;
pub mod wmi;

pub(crate) mod wide;
