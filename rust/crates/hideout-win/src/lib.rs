//! hideout-win: the one place Hideout talks to Windows directly.
//!
//! Everything in here is READ-ONLY. Nothing in this crate can delete, move, rename,
//! disable, stop or start anything: the only write it exposes is the named pipe a second
//! Hideout launch uses to say "show". The only thing that sends anything off the PC is
//! `https::Door`, which can reach exactly one host (the guide's service) and is handed
//! only the guide's redacted request. Both promises are checked by a test
//! (`tests/read_only.rs`) that scans this crate's source for the Windows calls that
//! change things or open connections.
//!
//! Every `unsafe` block in Hideout lives in this crate. Each one says why it is sound.
//! The other crates are `#![forbid(unsafe_code)]`.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod accounts;
pub mod admin;
pub mod authenticode;
pub mod certs;
pub mod com;
pub mod crypto;
pub mod elevate;
pub mod env;
pub mod https;
pub mod identity;
pub mod links;
pub mod net;
pub mod pipe;
pub mod registry;
pub mod services;
pub mod tasks;
pub mod time;
pub mod wmi;

pub(crate) mod wide;
