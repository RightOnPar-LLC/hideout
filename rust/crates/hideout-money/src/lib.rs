//! hideout-money: the Money tab. Reads the bank statement a person downloads, on this
//! PC, and shows what is still charging them, what changed, and what left after a scam.
//!
//! No statement, transaction or account number ever leaves the PC: this crate has no
//! network code at all, and long digit runs are masked the moment a statement is read.
//! Refund odds and "tell your bank by" dates are general information, not legal or
//! financial advice. No `unsafe`.

#![forbid(unsafe_code)]

pub mod analyze;
pub mod directory;
pub mod js;
pub mod money;
pub mod statement;
