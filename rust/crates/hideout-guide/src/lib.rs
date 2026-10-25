//! hideout-guide: the Hideout Guide.
//!
//!   spec       the model, instructions and tools (guide-spec.mjs), held to it by a test
//!   wire       the conversation, typed so only redacted text and the model's own words
//!              can go in; the one sealed request a transport may send
//!   transport  gateway (the normal way) and direct (a developer's key, memory only)
//!   guide      the conversation loop and its tools (guide.mjs)
//!   case       the case file and the six-step tracker
//!   letters    the letter builder (no AI needed)
//!   checks     the deeper checks: scam drift, test charges, leaks, rogue AI, evidence,
//!              browser drift
//!   offline    the offline guide: steps, letters and checklists with no network
//!
//! No network code lives here: the app hands in one HTTPS door to one host. No `unsafe`.
//! The guide is general information, not legal or financial advice; it says it is an AI
//! and can be wrong.

#![forbid(unsafe_code)]

pub mod case;
pub mod checks;
pub mod guide;
pub mod letters;
pub mod offline;
pub mod spec;
pub mod transport;
pub mod wire;
