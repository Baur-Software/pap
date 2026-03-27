//! Intent detection for canvas prompts.
//!
//! Delegates to the shared intent table in `papillion_shared::intent`.
//! No more duplicated if-else chains.

pub use papillion_shared::intent::detect_intent;
