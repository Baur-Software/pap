//! Intent detection for canvas prompts.
//!
//! Delegates to the shared intent table in `papillon_shared::intent`.
//! No more duplicated if-else chains.

pub use papillon_shared::intent::detect_intent;
