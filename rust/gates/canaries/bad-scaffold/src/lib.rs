//! US-009 AC1 BAD scaffold canary.
//!
//! Deliberately violates the AC1 gates: no `#![forbid(unsafe_code)]`
//! attribute (that absence is the point — the forbid scan must flag it), a
//! first-party `unsafe` block, and a clippy violation denied under
//! `-D warnings`. The canary gate FAILS if this crate ever PASSES the gate
//! suite. Do not "fix" this file; its violations are its purpose.

/// First-party unsafe with the forbid attribute absent: compiles here, but
/// the forbid scan must report the missing attribute, and adding the
/// attribute would make this a compile error.
pub fn first_byte(bytes: &[u8]) -> Option<u8> {
    if bytes.is_empty() {
        return None;
    }
    // Deliberate unsafe: the safe `bytes.first().copied()` equivalent.
    Some(unsafe { *bytes.as_ptr() })
}

/// Deliberate clippy violation (`clippy::bool_comparison`, denied under
/// `-D warnings`): compares a bool against a literal.
pub fn is_enabled(flag: bool) -> bool {
    if flag == true { true } else { false }
}
