//! US-009 AC1 GOOD scaffold canary.
//!
//! Minimal conforming crate: carries the mandatory safety attribute, is
//! clippy-clean under `-D warnings`, and has a passing test. The canary gate
//! fails if this crate ever stops passing the gate suite.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Adds two bytes without overflow by saturating at `u8::MAX`.
pub fn saturating_add(a: u8, b: u8) -> u8 {
    a.saturating_add(b)
}

#[cfg(test)]
mod tests {
    use super::saturating_add;

    #[test]
    fn saturates_at_max() {
        assert_eq!(saturating_add(200, 100), u8::MAX);
        assert_eq!(saturating_add(1, 2), 3);
    }
}
