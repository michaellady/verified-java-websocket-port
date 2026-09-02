#![forbid(unsafe_code)]
//! Kani actual-code verification harnesses for `ws_core` (US-012 AC5 lane).
//!
//! This crate is a VERIFICATION-ONLY artifact. It is not a member of the
//! `rust/` cargo workspace, no shipped crate depends on it, and it is never
//! linked into any shipped binary — so it does not appear in the
//! `cargo metadata` the `dependency-inventory` and `audit` gates read.
//!
//! It depends by PATH on `ws-core-under-verification`, whose `[lib] path`
//! points directly at the shipped `rust/ws-core/src/lib.rs`. Nothing is
//! copied: `cargo kani` compiles the byte-identical production source files
//! in place.
//!
//! All harness code is behind `#[cfg(kani)]`, so an ordinary `cargo build`
//! of this crate compiles an empty library.

#[cfg(kani)]
mod mutants;
#[cfg(kani)]
mod negative_control;
#[cfg(kani)]
mod real;
#[cfg(kani)]
mod spec;
