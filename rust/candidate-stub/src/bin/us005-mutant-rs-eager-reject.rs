//! US-005 planted Rust mutant `us005-rm-eager-reject-1002`: unconditional
//! protocol rejection (JAVA_INVALID_DATA, close code 1002) on every request.
//! Documented in mutants/manifest.json; must be killed by evaluation.

#![forbid(unsafe_code)]

fn main() -> std::io::Result<()> {
    candidate_stub::run_main(candidate_stub::Deviation::EagerReject)
}
