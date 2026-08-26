//! US-005 planted Rust mutant `us005-rm-digest-unbind`: emits stub responses
//! whose request_digest is an all-zero identity, breaking the scenario
//! binding. Documented in mutants/manifest.json; must be killed by evaluation.

#![forbid(unsafe_code)]

fn main() -> std::io::Result<()> {
    candidate_stub::run_main(candidate_stub::Deviation::DigestUnbind)
}
