//! US-005 inert stub target (negative control): speaks the java-oracle JSONL
//! protocol, implements no WebSocket behavior, and must FAIL the corpus.

#![forbid(unsafe_code)]

fn main() -> std::io::Result<()> {
    candidate_stub::run_main(candidate_stub::Deviation::Inert)
}
