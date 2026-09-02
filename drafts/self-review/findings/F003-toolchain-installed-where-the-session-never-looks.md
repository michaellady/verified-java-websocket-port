# F003 — A setup script that declares success without asking the session's own tool what it sees hides an install that landed in the wrong home
phase: environment rig (nearest: port-qualify)   step: n/a   date: 2026-09-02T03:00Z
what happened: `cloud-setup.sh` exported `RUSTUP_HOME=/usr/local/rustup` and installed the pinned Rust 1.95.0 there. The session shell carries `RUSTUP_HOME=/root/.rustup` from the harness, which overrides `/etc/profile.d`, so `rustup toolchain list` showed only the pre-installed stable; the MSRV gate passed only because cargo's first run under `rust-toolchain.toml` made rustup install 1.95.0 on demand, which needs network at session time.
what it cost: a latent hard failure of the MSRV gate under a stricter network policy, masked by a pass; about thirty minutes.
where the deciding moment was: the script's verification block printed versions from the setup process's own environment instead of proving that the toolchain was visible where the session's rustup looks.
evidence: commit 51962e5; `.claude/CLOUD-ENVIRONMENT.md` "Verifying the environment actually works", which now says to run `rustup toolchain list` before the first cargo command.
bin: TOOL GAP for the environment rig; TARGET-LOCAL otherwise.
