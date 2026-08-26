# Benchmark pipeline plumbing run — 2026-08-26

This pull request exists solely to exercise the US-008 benchmark pipeline in
plumbing mode. Applying the `benchmark-plumbing` label to this PR triggers
`.github/workflows/benchmark.yml` with the plumbing defaults: a cheap `c7i.large`
VM instead of a bare-metal host, the latest AL2023 AMI explicitly allowed, and
the runner stub emitting only the result-schema skeleton whose every metric
field is the NOT_MEASURED sentinel.

Nothing this run produces is a benchmark sample, a performance claim, or
evidence that US-008 passes. The run verifies only the plumbing: OIDC role
assumption, Terraform state and locking, host provisioning, SSM execution,
result sync, artifact upload, and — most importantly — job-scoped teardown
leaving zero surviving EC2 instances.

Owner authorization: standing instruction from mikelady, 2026-08-26 — "Run the
plumbing test on the pipeline once the fixes merge." The fixes merged to
claude/feature/verified-java-websocket-port at 5faaef3 after two pinned-reviewer
confirmation passes (sessions 01a03f3c and 01a03f3e).
