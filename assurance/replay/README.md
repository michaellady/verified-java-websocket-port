Replay the retained lifecycle with:

`go run ./cmd/assurectl replay --root . --lifecycle assurance/lifecycle.json`

The deterministic resume checkpoint is checked in at `assurance/replay/checkpoint.json` and is bound to the retained lifecycle bundle, child policy, and dual vendored validators.

Adversarial fixtures under `assurance/replay/fixtures/` are synthetic fail-closed cases. They do not create acceptance claims.
