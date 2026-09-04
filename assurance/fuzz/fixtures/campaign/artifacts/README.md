Artifact-capture directory for the campaign-runner polarity fixtures.

`cmd/fuzzpinctl -campaign-fixtures` writes each synthetic run's captured log
here. The logs are transient by-products of the polarity suite, not evidence:
the evidence for the real campaigns lives in `assurance/fuzz/campaign/`.
