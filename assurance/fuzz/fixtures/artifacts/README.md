Artifact-capture directory for the fuzzpinctl polarity fixtures.

It exists so the `good-all-pinned` fixture has a real capture path to point at,
and so the `artifact-capture-absent` mutation — which points at a path that does
not exist — has something to be a mutation of. Nothing is written here: the
fixtures drive the checker, not a campaign.
