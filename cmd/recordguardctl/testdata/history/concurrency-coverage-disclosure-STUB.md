# Concurrency coverage disclosure — WIP

Track: `claude/concurrency-coverage-disclosure`, branched from mainline
`claude/feature/verified-java-websocket-port` @ 2c63205.

Status: STUB. Work in progress; pushed early so a container restart does not
lose the branch again (this task has been lost twice).

Two problems under investigation:

1. The `post-failure` landing traded exclusivity for an ordering assertion
   (correct, not to be undone) and lost 83% of the exploration's
   discriminating power (18,755 -> 3,129 distinct semantic trace digests;
   56,777 -> 49 closed terminal runs). No `limitations` entry records it.
2. `revision_note` in `assurance/concurrency/results.json` carries superseded
   counters in present tense, in a leaf the enumeration classes as INERT.
