#!/usr/bin/env python3
"""Generate the US-022 polarity fixture suite.

One green base manifest that verifies end to end, plus one derived manifest per
rule, each carrying a SINGLE mutation. A checker that blocked unconditionally
would fail the green case; a checker missing any rule would fail that rule's
case. Both directions are needed, which is why the green case exists.
"""
import copy, json, os, subprocess, sys

ROOT = sys.argv[1]
FIXDIR = os.path.join(ROOT, "assurance/mutation/fixtures")
os.makedirs(os.path.join(FIXDIR, "manifests"), exist_ok=True)

JAVA_PROD_DIGEST = "sha256:29773c46596aafef879b1e536b51e2dd1fc42b08b16e3987f71b33854f3bda17"
JAVA_TEST_DIGEST = "sha256:9e47ecae95d63e33040d20fb4ee5e9342e08f4df1df32498f38e4db51a6bef40"

GREEN = {
    "schema_version": "1.0.0",
    "document_id": "us022-polarity-fixture-green",
    "entity_type": "NormalizedMutationDenominator",
    "story": "US-022",
    "digest_scheme": "CANONICAL_PATH_SHA256_V1",
    "statement": "POLARITY FIXTURE, NOT EVIDENCE. A synthetic denominator that passes every rule, so a checker that blocked unconditionally would fail its own suite. Its two mutants and its campaign never happened; its engine is `cargo --version` standing in for a mutation engine so the availability probe really succeeds. Nothing here may be cited as a US-022 result.",
    "ac_verbatim": {"ac1": "fixture", "ac2": "fixture", "ac3": "fixture", "ac4": "fixture", "ac5": "fixture"},
    "note": "fixture",
    "engines": [{
        "id": "engine-a",
        "kind": "rust_mutation",
        "tool": "fixture-engine",
        "probe_command": ["cargo", "--version"],
        "probe_dir": "rust",
        "toolchain": {"required": "Rust 1.95.0", "probe_command": ["cargo", "--version"], "probe_dir": "rust", "version_pattern": "1.95.0"},
        "dependency_graph": {"status": "PROMOTED", "promotion_record": "rust/rust-toolchain.toml", "note": "fixture"},
        "note": "fixture",
    }],
    "surfaces": [
        {"id": "prod", "kind": "production", "language": "java", "paths": ["java-oracle/src/main/java"], "file_count": 5, "digest": JAVA_PROD_DIGEST, "note": "fixture"},
        {"id": "tests", "kind": "test", "language": "java", "paths": ["java-oracle/src/test/java"], "file_count": 1, "digest": JAVA_TEST_DIGEST, "note": "fixture"},
    ],
    "populations": [{
        "id": "pop-a",
        "surface": "prod",
        "engine": "engine-a",
        "enumeration_status": "ENUMERATED",
        "provenance": "tool_enumerated",
        "source_manifest": "",
        "source_manifest_key": "",
        "declared_total": 2,
        "classes": {"killed": 1, "equivalent": 1},
        "records": [
            {"id": "mx-1", "source_tool": "PIT", "raw_status": "KILLED", "disposition": "killed", "eligible": True, "in_denominator": True, "evidence": "", "review_ids": []},
            {"id": "mx-2", "source_tool": "PIT", "raw_status": "SURVIVED", "disposition": "equivalent", "eligible": False, "in_denominator": True, "evidence": "fixture equivalence argument", "review_ids": ["rv-1"]},
        ],
        "rationale": "fixture",
    }],
    "reviews": [{"id": "rv-1", "reviewer_id": "fixture-reviewer", "role": "independent-reviewer", "blind": True, "disposition": "APPROVE", "basis": "fixture"}],
    "score": {"denominator_total": 2, "eligible_total": 1, "killed_total": 1, "missed_total": 0, "eligible_score_percent": 100.0, "computable": True, "note": "fixture"},
    "test_integrity": {
        "legs": [
            {"id": "no-stub-before", "status": "RUN", "command": "fixture", "exit": 0, "note": "fixture"},
            {"id": "no-stub-after", "status": "RUN", "command": "fixture", "exit": 0, "note": "fixture"},
            {"id": "test-manifest-before", "status": "RUN", "command": "fixture", "exit": 0, "note": "fixture"},
            {"id": "test-manifest-after", "status": "RUN", "command": "fixture", "exit": 0, "note": "fixture"},
        ],
        "test_surface_digest_before": JAVA_TEST_DIGEST,
        "test_surface_digest_after": JAVA_TEST_DIGEST,
        "note": "fixture",
    },
    "arms": [
        {
            "id": "hidden",
            "mutation_run_status": "RUN",
            "separation": {d: {"declared": "hidden-" + d, "source": "", "field": "", "note": "fixture"} for d in
                           ["identity", "filesystem", "cache", "credential", "signing_key", "workspace"]},
            "network_denial": "fixture deny-all",
            "protected_store_denial": "fixture deny-all",
            "budget_monotonic": True,
            "budget_basis": "fixture",
            "anti_evasion": "fixture",
            "diagnostic_policy": "fixture",
            "rationale": "fixture",
        },
        {
            "id": "sealed",
            "mutation_run_status": "RUN",
            "separation": {d: {"declared": "sealed-" + d, "source": "", "field": "", "note": "fixture"} for d in
                           ["identity", "filesystem", "cache", "credential", "signing_key", "workspace"]},
            "network_denial": "fixture deny-all",
            "protected_store_denial": "fixture deny-all",
            "budget_monotonic": True,
            "budget_basis": "fixture",
            "anti_evasion": "fixture",
            "diagnostic_policy": "fixture",
            "rationale": "fixture",
        },
    ],
    "ac5_legs": [{"id": leg, "requirement": "fixture", "status": "PASSED", "evidence": "fixture"} for leg in
                 ["pinned-java-passes-100", "empty-stub-rust-fails", "planted-mutants-fail",
                  "candidate-passes", "all-cases-reconcile", "zero-protected-leakage"]],
    "signature": {"scheme": "ed25519", "payload_scheme": "MUTDENOM_PAYLOAD_SHA256_V1",
                  "key_id": "", "public_key_hex": "", "payload_digest": "", "signature": "", "note": "fixture"},
    "claim": {"ac1_met": False, "ac2_met": False, "ac3_met": False, "ac4_met": False, "ac5_met": False,
              "claim_grade": "observed", "honest_state": "POLARITY FIXTURE. Claims nothing."},
}


def mutate(fn):
    m = copy.deepcopy(GREEN)
    fn(m)
    return m


CASES = []


def case(cid, rationale, findings, fn, resign=True, post=None):
    m = mutate(fn)
    m["document_id"] = "us022-polarity-fixture-" + cid
    rel = "assurance/mutation/fixtures/manifests/%s.json" % cid
    with open(os.path.join(ROOT, rel), "w") as fh:
        json.dump(m, fh, indent=2)
        fh.write("\n")
    if resign:
        subprocess.run(["go", "run", "./cmd/mutdenomctl", "-root", ROOT, "-sign-fixture", rel],
                       cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    if post is not None:
        # Mutations that must survive signing: they attack the signature block
        # itself, so they are applied AFTER the fixture is signed.
        with open(os.path.join(ROOT, rel)) as fh:
            signed = json.load(fh)
        post(signed)
        with open(os.path.join(ROOT, rel), "w") as fh:
            json.dump(signed, fh, indent=2)
            fh.write("\n")
    CASES.append({
        "id": cid,
        "manifest_path": rel,
        "rationale": rationale,
        "expected": {"exit_code": 0 if not findings else 1,
                     "state": "OK" if not findings else "BLOCKED",
                     "findings": sorted(findings)},
    })


# --- the green anchor -------------------------------------------------------
case("green", "The polarity anchor: a manifest that satisfies every rule. Without it, a checker that returned BLOCKED unconditionally would pass this entire suite.", [], lambda m: None)

# --- schema / digest scheme -------------------------------------------------
case("digest-scheme-invalid", "A manifest that digests its surfaces under some other scheme is not comparable with the rest of the repository's evidence.",
     ["MUT_DIGEST_SCHEME_INVALID"], lambda m: m.update({"digest_scheme": "SOME_OTHER_SCHEME"}))

# --- engines ----------------------------------------------------------------
case("engine-unavailable-honestly-blocked",
     "The load-bearing case. The engine is genuinely absent AND the manifest says so honestly -- the population is parked NOT_ENUMERATED_ENGINE_UNAVAILABLE and the arms are parked NOT_RUN. Honest unavailability STILL BLOCKS. Missing tooling is never a pass.",
     ["MUT_ENGINE_UNAVAILABLE", "MUT_POPULATION_NOT_ENUMERATED", "MUT_SCORE_NOT_COMPUTABLE",
      "MUT_DENOMINATOR_TOTAL_DRIFT", "MUT_ELIGIBLE_TOTAL_DRIFT", "MUT_KILLED_TOTAL_DRIFT",
      "MUT_SCORE_PERCENT_DRIFT", "MUT_ARM_NOT_RUN"],
     lambda m: (m["engines"][0].update({"probe_command": ["cargo", "definitely-not-a-subcommand"]}),
                m["populations"][0].update({"enumeration_status": "NOT_ENUMERATED_ENGINE_UNAVAILABLE",
                                            "declared_total": 0, "classes": {}, "records": []}),
                [a.update({"mutation_run_status": "NOT_RUN_ENGINE_UNAVAILABLE"}) for a in m["arms"]]))

case("toolchain-version-mismatch",
     "The engine is installed but the runtime under it is not the pinned one. A campaign run on the wrong toolchain is a campaign about a different program.",
     ["MUT_TOOLCHAIN_VERSION_MISMATCH"], lambda m: m["engines"][0]["toolchain"].update({"version_pattern": "0.0.0-not-this-toolchain"}))

case("toolchain-probe-unrunnable",
     "The toolchain probe itself cannot run, so the pinned runtime could not be OBSERVED at all. Not being able to decide the runtime is not the same as deciding it is right, and it blocks the same way. Added after the deletion attack found this branch had no witness.",
     ["MUT_TOOLCHAIN_VERSION_MISMATCH"],
     lambda m: m["engines"][0]["toolchain"].update({"probe_command": ["definitely-not-a-real-binary-xyz"]}))

case("dependency-graph-not-promoted",
     "AC1 says the engines run FROM PROMOTED tool/dependency graphs. An unpromoted graph is not one they may run from.",
     ["MUT_DEPENDENCY_GRAPH_NOT_PROMOTED"], lambda m: m["engines"][0]["dependency_graph"].update({"status": "NOT_PROMOTED", "promotion_record": ""}))

case("promotion-record-empty",
     "PROMOTED with no record named. Promotion that names no record is an adjective.",
     ["MUT_PROMOTION_RECORD_ABSENT"], lambda m: m["engines"][0]["dependency_graph"].update({"promotion_record": ""}))

case("promotion-record-missing-file",
     "PROMOTED naming a record that is not on disk. A promotion record nobody can open promoted nothing.",
     ["MUT_PROMOTION_RECORD_ABSENT"], lambda m: m["engines"][0]["dependency_graph"].update({"promotion_record": "does/not/exist.json"}))

case("dependency-graph-status-unknown",
     "An invented promotion status.",
     ["MUT_MANIFEST_SCHEMA_INVALID"], lambda m: m["engines"][0]["dependency_graph"].update({"status": "MOSTLY_PROMOTED"}))

case("unknown-engine-reference",
     "A population citing an engine the manifest never declares: its availability was never decided, so its campaign was never judged.",
     ["MUT_UNKNOWN_ENGINE_REFERENCE"], lambda m: m["populations"][0].update({"engine": "engine-that-does-not-exist"}))

# --- unavailable in both directions -----------------------------------------
case("unavailable-as-skip-population-claims-run",
     "A population recorded ENUMERATED on an engine that is not installed: the campaign is asserted and the tool is absent.",
     ["MUT_ENGINE_UNAVAILABLE", "UNAVAILABLE_REPRESENTED_AS_SKIP",
      "MUT_ARM_NOT_RUN", "MUT_ARM_SEPARATION_SHARED"],
     lambda m: (m["engines"][0].update({"probe_command": ["cargo", "definitely-not-a-subcommand"]}),
                [a.update({"mutation_run_status": "NOT_RUN_ENGINE_UNAVAILABLE",
                           "separation": {d: {"declared": "shared-" + d, "source": "", "field": "", "note": "fixture"}
                                          for d in ["identity", "filesystem", "cache", "credential", "signing_key", "workspace"]}})
                 for a in m["arms"]]))

case("unavailable-as-skip-population-parked-while-available",
     "THE INVERSE EVASION. The engine is right there and the population is parked as blocked-on-tooling. That hides a campaign nobody ran behind a tool that is installed.",
     ["UNAVAILABLE_REPRESENTED_AS_SKIP", "MUT_POPULATION_NOT_ENUMERATED", "MUT_SCORE_NOT_COMPUTABLE",
      "MUT_DENOMINATOR_TOTAL_DRIFT", "MUT_ELIGIBLE_TOTAL_DRIFT", "MUT_KILLED_TOTAL_DRIFT", "MUT_SCORE_PERCENT_DRIFT"],
     lambda m: m["populations"][0].update({"enumeration_status": "NOT_ENUMERATED_ENGINE_UNAVAILABLE",
                                           "declared_total": 0, "classes": {}, "records": []}))

case("unavailable-as-skip-arm-claims-run",
     "An arm recorded RUN while the only declared engine is absent.",
     ["MUT_ENGINE_UNAVAILABLE", "UNAVAILABLE_REPRESENTED_AS_SKIP",
      "MUT_POPULATION_NOT_ENUMERATED", "MUT_SCORE_NOT_COMPUTABLE",
      "MUT_DENOMINATOR_TOTAL_DRIFT", "MUT_ELIGIBLE_TOTAL_DRIFT", "MUT_KILLED_TOTAL_DRIFT", "MUT_SCORE_PERCENT_DRIFT"],
     lambda m: (m["engines"][0].update({"probe_command": ["cargo", "definitely-not-a-subcommand"]}),
                m["populations"][0].update({"enumeration_status": "NOT_ENUMERATED_ENGINE_UNAVAILABLE",
                                            "declared_total": 0, "classes": {}, "records": []})))

case("unavailable-as-skip-arm-parked-while-available",
     "THE INVERSE EVASION at the arm. Every engine probes available and the arm is still parked as blocked-on-tooling.",
     ["UNAVAILABLE_REPRESENTED_AS_SKIP", "MUT_ARM_NOT_RUN"],
     lambda m: m["arms"][0].update({"mutation_run_status": "NOT_RUN_ENGINE_UNAVAILABLE"}))

case("status-skipped-forbidden-population",
     "There is no SKIPPED status in this model. Writing one is refused BY NAME rather than falling through to 'unknown'.",
     ["MUT_STATUS_SKIPPED_FORBIDDEN", "MUT_SCORE_NOT_COMPUTABLE"],
     lambda m: m["populations"][0].update({"enumeration_status": "SKIPPED"}))

case("status-skipped-forbidden-arm",
     "Same refusal at the arm.",
     ["MUT_STATUS_SKIPPED_FORBIDDEN"], lambda m: m["arms"][0].update({"mutation_run_status": "SKIPPED"}))

case("arm-status-unknown", "An invented arm run status.",
     ["MUT_MANIFEST_SCHEMA_INVALID"], lambda m: m["arms"][0].update({"mutation_run_status": "PROBABLY_RAN"}))

# --- surfaces ---------------------------------------------------------------
case("surface-undeclared", "A surface with no paths: AC1 mutates a DECLARED surface, and an undeclared one has no denominator.",
     ["MUT_SURFACE_UNDECLARED"], lambda m: m["surfaces"][0].update({"paths": []}))

case("surface-digest-drift", "The production surface moved under the manifest.",
     ["MUT_SURFACE_DIGEST_DRIFT"], lambda m: m["surfaces"][0].update({"digest": "sha256:" + "0" * 64}))

case("surface-file-count-drift", "The digest matches and the file count does not: a separate rule with a separate code, so neither can hide behind the other.",
     ["MUT_SURFACE_FILE_COUNT_DRIFT"], lambda m: m["surfaces"][0].update({"file_count": 99}))

case("surface-unreadable", "A surface path that is not on disk. A missing surface is not an empty surface.",
     ["MUT_SURFACE_DIGEST_DRIFT"], lambda m: m["surfaces"][0].update({"paths": ["no/such/place"]}))

case("production-surface-has-no-population", "A declared production surface nobody enumerated a population over is a surface nobody mutated.",
     ["MUT_SURFACE_HAS_NO_POPULATION"],
     lambda m: m["surfaces"].append({"id": "orphan", "kind": "production", "language": "java",
                                     "paths": ["java-oracle/src/test/java"], "file_count": 1,
                                     "digest": JAVA_TEST_DIGEST, "note": "fixture"}))

case("unknown-surface-reference", "A population citing a surface the manifest never declares.",
     ["MUT_UNKNOWN_SURFACE_REFERENCE", "MUT_SURFACE_HAS_NO_POPULATION"],
     lambda m: m["populations"][0].update({"surface": "no-such-surface"}))

# --- population integrity ----------------------------------------------------
case("population-not-tool-enumerated",
     "THE SUBSTITUTION THIS STORY IS MOST LIKELY TO BE OFFERED: a hand-curated catalogue of chosen mutants presented as a population. The mutants nobody wrote down were never counted.",
     ["MUT_POPULATION_NOT_TOOL_ENUMERATED"], lambda m: m["populations"][0].update({"provenance": "hand_curated"}))

case("provenance-unknown", "An invented provenance.",
     ["MUT_MANIFEST_SCHEMA_INVALID"], lambda m: m["populations"][0].update({"provenance": "somehow"}))

case("enumeration-status-unknown", "An invented enumeration status.",
     ["MUT_MANIFEST_SCHEMA_INVALID", "MUT_SCORE_NOT_COMPUTABLE"],
     lambda m: m["populations"][0].update({"enumeration_status": "PARTIALLY"}))

case("silent-absence-record-dropped",
     "THE CENTRAL RULE. A mutant is removed from the records while the header count keeps counting it. This is what 'impossible for a mutant to be silently absent' means mechanically: the count and the records must be the same thing.",
     ["MUT_POPULATION_RECORD_COUNT_DRIFT", "MUT_CLASS_TALLY_DRIFT", "MUT_DENOMINATOR_TOTAL_DRIFT"],
     lambda m: m["populations"][0].update({"records": m["populations"][0]["records"][:1]}))

case("class-sum-mismatch", "The class table sums to something other than the declared total.",
     ["MUT_CLASS_SUM_MISMATCH", "MUT_CLASS_TALLY_DRIFT"],
     lambda m: m["populations"][0].update({"classes": {"killed": 1, "equivalent": 1, "survived": 5}}))

case("class-tally-drift", "The class table sums correctly and disagrees with the records. A separate rule from the sum, with a separate code.",
     ["MUT_CLASS_TALLY_DRIFT"], lambda m: m["populations"][0].update({"classes": {"killed": 2}}))

case("class-table-disposition-unknown", "A tenth class invented in the class table.",
     ["MUT_CLASS_TABLE_DISPOSITION_UNKNOWN", "MUT_CLASS_SUM_MISMATCH"],
     lambda m: m["populations"][0]["classes"].update({"probably_fine": 1}))

case("source-manifest-count-drift",
     "A population normalized from an on-disk campaign manifest whose entry count does not match. The normalization is re-derived from the file, not asserted.",
     ["MUT_SOURCE_MANIFEST_COUNT_DRIFT"],
     lambda m: m["populations"][0].update({"source_manifest": "mutants/e1-ws-core-manifest.json", "source_manifest_key": "mutants"}))

case("source-manifest-unreadable", "A source manifest that is not on disk.",
     ["MUT_SOURCE_MANIFEST_UNREADABLE"],
     lambda m: m["populations"][0].update({"source_manifest": "mutants/no-such-file.json", "source_manifest_key": "mutants"}))

# --- record integrity --------------------------------------------------------
case("disposition-absent", "A mutant with no disposition. Every mutant lands in exactly one of the nine classes, and 'none' is not one of them.",
     ["MUT_DISPOSITION_ABSENT", "MUT_CLASS_TALLY_DRIFT", "MUT_KILLED_TOTAL_DRIFT",
      "MUT_SCORE_PERCENT_DRIFT"],
     lambda m: m["populations"][0]["records"][0].update({"disposition": ""}))

case("disposition-unknown", "A tenth class invented on a record.",
     ["MUT_DISPOSITION_UNKNOWN", "MUT_CLASS_TALLY_DRIFT", "MUT_KILLED_TOTAL_DRIFT",
      "MUT_SCORE_PERCENT_DRIFT"],
     lambda m: m["populations"][0]["records"][0].update({"disposition": "probably_fine"}))

case("mutant-id-duplicate", "One mutant counted twice inflates every denominator it is in.",
     ["MUT_MUTANT_ID_DUPLICATE", "MUT_CLASS_TALLY_DRIFT",
      "MUT_POPULATION_RECORD_COUNT_DRIFT", "MUT_DENOMINATOR_TOTAL_DRIFT",
      "MUT_ELIGIBLE_TOTAL_DRIFT", "MUT_KILLED_TOTAL_DRIFT"],
     lambda m: m["populations"][0]["records"].append(copy.deepcopy(m["populations"][0]["records"][0])))

case("record-excluded-from-denominator",
     "A mutant marked out of the denominator. AC2 requires EVERY classification to remain visible in it -- this is the rule that stops an inconvenient mutant from being quietly dropped.",
     ["MUT_RECORD_EXCLUDED_FROM_DENOMINATOR", "MUT_DENOMINATOR_TOTAL_DRIFT"],
     lambda m: m["populations"][0]["records"][1].update({"in_denominator": False}))

case("eligibility-mislabelled-ineligible-marked-eligible",
     "An equivalent mutant marked eligible. The two ineligible classes leave the ELIGIBLE set and stay in the denominator, never the reverse.",
     ["MUT_ELIGIBILITY_MISLABELLED"], lambda m: m["populations"][0]["records"][1].update({"eligible": True}))

case("eligibility-mislabelled-eligible-marked-ineligible",
     "A killed mutant marked ineligible, which would shrink the eligible denominator without any equivalence argument at all. Separate branch, same code, its own fixture.",
     ["MUT_ELIGIBILITY_MISLABELLED"],
     lambda m: m["populations"][0]["records"][0].update({"eligible": False}))

case("source-tool-invalid", "AC1 normalizes the output of PIT and cargo-mutants and of nothing else.",
     ["MUT_SOURCE_TOOL_INVALID"], lambda m: m["populations"][0]["records"][0].update({"source_tool": "some-other-tool"}))

case("raw-status-absent", "Without the tool's own word, the normalization into an AC1 class cannot be audited.",
     ["MUT_RAW_STATUS_ABSENT"], lambda m: m["populations"][0]["records"][0].update({"raw_status": ""}))

# --- AC2: equivalent / technically-unviable gating ---------------------------
case("equivalence-evidence-absent", "An equivalent classification with no technical evidence. AC2 requires it.",
     ["MUT_EQUIVALENCE_EVIDENCE_ABSENT"], lambda m: m["populations"][0]["records"][1].update({"evidence": ""}))

case("equivalence-review-absent",
     "An equivalent classification with impeccable technical evidence and NO independent explicit review. This is the exact shape of mutants/e1-ws-core-manifest.json's four EQUIVALENT_DOCUMENTED entries today.",
     ["MUT_EQUIVALENCE_REVIEW_ABSENT"], lambda m: m["populations"][0]["records"][1].update({"review_ids": []}))

case("review-record-missing", "A review cited by id that the manifest does not carry.",
     ["MUT_REVIEW_RECORD_MISSING"], lambda m: m["populations"][0]["records"][1].update({"review_ids": ["rv-nonexistent"]}))

case("review-not-independent", "A review by someone who is not an independent reviewer. Self-review is not review.",
     ["MUT_REVIEW_NOT_INDEPENDENT"], lambda m: m["reviews"][0].update({"role": "author"}))

case("review-not-blind", "A non-blind review. The master story requires DUAL-BLIND independent review of these two classes.",
     ["MUT_REVIEW_NOT_BLIND"], lambda m: m["reviews"][0].update({"blind": False}))

case("review-not-approved", "A review that rejected the classification, recorded as if it had settled it.",
     ["MUT_REVIEW_NOT_APPROVED"], lambda m: m["reviews"][0].update({"disposition": "REJECT"}))

case("technically-unviable-needs-the-same-gates",
     "The second ineligible class carries exactly the same two gates as the first. A mutant reclassified technically-unviable without evidence and review leaves the eligible set for free.",
     ["MUT_EQUIVALENCE_EVIDENCE_ABSENT", "MUT_EQUIVALENCE_REVIEW_ABSENT", "MUT_CLASS_TALLY_DRIFT"],
     lambda m: m["populations"][0]["records"][1].update({"disposition": "technically_unviable", "evidence": "", "review_ids": []}))

# --- AC2: the score ----------------------------------------------------------
case("denominator-total-drift", "The declared denominator disagrees with the records.",
     ["MUT_DENOMINATOR_TOTAL_DRIFT"], lambda m: m["score"].update({"denominator_total": 99}))

case("eligible-total-drift", "The declared eligible total disagrees with the records.",
     ["MUT_ELIGIBLE_TOTAL_DRIFT"], lambda m: m["score"].update({"eligible_total": 99}))

case("killed-total-drift", "The declared kill count disagrees with the records.",
     ["MUT_KILLED_TOTAL_DRIFT"], lambda m: m["score"].update({"killed_total": 99}))

case("missed-total-drift", "The declared missed count disagrees with the records -- the direction that matters, since a declared 0 over a real survivor is the whole game.",
     ["MUT_MISSED_TOTAL_DRIFT"], lambda m: m["score"].update({"missed_total": 7}))

case("score-percent-drift", "The declared percentage disagrees with killed/eligible.",
     ["MUT_SCORE_PERCENT_DRIFT"], lambda m: m["score"].update({"eligible_score_percent": 99.9}))

case("missed-nonzero-survivor",
     "A real survivor. AC2 requires zero MISSED, and a survivor is MISSED however the summary is worded.",
     ["MUT_MISSED_NONZERO", "MUT_MISSED_TOTAL_DRIFT", "MUT_KILLED_TOTAL_DRIFT",
      "MUT_SCORE_PERCENT_DRIFT", "MUT_CLASS_TALLY_DRIFT"],
     lambda m: m["populations"][0]["records"][0].update({"disposition": "survived", "raw_status": "SURVIVED"}))

case("missed-nonzero-uncovered",
     "An uncovered mutant is MISSED too. So are not_executed, timeout, tool_failure and flaky: none of them is a demonstration that a test caught anything.",
     ["MUT_MISSED_NONZERO", "MUT_MISSED_TOTAL_DRIFT", "MUT_KILLED_TOTAL_DRIFT",
      "MUT_SCORE_PERCENT_DRIFT", "MUT_CLASS_TALLY_DRIFT"],
     lambda m: m["populations"][0]["records"][0].update({"disposition": "uncovered", "raw_status": "NO_COVERAGE"}))

case("score-claimed-computable-over-unenumerated-population",
     "A score declared computable while a population was never enumerated. A ratio over a fragment of the surface is not the eligible mutation score of the surface.",
     ["MUT_SCORE_NOT_COMPUTABLE", "MUT_POPULATION_NOT_ENUMERATED", "UNAVAILABLE_REPRESENTED_AS_SKIP",
      "MUT_SURFACE_HAS_NO_POPULATION"],
     lambda m: (m["surfaces"].append({"id": "prod2", "kind": "production", "language": "java",
                                      "paths": ["java-oracle/src/test/java"], "file_count": 1,
                                      "digest": JAVA_TEST_DIGEST, "note": "fixture"}),
                m["populations"].append({"id": "pop-b", "surface": "prod2", "engine": "engine-a",
                                         "enumeration_status": "NOT_ENUMERATED_ENGINE_UNAVAILABLE",
                                         "provenance": "tool_enumerated", "source_manifest": "",
                                         "source_manifest_key": "", "declared_total": 0,
                                         "classes": {}, "records": [], "rationale": "fixture"}),
                m["surfaces"].append({"id": "prod3", "kind": "production", "language": "java",
                                      "paths": ["java-oracle/src/main/java"], "file_count": 5,
                                      "digest": JAVA_PROD_DIGEST, "note": "fixture"})))

case("score-honestly-not-computable",
     "THE SHIPPED ARTIFACT'S OWN SHAPE. The engine is absent, the population is honestly parked as unenumerated, the arms are honestly parked, and the score is honestly declared zero and NOT computable. Every one of those admissions is accurate -- and the verdict is still BLOCKED. Zero MISSED out of zero eligible is not a 100% eligible mutation score, and the honest way of saying so does not earn a pass. Added after the deletion attack found this branch had no witness.",
     ["MUT_ENGINE_UNAVAILABLE", "MUT_POPULATION_NOT_ENUMERATED", "MUT_SCORE_NOT_COMPUTABLE", "MUT_ARM_NOT_RUN"],
     lambda m: (m["engines"][0].update({"probe_command": ["cargo", "definitely-not-a-subcommand"]}),
                m["populations"][0].update({"enumeration_status": "NOT_ENUMERATED_ENGINE_UNAVAILABLE",
                                            "declared_total": 0, "classes": {}, "records": []}),
                m["score"].update({"denominator_total": 0, "eligible_total": 0, "killed_total": 0,
                                   "missed_total": 0, "eligible_score_percent": 0.0, "computable": False}),
                [a.update({"mutation_run_status": "NOT_RUN_ENGINE_UNAVAILABLE"}) for a in m["arms"]]))

# --- AC3 --------------------------------------------------------------------
case("reconciliation-leg-absent", "One of AC3's four required runs is not recorded at all.",
     ["MUT_RECONCILIATION_LEG_ABSENT"], lambda m: m["test_integrity"].update({"legs": m["test_integrity"]["legs"][:3]}))

case("reconciliation-leg-not-run", "A required run recorded as not run.",
     ["MUT_RECONCILIATION_LEG_NOT_RUN"], lambda m: m["test_integrity"]["legs"][3].update({"status": "NOT_RUN"}))

case("test-surface-mutated-across-campaign",
     "THE AC3 RULE. The test surface digest moved between the before and after readings: some test changed while the mutants were running, which is exactly what AC3 forbids.",
     ["MUT_TEST_SURFACE_MUTATED"], lambda m: m["test_integrity"].update({"test_surface_digest_after": "sha256:" + "1" * 64}))

case("test-surface-drifted-from-tree",
     "Before and after agree with each other and neither is the tree. A pinned pair that stopped describing the repository proves nothing.",
     ["MUT_TEST_SURFACE_MUTATED"],
     lambda m: m["test_integrity"].update({"test_surface_digest_before": "sha256:" + "2" * 64,
                                           "test_surface_digest_after": "sha256:" + "2" * 64}))

case("test-surface-unreadable", "A declared test surface that is not on disk.",
     ["MUT_TEST_SURFACE_MUTATED", "MUT_SURFACE_DIGEST_DRIFT"],
     lambda m: m["surfaces"][1].update({"paths": ["no/such/tests"]}))

# --- AC4 --------------------------------------------------------------------
case("arm-missing", "AC4 governs the hidden and sealed runs by name; an absent arm is an ungoverned one.",
     ["MUT_ARM_MISSING"], lambda m: m["arms"].pop())

case("arm-separation-dimension-missing", "One of AC4's six dimensions undeclared.",
     ["MUT_ARM_SEPARATION_DIMENSION_MISSING"], lambda m: m["arms"][0]["separation"].pop("cache"))

case("arm-separation-shared",
     "THE AC4 RULE. Hidden and sealed share one credential. A shared credential is the leakage channel AC4 exists to close, and it is exactly what corpora/hidden and corpora/sealed record today.",
     ["MUT_ARM_SEPARATION_SHARED"],
     lambda m: m["arms"][1]["separation"]["credential"].update({"declared": "hidden-credential"}))

case("arm-separation-witness-unreadable",
     "A dimension whose witness names a file or field that cannot be read. A separation dimension whose witness cannot be read is a promise, not a reading.",
     ["MUT_ARM_SEPARATION_WITNESS_UNREADABLE"],
     lambda m: m["arms"][0]["separation"]["credential"].update({"source": "corpora/hidden/manifest.json", "field": "no.such.field"}))

case("arm-separation-witness-drift",
     "A dimension whose declared value is not what the named file actually says. This is the difference between a declaration and a reading.",
     ["MUT_ARM_SEPARATION_WITNESS_DRIFT"],
     lambda m: m["arms"][0]["separation"]["credential"].update({"source": "corpora/hidden/manifest.json",
                                                               "field": "generator.secret_seed_commitment"}))

case("arm-network-denial-undeclared", "AC4 requires candidate execution to deny network APIs.",
     ["MUT_ARM_NETWORK_DENIAL_UNDECLARED"], lambda m: m["arms"][0].update({"network_denial": ""}))

case("arm-protected-store-denial-undeclared", "AC4 requires candidate execution to deny protected-store APIs.",
     ["MUT_ARM_PROTECTED_STORE_DENIAL_UNDECLARED"], lambda m: m["arms"][0].update({"protected_store_denial": ""}))

case("arm-budget-not-monotonic", "AC4 requires monotonic budgets and anti-evasion.",
     ["MUT_ARM_BUDGET_NOT_MONOTONIC"], lambda m: m["arms"][0].update({"budget_monotonic": False}))

case("arm-diagnostic-policy-absent", "AC4 releases only policy-limited diagnostics.",
     ["MUT_ARM_DIAGNOSTIC_POLICY_ABSENT"], lambda m: m["arms"][0].update({"diagnostic_policy": ""}))

# --- AC5 --------------------------------------------------------------------
case("ac5-leg-absent", "One of AC5's six clauses not recorded.",
     ["MUT_AC5_LEG_ABSENT"], lambda m: m["ac5_legs"].pop())

case("ac5-leg-not-passed", "An AC5 clause recorded as anything other than PASSED.",
     ["MUT_AC5_LEG_NOT_PASSED"], lambda m: m["ac5_legs"][5].update({"status": "NOT_RUN"}))

# --- AC1: signature ----------------------------------------------------------
case("signature-absent", "AC1 requires ONE SIGNED denominator. An unsigned one is a draft. The unsigned fixture also has no declared payload digest and no key, and all three absences are reported rather than folded into one.",
     ["MUT_SIGNATURE_ABSENT", "MUT_PAYLOAD_DIGEST_DRIFT", "MUT_SIGNING_KEY_ABSENT"], lambda m: None, resign=False)

case("signature-scheme-invalid", "A signature scheme this repository does not use.",
     ["MUT_SIGNATURE_SCHEME_INVALID"], lambda m: m["signature"].update({"scheme": "hmac-sha1"}))

case("payload-digest-drift",
     "A properly signed fixture whose DECLARED payload digest was then edited. Because the digest covers every field but the signature's own two, no surface, population, record, arm or claim can drift under it unnoticed. Applied AFTER signing, or the signer would simply restamp it.",
     ["MUT_PAYLOAD_DIGEST_DRIFT"], lambda m: None,
     post=lambda m: m["signature"].update({"payload_digest": "sha256:" + "3" * 64}))

case("signature-does-not-verify",
     "A signature of the right shape over the wrong thing. Present-but-unverifiable is worse than absent, because it looks signed, so it raises the same BLOCK.",
     ["MUT_SIGNATURE_ABSENT"], lambda m: None,
     post=lambda m: m["signature"].update({"signature": "ab" * 64}))

case("signature-key-unusable",
     "A signature accompanied by a key that is not a usable Ed25519 key. Its own finding code, not the absent-key one: the deletion attack found that sharing a code let a deletion of either branch hide behind the other.",
     ["MUT_SIGNATURE_KEY_UNUSABLE", "MUT_PAYLOAD_DIGEST_DRIFT"], lambda m: None,
     post=lambda m: m["signature"].update({"public_key_hex": "not-hexadecimal-at-all"}))

case("signing-key-absent", "A signature with no key to check it against. An unverifiable signature is not a signature. The key is inside the signed payload, so removing it moves the digest too -- which is the point: the key identity cannot be swapped under a signature.",
     ["MUT_SIGNING_KEY_ABSENT", "MUT_PAYLOAD_DIGEST_DRIFT"], lambda m: None,
     post=lambda m: m["signature"].update({"public_key_hex": ""}))

# --- the claim ---------------------------------------------------------------
case("claim-outruns-findings",
     "A manifest claiming an AC met while a BLOCK stands. This is the rule that stops the document from grading itself.",
     ["UNAVAILABLE_REPRESENTED_AS_SUCCESS", "MUT_ARM_DIAGNOSTIC_POLICY_ABSENT"],
     lambda m: (m["arms"][0].update({"diagnostic_policy": ""}), m["claim"].update({"ac4_met": True})))

case("claim-grade-invalid", "A claim grade outside the program's assurance vocabulary.",
     ["MUT_CLAIM_GRADE_INVALID"], lambda m: m["claim"].update({"claim_grade": "pretty-good"}))

catalog = {
    "schema_version": "1.0.0",
    "story": "US-022",
    "note": (
        "Polarity suite for internal/mutdenom, driven through the REAL checker by "
        "`mutdenomctl -replay-fixtures`. Each case pins an exact exit code, state, and set of "
        "typed BLOCK codes. Exactly ONE case (`green`) expects OK: without it a checker that "
        "blocked unconditionally would pass this whole suite, and the runner refuses a catalog "
        "with no green case for that reason. Every other case carries a SINGLE mutation of the "
        "green base, so the rule it targets is the reason it is red. None of these manifests is "
        "evidence about US-022; the green one in particular describes a campaign that never "
        "happened and claims nothing."
    ),
    "cases": CASES,
}
with open(os.path.join(FIXDIR, "cases.json"), "w") as fh:
    json.dump(catalog, fh, indent=2)
    fh.write("\n")
print("wrote %d cases" % len(CASES))
