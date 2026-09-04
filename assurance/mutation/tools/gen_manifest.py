#!/usr/bin/env python3
"""Generate assurance/mutation/denominator.json.

Every digest below was emitted by `mutdenomctl -emit-digest` against this tree
and is re-derived by `mutdenomctl -check`; none of them is typed from memory.
"""
import json, os, sys

ROOT = sys.argv[1]

AC = {
    "ac1": "PIT and cargo-mutants run from promoted tool/dependency graphs against the declared production and test surfaces and normalize killed, survived, not-executed, uncovered, timeout, tool-failure, flaky, equivalent, and technically-unviable dispositions into one signed denominator.",
    "ac2": "Eligible mutation score is 100% with zero MISSED; every equivalent or technically unviable classification remains visible in the denominator, has technical evidence, and receives independent explicit review.",
    "ac3": "No requirement-bearing Java or Rust test is deleted, weakened, skipped, filtered, or replaced because a mutant or runtime makes it inconvenient; no-stub and test-manifest reconciliation run before and after mutation.",
    "ac4": "Hidden and sealed runs use separate identities, filesystems, caches, credentials, signing keys, and workspaces; candidate execution denies network/protected-store APIs, enforces monotonic budgets and anti-evasion, and releases only policy-limited diagnostics.",
    "ac5": "Pinned Java passes 100%, empty/stub Rust and planted mutants fail, the candidate passes, all cases reconcile, and zero protected case, output, raw diagnostic, or oracle secret enters public artifacts.",
}

STATEMENT = (
    "The US-022 normalized mutation denominator. This document is CHECKED, not asserted: "
    "cmd/mutdenomctl -check re-derives every surface digest from the tree, executes every "
    "engine probe and reads its exit code from the real ProcessState, recomputes the "
    "denominator, eligible, killed and missed totals and the eligible score from the "
    "records themselves, requires every mutant to land in exactly one of the nine AC1 "
    "disposition classes, and reads each AC4 separation witness out of the file it names. "
    "The state it reports today is BLOCKED, and that is the honest answer: NEITHER ENGINE "
    "IS INSTALLED, no PIT run and no cargo-mutants run has ever happened in this "
    "repository, and therefore no mutant population over the declared surfaces has ever "
    "been enumerated. A denominator is a count OF a population; with no population there "
    "is no denominator, and a score computed over nothing is not a score."
)

NOTE = (
    "Two substitutions this document refuses, both instances of the defect class this "
    "program keeps rediscovering -- existence standing in for identity. (1) A CORPUS "
    "MANIFEST IS NOT A PROTECTED EVALUATION. corpora/hidden/manifest.json and "
    "corpora/sealed/manifest.json are US-005 outputs: they record 92 executed behaviour "
    "scenarios per tier with a commitment root and a transcript digest. They record no "
    "mutant, no mutation engine, no disposition, and no separation of identity, cache, "
    "credential, signing key or workspace between the two tiers. They are cited here only "
    "as the AC4 separation witnesses this check READS, never as evidence that AC4 is met. "
    "(2) AN AC5 MUTANT CATALOGUE IS NOT A NORMALIZED MUTATION DENOMINATOR. "
    "mutants/e1-ws-core-manifest.json holds 76 hand-curated exact-literal substitutions "
    "at named ws-core sites, produced by cmd/mutctl for US-012..US-016 AC5 and extended "
    "this session by the AC5 class-completeness work. It is real evidence and it is good "
    "evidence, and it is not this. Its 76 mutants were CHOSEN; they were not enumerated by "
    "cargo-mutants over rust/ws-core/src, so the mutants nobody wrote down were never "
    "counted and the set has no denominator relationship to the surface. Its vocabulary is "
    "five verdicts (KILLED_BY_TESTS, KILLED_BY_CORPUS, SURVIVOR, BUILD_FAILED, "
    "EQUIVALENT_DOCUMENTED), not AC1's nine dispositions; it has no not_executed, no "
    "uncovered, no timeout, no flaky and no technically_unviable class at all. Its four "
    "EQUIVALENT_DOCUMENTED entries carry genuine technical evidence (exhaustive in-test "
    "witnesses) and ZERO independent explicit review -- mutants/manifest.json records "
    "independent_review_claimed:false -- so under AC2 all four would block today. "
    "`mutdenomctl -normalize-e1` reads that file from disk and prints the nine-class "
    "normalization of every one of its 76 entries so the refusal is a reading and not an "
    "opinion; the catalogue is deliberately NOT carried here as a population, because "
    "carrying it would be the substitution."
)

manifest = {
    "schema_version": "1.0.0",
    "document_id": "us022-normalized-mutation-denominator",
    "entity_type": "NormalizedMutationDenominator",
    "story": "US-022",
    "digest_scheme": "CANONICAL_PATH_SHA256_V1",
    "statement": STATEMENT,
    "ac_verbatim": AC,
    "note": NOTE,
    "engines": [
        {
            "id": "cargo-mutants",
            "kind": "rust_mutation",
            "tool": "cargo-mutants",
            "probe_command": ["cargo", "mutants", "--version"],
            "probe_dir": "rust",
            "toolchain": {
                "required": "Rust 1.95.0 (rust/rust-toolchain.toml)",
                "probe_command": ["cargo", "--version"],
                "probe_dir": "rust",
                "version_pattern": "1.95.0",
            },
            "dependency_graph": {
                "status": "NOT_PROMOTED",
                "promotion_record": "",
                "note": (
                    "No promoted tool/dependency graph exists for cargo-mutants. The binary is "
                    "absent from ~/.cargo/bin (cargo, cargo-clippy, cargo-fmt, cargo-miri, "
                    "rustfmt, rustup and the rustc/rustdoc drivers are present; cargo-mutants is "
                    "not), rust/Cargo.toml declares no such dev-dependency, and this environment's "
                    "proxy blocks acquisition. Installing it is out of scope for this story and "
                    "would change the pinned toolchain the whole project depends on."
                ),
            },
            "note": (
                "AC1 names this engine. Its absence is read from the host, not assumed: the probe "
                "exit code below comes from the real ProcessState."
            ),
        },
        {
            "id": "pit",
            "kind": "java_mutation",
            "tool": "org.pitest:pitest-maven",
            "probe_command": ["mvn", "-o", "-q", "org.pitest:pitest-maven:help"],
            "probe_dir": "java-oracle",
            "toolchain": {
                "required": "OpenJDK 17.0.19 (the promoted laboratory JDK, docs/prd-pack/07a-child-prd-header-index-us001-008.md)",
                "probe_command": ["java", "-version"],
                "probe_dir": ".",
                "version_pattern": "17.0.19",
            },
            "dependency_graph": {
                "status": "NOT_PROMOTED",
                "promotion_record": "",
                "note": (
                    "No promoted tool/dependency graph exists for PIT. There is not one reference "
                    "to pitest, org.pitest or pit-maven anywhere in this repository: java-oracle/"
                    "pom.xml declares resources, compiler, surefire, antrun and jar plugins and no "
                    "mutation plugin, and no PIT report has ever been written. PIT additionally "
                    "needs the promoted OpenJDK 17.0.19 and the quarantined Java-WebSocket 1.6.0 "
                    "tree, and this environment has neither: only OpenJDK 21.0.10 is installed, and "
                    ".quarantine is a self-referential symlink that resolves to nothing."
                ),
            },
            "note": (
                "AC1 names this engine. The probe runs Maven offline so a network failure cannot "
                "be mistaken for the plugin being present."
            ),
        },
    ],
    "surfaces": [
        {
            "id": "rust-ws-core-production",
            "kind": "production",
            "language": "rust",
            "paths": ["rust/ws-core/src"],
            "file_count": 16,
            "digest": "sha256:39030e01d73a835db6028757a786c468f36f674ad5e966902cc24dd4778d62e3",
            "note": "The shipped protocol core: framing, message/UTF-8, close, fragment, control, connection, queue, config, error, event and the four handshake modules.",
        },
        {
            "id": "rust-ws-driver-production",
            "kind": "production",
            "language": "rust",
            "paths": ["rust/ws-driver/src"],
            "file_count": 1,
            "digest": "sha256:f5984f557c245465ace5323828c5c877433f0fcb4726fa370edf81a37d42ae86",
            "note": "The owner-driver seam. Named as its own surface because AC1 mutates DECLARED surfaces and a surface folded into another one has no denominator of its own.",
        },
        {
            "id": "java-oracle-production",
            "kind": "production",
            "language": "java",
            "paths": ["java-oracle/src/main/java"],
            "file_count": 5,
            "digest": "sha256:29773c46596aafef879b1e536b51e2dd1fc42b08b16e3987f71b33854f3bda17",
            "note": "The retained Java oracle adapter. NOTE, and this is a real open question this document does not settle: AC1 says PIT runs against 'the declared production surface', and the Java production code actually under port is Java-WebSocket 1.6.0 in .quarantine, not this adapter. No record in this repository declares which of the two PIT's subject is. Whoever schedules US-022 must decide that before a PIT run means anything, and the decision belongs in the delta ledger, not here.",
        },
        {
            "id": "rust-ws-core-tests",
            "kind": "test",
            "language": "rust",
            "paths": ["rust/ws-core/tests"],
            "file_count": 22,
            "digest": "sha256:1ba964d6539026cace142036c13494e294ac304e8fde73cd739451b8d15ad71c",
            "note": "AC1 names the test surface as well as the production surface: PIT and cargo-mutants both need to know which tests are the judges.",
        },
        {
            "id": "rust-ws-driver-tests",
            "kind": "test",
            "language": "rust",
            "paths": ["rust/ws-driver/tests"],
            "file_count": 7,
            "digest": "sha256:388761c0bdd34383d589e051030e83247d099ab2c8aed85bbf75edd4f44bce97",
            "note": "Driver-seam judges, including the schedule explorer and its minimizer.",
        },
        {
            "id": "java-oracle-tests",
            "kind": "test",
            "language": "java",
            "paths": ["java-oracle/src/test/java"],
            "file_count": 1,
            "digest": "sha256:9e47ecae95d63e33040d20fb4ee5e9342e08f4df1df32498f38e4db51a6bef40",
            "note": "The single Java adapter test. One file is a small judge set for a PIT campaign, and that is itself a fact the eventual campaign will have to report rather than hide.",
        },
    ],
    "populations": [
        {
            "id": "pop-rust-ws-core-cargo-mutants",
            "surface": "rust-ws-core-production",
            "engine": "cargo-mutants",
            "enumeration_status": "NOT_ENUMERATED_ENGINE_UNAVAILABLE",
            "provenance": "tool_enumerated",
            "source_manifest": "",
            "source_manifest_key": "",
            "declared_total": 0,
            "classes": {},
            "records": [],
            "rationale": "cargo-mutants has never been run against rust/ws-core/src. The engine is not installed, so the mutant population over this surface is unknown -- not zero, unknown. This is recorded, never skipped.",
        },
        {
            "id": "pop-rust-ws-driver-cargo-mutants",
            "surface": "rust-ws-driver-production",
            "engine": "cargo-mutants",
            "enumeration_status": "NOT_ENUMERATED_ENGINE_UNAVAILABLE",
            "provenance": "tool_enumerated",
            "source_manifest": "",
            "source_manifest_key": "",
            "declared_total": 0,
            "classes": {},
            "records": [],
            "rationale": "cargo-mutants has never been run against rust/ws-driver/src. Not one mutant of this surface exists anywhere in the repository, curated or enumerated: the 76 entries of mutants/e1-ws-core-manifest.json are all in rust/ws-core/src.",
        },
        {
            "id": "pop-java-oracle-pit",
            "surface": "java-oracle-production",
            "engine": "pit",
            "enumeration_status": "NOT_ENUMERATED_ENGINE_UNAVAILABLE",
            "provenance": "tool_enumerated",
            "source_manifest": "",
            "source_manifest_key": "",
            "declared_total": 0,
            "classes": {},
            "records": [],
            "rationale": "PIT has never been run against any Java surface in this repository. The two Java mutants that exist (mutants/java/us005-jm-close-code-1000 and us005-jm-utf8-accept) are hand-written whole-file overlays staged by cmd/us005-mutantctl for the US-005 planted-mutant calibration gate; they are not PIT output, they carry no PIT status, and two chosen overlays are not an enumerated population.",
        },
    ],
    "reviews": [],
    "score": {
        "denominator_total": 0,
        "eligible_total": 0,
        "killed_total": 0,
        "missed_total": 0,
        "eligible_score_percent": 0.0,
        "computable": False,
        "note": "Every field here is recomputed from the records by the checker; the declared values exist only so a drift between claim and records is a finding rather than a matter of opinion. All are zero because no population was ever enumerated. Zero MISSED out of zero eligible is NOT a 100% eligible mutation score and must never be reported as one -- that is precisely why MUT_SCORE_NOT_COMPUTABLE blocks whenever any population is unenumerated.",
    },
    "test_integrity": {
        "legs": [
            {
                "id": "no-stub-before",
                "status": "NOT_RUN",
                "command": "make -C rust gates (no-stub leg), before the mutation campaign",
                "exit": -998,
                "note": "AC3 requires this before mutation. No mutation campaign exists to run it before, so the leg has no meaning yet and is recorded NOT_RUN rather than fabricated. exit -998 is the repo's sentinel for 'no ProcessState existed'; it is not an exit code.",
            },
            {
                "id": "no-stub-after",
                "status": "NOT_RUN",
                "command": "make -C rust gates (no-stub leg), after the mutation campaign",
                "exit": -998,
                "note": "Same: there is no 'after' because there is no campaign.",
            },
            {
                "id": "test-manifest-before",
                "status": "NOT_RUN",
                "command": "exact test-manifest reconciliation, before the mutation campaign",
                "exit": -998,
                "note": "Same.",
            },
            {
                "id": "test-manifest-after",
                "status": "NOT_RUN",
                "command": "exact test-manifest reconciliation, after the mutation campaign",
                "exit": -998,
                "note": "Same. The 'after' leg is the load-bearing one: it is what would catch a test deleted, weakened, skipped, filtered or replaced during the campaign.",
            },
        ],
        "test_surface_digest_before": "sha256:476fb186a97ba7d25b3de26721ac7e097d1d32238ee32185be90153dbba9f1fd",
        "test_surface_digest_after": "sha256:476fb186a97ba7d25b3de26721ac7e097d1d32238ee32185be90153dbba9f1fd",
        "note": "Both digests are the SAME reading of the same tree taken at the same moment, because no campaign ran between them. The equality therefore proves nothing about AC3 today and must not be read as if it did; what it does is bind the check, so that once a campaign does run, a test that moved during it becomes MUT_TEST_SURFACE_MUTATED instead of a paragraph nobody re-derives. This branch deleted, skipped, filtered and weakened no test: it adds internal/mutdenom, cmd/mutdenomctl and this artifact and modifies no pre-existing file.",
    },
    "arms": [
        {
            "id": "hidden",
            "mutation_run_status": "NOT_RUN_ENGINE_UNAVAILABLE",
            "separation": {
                "identity": {
                    "declared": "",
                    "source": "",
                    "field": "",
                    "note": "a custodian identity distinct from the sealed arm's, recorded per tier and bound to the run; the check would read that identity out of the hidden run's own receipt and require it to differ from the sealed receipt's. Today no such field exists: the only custodian record in corpora/hidden/manifest.json is custodian.policy_digest, which is a POLICY digest, not an identity, and it is byte-identical to the sealed tier's.",
                },
                "filesystem": {
                    "declared": "us005-corpora/hidden/scenarios.jsonl",
                    "source": "corpora/hidden/manifest.json",
                    "field": "artifacts.0.path",
                    "note": "the protected-store path this tier's data lives under. This one IS readable today and the two tiers do differ, which is why this dimension is the only one of the six that passes -- and it is the weakest of the six, because a distinct path is not a distinct filesystem.",
                },
                "cache": {
                    "declared": "",
                    "source": "",
                    "field": "",
                    "note": "a build/tool cache root used by the hidden run and by nothing else; the check would read the cache root out of the run receipt and require it to differ from the sealed arm's and to be outside the public workspace. No per-tier cache is recorded anywhere in this repository.",
                },
                "credential": {
                    "declared": "sha256:08ae5e87916ad20c76dd4d7450e23a87cb966ad4e8ed58be4dffd8430173f331",
                    "source": "corpora/hidden/manifest.json",
                    "field": "generator.secret_seed_commitment",
                    "note": "the secret material the tier's generator was seeded from. The check reads it and requires the two tiers to differ. They do NOT differ: this is the same commitment the sealed tier records, which is the finding.",
                },
                "signing_key": {
                    "declared": "",
                    "source": "",
                    "field": "",
                    "note": "a signing key distinct from the sealed arm's, so a hidden receipt cannot be minted by whoever holds the sealed key; the check would read the key id from the run receipt and require it to differ. Today neither tier is signed at all -- corpora/hidden/manifest.json and corpora/sealed/manifest.json both record signing:false -- so there is no key to be separate.",
                },
                "workspace": {
                    "declared": "",
                    "source": "",
                    "field": "",
                    "note": "a checkout the hidden run owns exclusively; the check would read the workspace root from the run receipt, require it to differ from the sealed arm's, and require it to be neither the public checkout nor a parent or child of the sealed workspace (resolved identity via EvalSymlinks and path-component comparison, never a string prefix -- the containment discipline mutants/e1-ws-core-manifest.json already documents). No per-tier workspace is recorded anywhere.",
                },
            },
            "network_denial": "",
            "protected_store_denial": "",
            "budget_monotonic": False,
            "budget_basis": "",
            "anti_evasion": "",
            "diagnostic_policy": "",
            "rationale": "No mutation campaign has run on the hidden arm, because neither mutation engine is installed. The hidden tier's 92 behaviour scenarios were executed by corporactl for US-005; that is a corpus evaluation, not a mutation run, and it is not this.",
        },
        {
            "id": "sealed",
            "mutation_run_status": "NOT_RUN_ENGINE_UNAVAILABLE",
            "separation": {
                "identity": {
                    "declared": "",
                    "source": "",
                    "field": "",
                    "note": "as for the hidden arm, and with the same absence: custodian.policy_digest in corpora/sealed/manifest.json is identical to the hidden tier's.",
                },
                "filesystem": {
                    "declared": "us005-corpora/sealed/scenarios.jsonl",
                    "source": "corpora/sealed/manifest.json",
                    "field": "artifacts.0.path",
                    "note": "the protected-store path this tier's data lives under.",
                },
                "cache": {
                    "declared": "",
                    "source": "",
                    "field": "",
                    "note": "as for the hidden arm; no per-tier cache is recorded anywhere.",
                },
                "credential": {
                    "declared": "sha256:08ae5e87916ad20c76dd4d7450e23a87cb966ad4e8ed58be4dffd8430173f331",
                    "source": "corpora/sealed/manifest.json",
                    "field": "generator.secret_seed_commitment",
                    "note": "read from the sealed manifest, and byte-identical to the hidden tier's. Two tiers seeded from one secret are one credential wearing two names.",
                },
                "signing_key": {
                    "declared": "",
                    "source": "",
                    "field": "",
                    "note": "as for the hidden arm; corpora/sealed/manifest.json records signing:false.",
                },
                "workspace": {
                    "declared": "",
                    "source": "",
                    "field": "",
                    "note": "as for the hidden arm; no per-tier workspace is recorded anywhere.",
                },
            },
            "network_denial": "",
            "protected_store_denial": "",
            "budget_monotonic": False,
            "budget_basis": "",
            "anti_evasion": "",
            "diagnostic_policy": "",
            "rationale": "No mutation campaign has run on the sealed arm, for the same reason. Note also that corpora/hidden/manifest.json and corpora/sealed/manifest.json declare the SAME execution_evidence.report_sha256 (sha256:61e1ce89fb298787619603c12b2a90611347f91d591bdf33ba281591afb560e3); only their transcript digests differ. Whatever that shared report is, it is one artifact covering both tiers, which is the shape AC4 exists to forbid.",
        },
    ],
    "ac5_legs": [
        {
            "id": "pinned-java-passes-100",
            "requirement": "Pinned Java passes 100%",
            "status": "NOT_RUN",
            "evidence": "Not run under a mutation campaign. A pristine-Java public-tier separation of 74 executed / 74 passed is recorded in mutants/manifest.json for US-005, and that is a corpus run against the pristine oracle, not the AC5 leg of a mutation campaign that never happened. It also ran on OpenJDK 21.0.10, not the promoted OpenJDK 17.0.19.",
        },
        {
            "id": "empty-stub-rust-fails",
            "requirement": "empty/stub Rust fails",
            "status": "NOT_RUN",
            "evidence": "Not run under a mutation campaign. mutants/manifest.json records the inert rust/candidate-stub scoring 74 executed / 0 passed / 74 failed for US-005. Same distinction: real evidence, different story.",
        },
        {
            "id": "planted-mutants-fail",
            "requirement": "planted mutants fail",
            "status": "NOT_RUN",
            "evidence": "Not run under a mutation campaign. The two US-005 planted Java mutants are recorded killed on the public tier. Again US-005 calibration, not US-022.",
        },
        {
            "id": "candidate-passes",
            "requirement": "the candidate passes",
            "status": "NOT_RUN",
            "evidence": "Not run under a mutation campaign.",
        },
        {
            "id": "all-cases-reconcile",
            "requirement": "all cases reconcile",
            "status": "NOT_RUN",
            "evidence": "Not run under a mutation campaign.",
        },
        {
            "id": "zero-protected-leakage",
            "requirement": "zero protected case, output, raw diagnostic, or oracle secret enters public artifacts",
            "status": "NOT_RUN",
            "evidence": "No mutation campaign produced any artifact, public or otherwise, so there is nothing to have leaked and nothing to have checked. Absence of leakage from a run that did not happen is not a pass, and recording it as one would be the exact shape of dishonesty this story is about.",
        },
    ],
    "signature": {
        "scheme": "ed25519",
        "payload_scheme": "MUTDENOM_PAYLOAD_SHA256_V1",
        "key_id": "",
        "public_key_hex": "",
        "payload_digest": "sha256:5ee69126f992fe00c58af5ffffa17c3110e83a90fbde7b4a0c1b852767386509",
        "signature": "",
        "note": "AC1 requires ONE SIGNED denominator. The payload digest below covers this entire document with the signature's own two fields blanked, so there is no surface, population, record, arm or claim a signer could decline to cover; the checker recomputes it and blocks on drift. The signature itself is absent and blocks: the Ed25519 key material is held by the protected operator (internal/intake/sign.go takes it as an argument and this repository stores no private key), and this session has none. Signing a denominator that counts nothing would in any case be signing a draft.",
    },
    "claim": {
        "ac1_met": False,
        "ac2_met": False,
        "ac3_met": False,
        "ac4_met": False,
        "ac5_met": False,
        "claim_grade": "observed",
        "honest_state": "BLOCKED. The claim grade is 'observed' and describes ONLY what this document itself is: an executed census -- engine probes run and their exit codes read, surface digests re-derived, separation witnesses read out of the files that hold them. It is not a mutation campaign at any grade, because no mutation campaign exists. A census is not a campaign and a plan is not evidence.",
    },
}

out = os.path.join(ROOT, "assurance/mutation/denominator.json")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
print("wrote", out)
