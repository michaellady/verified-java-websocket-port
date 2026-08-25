package assurance

import vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"

type staticEvidenceNode struct {
	ID             string
	Path           string
	Classification string
}

type developerToolExpectation struct {
	Path      string
	ProfileID string
	Language  string
	Name      string
	Version   string
}

type schemaExpectation struct {
	SchemaPath string
	Artifact   string
	Finding    string
}

type retainedArtifactExpectation struct {
	Path string
	Kind string
}

var expectedUpstreamEntries = []upstreamManifestEntry{
	{SourcePath: "go.mod", TargetPath: "third_party/verified-java-to-rust-foundation/go.mod", SHA256: "sha256:f2f360abf946bd2dbed13f01f4813759f9d3daf54beb40b4afaf4302a6981e63"},
	{SourcePath: "go.sum", TargetPath: "third_party/verified-java-to-rust-foundation/go.sum", SHA256: "sha256:190d9eb7b0bf958a72cdfa38e70887ba644442b0389537f21fcf5eff3daf325f"},
	{SourcePath: "foundation/evidence.go", TargetPath: "third_party/verified-java-to-rust-foundation/foundation/evidence.go", SHA256: "sha256:5d3b66f7867199d9645007109a86590dbff8462f1718e0604624a5a7eee2ffe7"},
	{SourcePath: "foundation/evidence_schema.go", TargetPath: "third_party/verified-java-to-rust-foundation/foundation/evidence_schema.go", SHA256: "sha256:394b1f1047157cebf18d5115e4694c7a0928248847a722365c51ed43d236f92d"},
	{SourcePath: "foundation/validate.go", TargetPath: "third_party/verified-java-to-rust-foundation/foundation/validate.go", SHA256: "sha256:26733314351bb967e3dd3b7c84d34b208234c1dcbb67b68c68ba4a32fd3302a6"},
	{SourcePath: "protocol/canonical.go", TargetPath: "third_party/verified-java-to-rust-foundation/protocol/canonical.go", SHA256: "sha256:9deead477c7e58b3af00045cdb6e1e3aec98ca09226a49fe54f2c855b3616d49"},
	{SourcePath: "protocol/gateway.go", TargetPath: "third_party/verified-java-to-rust-foundation/protocol/gateway.go", SHA256: "sha256:3b69a055ce647808531e497978be37ec1251b10be1f3550c4cfdc10c00ef0ca1"},
	{SourcePath: "protocol/policy.go", TargetPath: "third_party/verified-java-to-rust-foundation/protocol/policy.go", SHA256: "sha256:908a0c721ad72fbc8f4995520648735635b45caa7686d5c36281a56a213b50e4"},
	{SourcePath: "protocol/promotion.go", TargetPath: "third_party/verified-java-to-rust-foundation/protocol/promotion.go", SHA256: "sha256:a9a23b78eeff1bfc257f858c6d0445d666eca2673d62ca699e230687117ccb73"},
	{SourcePath: "protocol/runner.go", TargetPath: "third_party/verified-java-to-rust-foundation/protocol/runner.go", SHA256: "sha256:b84d65160bec7968d369d36d8cd6494252fbaca18f29e20610333110b9469bc0"},
	{SourcePath: "protocol/types.go", TargetPath: "third_party/verified-java-to-rust-foundation/protocol/types.go", SHA256: "sha256:af5d4d3306ffe966d4bc5986070abc7018c55712067aed9ab48f20aeca3767bc"},
	{SourcePath: "validators/reference.go", TargetPath: "third_party/verified-java-to-rust-foundation/validators/reference.go", SHA256: "sha256:bb6697319cd9eea23ad474680d25ff5ef0e182188d353eee4ab05afd8e4d9b43"},
	{SourcePath: "validators/independent.go", TargetPath: "third_party/verified-java-to-rust-foundation/validators/independent.go", SHA256: "sha256:4f4cc4c95773ff8b6657c3bf553ec40ce45853b15bf9ea318bb8f6ae0b06c405"},
	{SourcePath: "validators/foundation_adapter.go", TargetPath: "third_party/verified-java-to-rust-foundation/validators/foundation_adapter.go", SHA256: "sha256:5ceeb0d6e556efe2bfba927d677943eaf9f89a8fba0c04e4823465e3a5d76a56"},
	{SourcePath: "protocol/schemas/checkpoint-1.0.0.schema.json", TargetPath: "third_party/verified-java-to-rust-foundation/protocol/schemas/checkpoint-1.0.0.schema.json", SHA256: "sha256:458c47c0e42ca440400a3638aa6f81b5056724b13add2cdbeb1248fbbb994d2b"},
	{SourcePath: "protocol/schemas/protocol-bundle-1.0.0.schema.json", TargetPath: "third_party/verified-java-to-rust-foundation/protocol/schemas/protocol-bundle-1.0.0.schema.json", SHA256: "sha256:fd5b1be0266d7b4f922d39e74878a410b9bd69de9449d4cd083eb4af2751f40a"},
	{SourcePath: "schemas/evidence-model-1.0.0.schema.json", TargetPath: "assurance/schema/evidence-model-1.0.0.schema.json", SHA256: "sha256:0e6c2a25c1bd3dd1d26818e6487baee7e5b4d5e58d411deddae40a1f01dcd5e0"},
	{SourcePath: "schemas/evidence-model-1.1.0.schema.json", TargetPath: "assurance/schema/evidence-model-1.1.0.schema.json", SHA256: "sha256:6eb952861989ec129c364f1fd2d320fcc6b8db4823f3d9a73e85b69db92fd134"},
	{SourcePath: "schemas/evolution-1.1.0.schema.json", TargetPath: "assurance/schema/evolution-1.1.0.schema.json", SHA256: "sha256:70896b77c1c3c20f6b697998db848927a27df196852c04ec590ee8a07d96159c"},
	{SourcePath: "schemas/developer-tool-run.schema.json", TargetPath: "assurance/schema/developer-tool-run.schema.json", SHA256: "sha256:a77b5d1bd2101c837fcef044178441d29932065fe9b794dff8f62fd4b3cd26ac"},
	{SourcePath: "schemas/java-intake.schema.json", TargetPath: "assurance/schema/java-intake.schema.json", SHA256: "sha256:cb9031a0b709ea11f4f3b5001bf06fe4cda99972e1418f528f8f7733e5dbf2af"},
	{SourcePath: "schemas/compatibility-surface.schema.json", TargetPath: "assurance/schema/compatibility-surface.schema.json", SHA256: "sha256:5407e7330e4368d35c9792d9334256e237c3e559733f410b599e02665fba2e90"},
	{SourcePath: "schemas/cutover-contract.schema.json", TargetPath: "assurance/schema/cutover-contract.schema.json", SHA256: "sha256:6a8a65a7efd83917a88c354e8f9bb96cb7e27a8a601600720b5fbeaa2e8d2176"},
	{SourcePath: "schemas/port-seam-dossier.schema.json", TargetPath: "assurance/schema/port-seam-dossier.schema.json", SHA256: "sha256:41ebe1939fbcdfc544495f0f40ae30b0773b12825117fd2e9a365585c25ff0d1"},
	{SourcePath: "schemas/behavior-delta-ledger.schema.json", TargetPath: "assurance/schema/behavior-delta-ledger.schema.json", SHA256: "sha256:06303bd6d2ac8c316dc065fbe35bcc13f50a4eb57fd0a8a83f09547f7091e0cc"},
	{SourcePath: "schemas/language-intelligence-profile.schema.json", TargetPath: "assurance/schema/language-intelligence-profile.schema.json", SHA256: "sha256:41b2b0848155a21abd5dce21e4958ee135e5086efd91fd6e42f379459fe90741"},
	{SourcePath: "schemas/profile-switching.schema.json", TargetPath: "assurance/schema/profile-switching.schema.json", SHA256: "sha256:5d176e257e036ca41e85cd801d1c41d0c6f4c72e2f7e6b9ec770267d19ab18f7"},
	{SourcePath: "schemas/navigation-corpus.schema.json", TargetPath: "assurance/schema/navigation-corpus.schema.json", SHA256: "sha256:68c0e6be3ce62e4b0c8ad2362ab12e31beaa12b9e5b7236db344554f5ce20446"},
}

var expectedEvidenceNodes = []staticEvidenceNode{
	{ID: "evidence-upstream-manifest", Path: upstreamManifestPath, Classification: "PUBLIC"},
	{ID: "evidence-evidence-model", Path: evidenceModelPath, Classification: "PUBLIC"},
	{ID: "evidence-evolution", Path: evolutionPath, Classification: "PUBLIC_DERIVED"},
	{ID: "evidence-failures", Path: failuresPath, Classification: "PUBLIC"},
	{ID: "evidence-dag", Path: evidenceDAGPath, Classification: "PUBLIC_DERIVED"},
	{ID: "evidence-public-contract", Path: publicContractPath, Classification: "PUBLIC"},
	{ID: "evidence-jdt-ls", Path: jdtLSPath, Classification: "PUBLIC_DERIVED"},
	{ID: "evidence-rust-analyzer", Path: rustAnalyzerPath, Classification: "PUBLIC_DERIVED"},
	{ID: "evidence-glancer", Path: glancerPath, Classification: "PUBLIC_DERIVED"},
	{ID: "evidence-security-validation", Path: securityValidationPath, Classification: "PUBLIC_DERIVED"},
}

var expectedDeveloperToolRuns = []developerToolExpectation{
	{Path: jdtLSPath, ProfileID: "profile.jdt-ls.java.v1", Language: "java", Name: "Eclipse JDT Language Server", Version: "1.60.0"},
	{Path: rustAnalyzerPath, ProfileID: "profile.rust-analyzer.baseline.v1", Language: "rust", Name: "rust-analyzer", Version: "2026-08-17.4"},
	{Path: glancerPath, ProfileID: "profile.glancer.experimental.v1", Language: "rust", Name: "Rust Glancer", Version: "v0.1.1"},
}

var expectedSchemaValidations = []schemaExpectation{
	{SchemaPath: "third_party/verified-java-to-rust-foundation/protocol/schemas/protocol-bundle-1.0.0.schema.json", Artifact: lifecyclePathDefault, Finding: "INVALID_LIFECYCLE_SCHEMA"},
	{SchemaPath: "third_party/verified-java-to-rust-foundation/protocol/schemas/checkpoint-1.0.0.schema.json", Artifact: checkpointPath, Finding: "CHECKPOINT_INVALID"},
	{SchemaPath: "assurance/schema/evidence-model-1.1.0.schema.json", Artifact: evidenceModelPath, Finding: "INVALID_EVIDENCE_MODEL"},
	{SchemaPath: "assurance/schema/evolution-1.1.0.schema.json", Artifact: evolutionPath, Finding: "INVALID_EVOLUTION"},
	{SchemaPath: "assurance/schema/developer-tool-run.schema.json", Artifact: jdtLSPath, Finding: "INVALID_DEVELOPER_TOOL_RUN"},
	{SchemaPath: "assurance/schema/developer-tool-run.schema.json", Artifact: rustAnalyzerPath, Finding: "INVALID_DEVELOPER_TOOL_RUN"},
	{SchemaPath: "assurance/schema/developer-tool-run.schema.json", Artifact: glancerPath, Finding: "INVALID_DEVELOPER_TOOL_RUN"},
	{SchemaPath: "assurance/schema/java-intake.schema.json", Artifact: javaIntakePath, Finding: "INVALID_JAVA_INTAKE"},
	{SchemaPath: "assurance/schema/compatibility-surface.schema.json", Artifact: compatibilitySurfacePath, Finding: "INVALID_COMPATIBILITY_SURFACE"},
	{SchemaPath: "assurance/schema/cutover-contract.schema.json", Artifact: cutoverContractPath, Finding: "INVALID_CUTOVER_CONTRACT"},
	{SchemaPath: "assurance/schema/port-seam-dossier.schema.json", Artifact: portSeamDossierPath, Finding: "INVALID_PORT_SEAM_DOSSIER"},
	{SchemaPath: "assurance/schema/behavior-delta-ledger.schema.json", Artifact: behaviorDeltaLedgerPath, Finding: "INVALID_BEHAVIOR_DELTA_LEDGER"},
	{SchemaPath: "assurance/schema/language-intelligence-profile.schema.json", Artifact: languageIntelligenceProfilePath, Finding: "INVALID_LANGUAGE_INTELLIGENCE_PROFILE"},
	{SchemaPath: "assurance/schema/profile-switching.schema.json", Artifact: profileSwitchingPath, Finding: "INVALID_PROFILE_SWITCHING"},
	{SchemaPath: "assurance/schema/navigation-corpus.schema.json", Artifact: navigationCorpusPath, Finding: "INVALID_NAVIGATION_CORPUS"},
	{SchemaPath: securityValidationSchemaPath, Artifact: securityValidationPath, Finding: "INVALID_SECURITY_VALIDATION"},
}

var expectedRetainedArtifacts = []retainedArtifactExpectation{
	{Path: upstreamManifestPath, Kind: "retained-evidence"},
	{Path: evidenceModelPath, Kind: "retained-evidence"},
	{Path: evolutionPath, Kind: "retained-evidence"},
	{Path: failuresPath, Kind: "retained-evidence"},
	{Path: evidenceDAGPath, Kind: "retained-evidence"},
	{Path: publicContractPath, Kind: "retained-evidence"},
	{Path: jdtLSPath, Kind: "retained-evidence"},
	{Path: rustAnalyzerPath, Kind: "retained-evidence"},
	{Path: glancerPath, Kind: "retained-evidence"},
	{Path: securityValidationPath, Kind: "retained-evidence"},
	{Path: jdtLSEvidencePath, Kind: "developer-tool-evidence"},
	{Path: rustAnalyzerEvidencePath, Kind: "developer-tool-evidence"},
	{Path: glancerEvidencePath, Kind: "developer-tool-evidence"},
	{Path: javaIntakePath, Kind: "developer-tool-material"},
	{Path: compatibilitySurfacePath, Kind: "developer-tool-material"},
	{Path: cutoverContractPath, Kind: "developer-tool-material"},
	{Path: portSeamDossierPath, Kind: "developer-tool-material"},
	{Path: behaviorDeltaLedgerPath, Kind: "developer-tool-material"},
	{Path: languageIntelligenceProfilePath, Kind: "developer-tool-material"},
	{Path: profileSwitchingPath, Kind: "developer-tool-material"},
	{Path: navigationCorpusPath, Kind: "developer-tool-material"},
	{Path: replayReadmePath, Kind: "replay-material"},
	{Path: replayProvenancePath, Kind: "replay-material"},
}

var expectedFailureRegistryEntries = []failureRegistryEntry{
	{Code: "NETWORK_DENIED", Disposition: vendorprotocol.Retry},
	{Code: "WORKER_INTERRUPTED", Disposition: vendorprotocol.Retry},
	{Code: "STORAGE_UNAVAILABLE", Disposition: vendorprotocol.Retry},
	{Code: "LEASE_EXPIRED", Disposition: vendorprotocol.Retry},
	{Code: "QUARANTINE_UNAVAILABLE", Disposition: vendorprotocol.Retry},
	{Code: "LSP_NAVIGATION_FAILURE", Disposition: vendorprotocol.DegradeNonAssurance},
	{Code: "SEMANTIC_INCONSISTENCY", Disposition: vendorprotocol.Block},
	{Code: "ORACLE_MISMATCH", Disposition: vendorprotocol.Block},
	{Code: "ORACLE_DISAGREEMENT", Disposition: vendorprotocol.Block},
	{Code: "STALE_INPUT", Disposition: vendorprotocol.Invalidate},
	{Code: "AUTHORIZATION_DENIED", Disposition: vendorprotocol.Quarantine},
	{Code: "REVOKED_KEY", Disposition: vendorprotocol.Quarantine},
	{Code: "ROLE_CONFLICT", Disposition: vendorprotocol.Quarantine},
	{Code: "PROTECTED_DISCLOSURE", Disposition: vendorprotocol.Quarantine},
	{Code: "PROTECTED_PUBLICATION_DISCLOSURE", Disposition: vendorprotocol.Revoke},
	{Code: "CORRUPT_CACHE", Disposition: vendorprotocol.Quarantine},
	{Code: "DIGEST_MISMATCH", Disposition: vendorprotocol.Quarantine},
	{Code: "PARTIAL_PUBLICATION", Disposition: vendorprotocol.Quarantine},
}
