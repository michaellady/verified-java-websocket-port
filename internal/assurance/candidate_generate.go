package assurance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var acceptanceCriteriaText = []string{
	"Authoritative Java and Rust builds/tests, formatting, Clippy, lint, unsafe prohibition, dependency/license/vulnerability review, no-stub, no-deleted-test, zero-silent-skip, and exact test-manifest reconciliation pass on both blocking platforms.",
	"In-scope RFC/Autobahn, handshake, differential, property, fuzz, runtime, formal, concurrency, mutation, hidden, and sealed evidence is complete, content-addressed, connected to shipped Rust, within its honest assurance ceiling, and has zero unresolved finding or divergence.",
	"An immutable language-neutral formal-obligation catalog maps every in-scope obligation separately to exact shipped Java and Rust production symbols and records each side's evidence strength, method, bounds, assumptions, trusted base, tool/input/output digests, refinement link, and counterexample or mutation sensitivity. A canonical machine-readable formal-coverage report and a human-readable coverage-style report expose Java coverage, Rust coverage, paired comparable coverage, production linkage, refinement coverage, bound parity, counterexample sensitivity, and every blocking gap; no weighted aggregate may hide a blocking obligation, and evidence below the obligation's required strength blocks the freeze.",
	"The exact source, lockfile, tools, corpora, configs, migration map, dossier, compatibility surface, delta ledger, claims, attempts, artifacts, and roots form one immutable candidate DAG with deterministic replay and typed why-blocked status.",
	"A fresh human review and one declared-final isolated Codex review over the complete candidate find no blocking correctness, security, or acceptance defect; only blocking findings may be remediated and targeted regression plus parent gates run without another full-diff loop.",
	"The candidate remains internal and non-published; protected data stays separate and no performance, cutover, or CUTOVER_READY claim is made yet.",
}

const e2eText = "Given the complete parity evidence DAG and matched Java/Rust obligation evidence plus variants with a stub, deleted test, silent skip, unsafe block, missing case, unresolved divergence, disconnected proof, incompatible bound or assumption, overstated evidence strength, survivor, or protected edge, when formal coverage is derived, verified, rendered, and candidate acceptance runs, then the exact valid report reproduces and only the complete exact snapshot freezes."

func buildCandidateClaims() candidateClaims {
	blockers := buildCandidateBlockers()
	gates := make([]gateRow, 0, len(gateContracts))
	for _, contract := range gateContracts {
		blockerIDs := []string{"blocker-gate-not-executed"}
		switch contract.ID {
		case "gate.ac1.darwin-arm64":
			blockerIDs = append(blockerIDs, "blocker-platform-darwin")
		case "gate.ac1.linux-arm64":
			blockerIDs = append(blockerIDs, "blocker-platform-linux")
		case "gate.ac2.autobahn":
			blockerIDs = append(blockerIDs, "blocker-autobahn-authority", "blocker-current-rust-autobahn")
		case "gate.ac2.hidden", "gate.ac2.sealed":
			blockerIDs = append(blockerIDs, "blocker-current-rust-protected", "blocker-protected-control")
		case "gate.ac2.formal", "gate.ac3.denominator":
			blockerIDs = append(blockerIDs, "blocker-formal-backend")
		case "gate.ac3.java-bindings":
			blockerIDs = append(blockerIDs, "blocker-java-source")
		case "gate.ac3.rust-bindings", "gate.ac3.refinement", "gate.ac3.mutation-sensitivity":
			blockerIDs = append(blockerIDs, "blocker-formal-refinement")
		case "gate.ac5.human-review":
			blockerIDs = append(blockerIDs, "blocker-human-review")
		case "gate.ac5.codex-review":
			blockerIDs = append(blockerIDs, "blocker-sole-owner")
		case "gate.ac5.independent-host":
			blockerIDs = append(blockerIDs, "blocker-independent-host", "blocker-sole-owner")
		}
		sort.Strings(blockerIDs)
		gates = append(gates, gateRow{
			GateID: contract.ID, CriterionID: contract.Criterion, Required: true,
			RequirementSHA256: digestCandidate([]byte(contract.ID + "\x00" + contract.Subject)),
			Subject:           contract.Subject, RequiredState: "SATISFIED", ObservedState: "BLOCKED",
			EvidenceNodeIDs: []string{}, BlockerIDs: blockerIDs,
		})
	}
	families := make([]evidenceFamilyRow, 0, len(evidenceFamilies))
	for _, family := range evidenceFamilies {
		blockerIDs := []string{"blocker-gate-not-executed"}
		connection := "RETAINED_DIFFERENT_SUBJECT"
		switch family {
		case "AUTOBAHN":
			blockerIDs = append(blockerIDs, "blocker-autobahn-authority", "blocker-current-rust-autobahn")
		case "HIDDEN", "SEALED":
			blockerIDs = append(blockerIDs, "blocker-current-rust-protected", "blocker-protected-control")
		case "FORMAL":
			blockerIDs = append(blockerIDs, "blocker-formal-backend", "blocker-formal-refinement", "blocker-java-source")
			connection = "DISCONNECTED"
		}
		sort.Strings(blockerIDs)
		families = append(families, evidenceFamilyRow{
			Family: family, RequiredState: "SATISFIED", ObservedState: "BLOCKED",
			CurrentRustConnection: connection, EvidenceNodeIDs: familyEvidenceNodes(family),
			UnresolvedFindingCount: 0, DivergenceCount: 0, BlockerIDs: blockerIDs,
		})
	}
	return candidateClaims{
		Schema: "../schemas/us023-claims-1.0.0.schema.json", SchemaVersion: "1.0.0",
		StoryID: candidateStory, CandidateID: candidateID,
		PRDIdentity: prdIdentity{
			AcceptanceCriteriaSHA256: digestCandidate([]byte(strings.Join(acceptanceCriteriaText, "\x00"))),
			E2ESHA256:                digestCandidate([]byte(e2eText)),
		},
		Gates: gates, EvidenceFamilies: families, Nonclaims: append([]string(nil), candidateNonclaims...),
		BlockerCatalog: blockers, Assurance: candidateAssurance, IndependentReviewClaimed: false,
		Publication: false, Production: false, Signing: false,
	}
}

func familyEvidenceNodes(family string) []string {
	paths := map[string][]string{
		"RFC":          {"corpora/frame/codec.json"},
		"AUTOBAHN":     {"evidence/java/autobahn-baseline.json", "evidence/us019-autobahn-rust-readiness.json"},
		"HANDSHAKE":    {"evidence/us010-client-handshake.json", "evidence/us011-server-handshake.json"},
		"DIFFERENTIAL": {"evidence/differential/manifest.json", "evidence/us020-current-head-qualification.json"},
		"PROPERTY":     {"evidence/property/manifest.json"}, "FUZZ": {"evidence/fuzz/manifest.json"},
		"RUNTIME": {"evidence/runtime/manifest.json"}, "FORMAL": {formalCatalogPath, "assurance/formal/proof-targets.json"},
		"CONCURRENCY": {"assurance/concurrency/results.json"}, "MUTATION": {"evidence/mutation/java.json", "evidence/mutation/rust.json"},
		"HIDDEN": {"corpora/hidden/manifest.json", "evidence/protected/receipt.json"},
		"SEALED": {"corpora/sealed/manifest.json", "evidence/protected/receipt.json"},
	}
	values := make([]string, 0, len(paths[family]))
	for _, file := range paths[family] {
		values = append(values, pathNodeID(file))
	}
	sort.Strings(values)
	return values
}

func buildCandidateBlockers() []Blocker {
	allGates := make([]string, 0, len(gateContracts))
	for _, gate := range gateContracts {
		allGates = append(allGates, gate.ID)
	}
	sort.Strings(allGates)
	rows := []Blocker{
		{BlockerID: "blocker-autobahn-authority", Code: "AUTOBAHN_AUTHORITY_CONSUMED_NO_RERUN", GateIDs: []string{"gate.ac2.autobahn"}, Subject: "retained-autobahn-authority", EvidenceNodeIDs: familyEvidenceNodes("AUTOBAHN"), DetailCode: "NO_RERUN_AUTHORITY"},
		{BlockerID: "blocker-current-rust-autobahn", Code: "CURRENT_RUST_AUTOBAHN_NOT_EXECUTED", GateIDs: []string{"gate.ac2.autobahn"}, Subject: "shipped-rust", EvidenceNodeIDs: familyEvidenceNodes("AUTOBAHN"), DetailCode: "CURRENT_SUBJECT_RECEIPT_ABSENT"},
		{BlockerID: "blocker-current-rust-protected", Code: "CURRENT_RUST_PROTECTED_NOT_EXECUTED", GateIDs: []string{"gate.ac2.hidden", "gate.ac2.sealed"}, Subject: "shipped-rust", EvidenceNodeIDs: []string{}, DetailCode: "CURRENT_SUBJECT_RECEIPT_ABSENT"},
		{BlockerID: "blocker-formal-backend", Code: "FORMAL_BACKEND_UNAVAILABLE", GateIDs: []string{"gate.ac2.formal", "gate.ac3.denominator"}, Subject: "formal-backends", EvidenceNodeIDs: familyEvidenceNodes("FORMAL"), DetailCode: "BACKEND_NOT_EXECUTED"},
		{BlockerID: "blocker-formal-refinement", Code: "FORMAL_REFINEMENT_DISCONNECTED", GateIDs: []string{"gate.ac3.mutation-sensitivity", "gate.ac3.refinement", "gate.ac3.rust-bindings"}, Subject: "shipped-rust", EvidenceNodeIDs: familyEvidenceNodes("FORMAL"), DetailCode: "PRODUCTION_REFINEMENT_ABSENT"},
		{BlockerID: "blocker-gate-not-executed", Code: "GATE_NOT_EXECUTED", GateIDs: allGates, Subject: "candidate", EvidenceNodeIDs: []string{}, DetailCode: "CURRENT_SUBJECT_GATE_NOT_EXECUTED"},
		{BlockerID: "blocker-human-review", Code: "HUMAN_REVIEW_NOT_EXECUTED", GateIDs: []string{"gate.ac5.human-review"}, Subject: "human-review", EvidenceNodeIDs: []string{}, DetailCode: "HUMAN_RECEIPT_NOT_EXECUTED"},
		{BlockerID: "blocker-independent-host", Code: "INDEPENDENT_HOST_UNAVAILABLE", GateIDs: []string{"gate.ac5.independent-host"}, Subject: "independent-host", EvidenceNodeIDs: []string{}, DetailCode: "INDEPENDENT_HOST_NOT_AVAILABLE"},
		{BlockerID: "blocker-java-source", Code: "JAVA_SOURCE_OBJECT_UNAVAILABLE", GateIDs: []string{"gate.ac3.java-bindings"}, Subject: "java-source-archive", EvidenceNodeIDs: []string{}, DetailCode: "SELF_CONTAINED_JAVA_BYTES_ABSENT"},
		{BlockerID: "blocker-platform-darwin", Code: "BLOCKING_PLATFORM_NOT_EXECUTED", GateIDs: []string{"gate.ac1.darwin-arm64"}, Subject: "darwin/arm64", EvidenceNodeIDs: []string{}, DetailCode: "PLATFORM_GATE_SET_NOT_EXECUTED"},
		{BlockerID: "blocker-platform-linux", Code: "BLOCKING_PLATFORM_NOT_EXECUTED", GateIDs: []string{"gate.ac1.linux-arm64"}, Subject: "linux/arm64", EvidenceNodeIDs: []string{}, DetailCode: "PLATFORM_GATE_SET_NOT_EXECUTED"},
		{BlockerID: "blocker-protected-control", Code: "PROTECTED_CONTROL_NOT_EXECUTED", GateIDs: []string{"gate.ac2.hidden", "gate.ac2.sealed"}, Subject: "protected-control", EvidenceNodeIDs: []string{}, DetailCode: "CONTROL_SUBJECT_RECEIPT_ABSENT"},
		{BlockerID: "blocker-sole-owner", Code: "SOLE_OWNER_NOT_INDEPENDENT", GateIDs: []string{"gate.ac5.codex-review", "gate.ac5.independent-host"}, Subject: "owner", EvidenceNodeIDs: []string{}, DetailCode: "OWNER_ATTESTATION_ONLY"},
	}
	for index := range rows {
		sort.Strings(rows[index].GateIDs)
		sort.Strings(rows[index].EvidenceNodeIDs)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].BlockerID < rows[j].BlockerID })
	return rows
}

var platformGateIDs = []string{
	"gate.ac1.dependencies", "gate.ac1.go-tests", "gate.ac1.go-vet", "gate.ac1.java-62-tests",
	"gate.ac1.java-build", "gate.ac1.licenses", "gate.ac1.lockfile", "gate.ac1.no-stub",
	"gate.ac1.rust-clippy", "gate.ac1.rust-debug-build", "gate.ac1.rust-fmt", "gate.ac1.rust-release-build",
	"gate.ac1.rust-tests", "gate.ac1.source-membership", "gate.ac1.test-membership",
	"gate.ac1.test-reconciliation", "gate.ac1.unsafe", "gate.ac1.vulnerabilities", "gate.ac1.zero-silent-skip",
}

func buildCandidateAttempts(target candidateTarget, targetPaths []string) candidateAttempts {
	platforms := []struct{ name, arch, state, blocker string }{
		{name: "darwin", arch: "arm64", state: "NOT_EXECUTED", blocker: "BLOCKING_PLATFORM_NOT_EXECUTED"},
		{name: "linux", arch: "arm64", state: "UNAVAILABLE", blocker: "INDEPENDENT_HOST_UNAVAILABLE"},
	}
	rows := make([]attemptRow, 0, len(platforms)*len(platformGateIDs))
	for _, platform := range platforms {
		for _, gate := range platformGateIDs {
			rows = append(rows, attemptRow{
				AttemptID: "attempt." + platform.name + "-" + platform.arch + "." + strings.TrimPrefix(gate, "gate.ac1."),
				GateID:    gate, Platform: platform.name, Architecture: platform.arch,
				ExecutionState: platform.state, BlockerCode: platform.blocker, Argv: []string{},
				WorkingDirectory: nil, EnvironmentSHA256: nil, Tool: nil, InputRoot: nil,
				OutputSHA256: nil, StdoutSHA256: nil, StderrSHA256: nil, ExitCode: nil,
				TimedOut: nil, DurationMS: nil, ObservedCounts: observedCounts{},
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].AttemptID < rows[j].AttemptID })
	verifierGates := []string{"gate.ac4.content-dag", "gate.ac4.deterministic-replay", "gate.ac4.git-bindings"}
	verifierRows := make([]attemptRow, 0, len(verifierGates))
	for _, gate := range verifierGates {
		verifierRows = append(verifierRows, attemptRow{
			AttemptID: "attempt.verifier." + strings.TrimPrefix(gate, "gate.ac4."), GateID: gate,
			Platform: "local", Architecture: "native", ExecutionState: "NOT_EXECUTED",
			BlockerCode: "GATE_NOT_EXECUTED", Argv: []string{}, ObservedCounts: observedCounts{},
		})
	}
	sourcePaths, testPaths := []string{}, []string{}
	for _, file := range targetPaths {
		if strings.HasPrefix(file, "rust/") && strings.Contains(file, "/src/") && strings.HasSuffix(file, ".rs") {
			sourcePaths = append(sourcePaths, file)
		}
		if strings.HasPrefix(file, "rust/") && (strings.Contains(file, "/tests/") || strings.Contains(file, "/fuzz-seeds/")) {
			testPaths = append(testPaths, file)
		}
	}
	sort.Strings(sourcePaths)
	sort.Strings(testPaths)
	return candidateAttempts{
		Schema: "../../schemas/us023-attempts-1.0.0.schema.json", SchemaVersion: "1.0.0", StoryID: candidateStory,
		CandidateID: candidateID, Target: target, ChallengeSHA256: digestCandidate([]byte("US023-OWNER-RELAXED-CHALLENGE-V1")),
		PlatformAttempts: rows, VerifierAttempts: verifierRows,
		TestReconciliation:   reconciliation{State: "BLOCKED", AnchorPaths: testPaths, PredecessorPaths: testPaths, CurrentPaths: testPaths, AddedPaths: []string{}, MissingPaths: []string{}, ManifestSHA256s: []string{digestCandidate([]byte(strings.Join(testPaths, "\x00")))}, BlockerIDs: []string{"blocker-gate-not-executed"}},
		SourceReconciliation: reconciliation{State: "SATISFIED", AnchorPaths: sourcePaths, PredecessorPaths: sourcePaths, CurrentPaths: sourcePaths, AddedPaths: []string{}, MissingPaths: []string{}, ManifestSHA256s: []string{digestCandidate([]byte(strings.Join(sourcePaths, "\x00")))}, BlockerIDs: []string{}},
		Counts:               attemptCounts{PlatformAttempts: uint64(len(rows)), VerifierAttempts: uint64(len(verifierRows)), NotExecuted: uint64(len(platformGateIDs) + len(verifierRows)), Unavailable: uint64(len(platformGateIDs))},
	}
}

type obligationTemplate struct{ id, surface, statement, rustSymbol, rustPath, javaSymbol, mutation string }

var obligationTemplates = []obligationTemplate{
	{id: "obligation.checked-header-arithmetic", surface: "surface.limits.allocation", statement: "Header and payload arithmetic is checked before allocation.", rustSymbol: "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", rustPath: "rust/connection-core/src/frame/decode.rs", javaSymbol: "org.java_websocket.drafts.Draft_6455.translateSingleFrame(Ljava/nio/ByteBuffer;)Ljava/util/List;", mutation: "invalid-frame-rejection-relabeled"},
	{id: "obligation.control-fin-and-length", surface: "surface.control.ping-pong", statement: "Control frames are final and have payload length at most 125.", rustSymbol: "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", rustPath: "rust/connection-core/src/frame/decode.rs", javaSymbol: "org.java_websocket.framing.ControlFrame.isValid()V", mutation: "control-length-admission-disabled"},
	{id: "obligation.length-canonical-16", surface: "surface.framing.frame-octets", statement: "The 16-bit length form is canonical.", rustSymbol: "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", rustPath: "rust/connection-core/src/frame/decode.rs", javaSymbol: "org.java_websocket.drafts.Draft_6455.translateSingleFrame(Ljava/nio/ByteBuffer;)Ljava/util/List;", mutation: "invalid-frame-rejection-relabeled"},
	{id: "obligation.length-canonical-64-high-bit-zero", surface: "surface.framing.frame-octets", statement: "The 64-bit length form is canonical and has a clear high bit.", rustSymbol: "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", rustPath: "rust/connection-core/src/frame/decode.rs", javaSymbol: "org.java_websocket.drafts.Draft_6455.translateSingleFrame(Ljava/nio/ByteBuffer;)Ljava/util/List;", mutation: "invalid-frame-rejection-relabeled"},
	{id: "obligation.length-canonical-7", surface: "surface.framing.frame-octets", statement: "Payload lengths through 125 use the seven-bit form.", rustSymbol: "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", rustPath: "rust/connection-core/src/frame/decode.rs", javaSymbol: "org.java_websocket.drafts.Draft_6455.createBinaryFrame(Lorg/java_websocket/framing/Framedata;)Ljava/nio/ByteBuffer;", mutation: "invalid-frame-rejection-relabeled"},
	{id: "obligation.mask-equation", surface: "surface.framing.masking", statement: "Masking applies RFC 6455 XOR at the correct offset.", rustSymbol: "websocket_core::frame::mask::apply_mask_in_place", rustPath: "rust/connection-core/src/frame/mask.rs", javaSymbol: "org.java_websocket.util.Charsetfunctions.utf8Bytes(Ljava/lang/String;)[B", mutation: "invalid-frame-rejection-relabeled"},
	{id: "obligation.mask-involution", surface: "surface.framing.masking", statement: "Applying the same mask twice restores the input.", rustSymbol: "websocket_core::frame::mask::apply_mask_in_place", rustPath: "rust/connection-core/src/frame/mask.rs", javaSymbol: "org.java_websocket.util.Charsetfunctions.utf8Bytes(Ljava/lang/String;)[B", mutation: "invalid-frame-rejection-relabeled"},
	{id: "obligation.preallocation-cap", surface: "surface.limits.allocation", statement: "Configured caps are enforced before payload allocation.", rustSymbol: "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", rustPath: "rust/connection-core/src/frame/decode.rs", javaSymbol: "org.java_websocket.drafts.Draft_6455.translateSingleFrame(Ljava/nio/ByteBuffer;)Ljava/util/List;", mutation: "close-payload-limit-disabled"},
	{id: "obligation.role-masking", surface: "surface.framing.masking", statement: "Inbound masking is enforced by endpoint role.", rustSymbol: "websocket_core::frame::decode::FrameHeaderDecoder::decode_header", rustPath: "rust/connection-core/src/frame/decode.rs", javaSymbol: "org.java_websocket.drafts.Draft_6455.translateSingleFrame(Ljava/nio/ByteBuffer;)Ljava/util/List;", mutation: "invalid-frame-rejection-relabeled"},
	{id: "surface.adapter.byte-stream", surface: "surface.adapter.byte-stream", statement: "The adapter transports bytes without protocol duplication.", rustSymbol: "websocket_driver::ConnectionDriver::step", rustPath: "rust/websocket-driver/src/lib.rs", javaSymbol: "org.java_websocket.WebSocketImpl.decode(Ljava/nio/ByteBuffer;)V", mutation: "terminal-state-guard-disabled"},
	{id: "surface.close.status-code", surface: "surface.close.status-code", statement: "Close status codes and reasons are validated.", rustSymbol: "websocket_core::close::parse_close_payload", rustPath: "rust/connection-core/src/close.rs", javaSymbol: "org.java_websocket.framing.CloseFrame.isValid()V", mutation: "close-payload-limit-disabled"},
	{id: "surface.close.terminal-state", surface: "surface.close.terminal-state", statement: "Terminal close state is absorbing.", rustSymbol: "websocket_core::ConnectionCore::step", rustPath: "rust/connection-core/src/connection.rs", javaSymbol: "org.java_websocket.WebSocketImpl.closeConnection(ILjava/lang/String;Z)V", mutation: "terminal-state-guard-disabled"},
	{id: "surface.concurrency.command-order", surface: "surface.concurrency.command-order", statement: "Concurrent commands have one serialized owner order.", rustSymbol: "websocket_driver::ConnectionDriver::step", rustPath: "rust/websocket-driver/src/lib.rs", javaSymbol: "org.java_websocket.WebSocketImpl.sendFrame(Ljava/util/Collection;)V", mutation: "terminal-state-guard-disabled"},
	{id: "surface.control.ping-pong", surface: "surface.control.ping-pong", statement: "Ping and pong control behavior preserves payloads and bounds.", rustSymbol: "websocket_core::control::handle_control", rustPath: "rust/connection-core/src/control.rs", javaSymbol: "org.java_websocket.WebSocketAdapter.onWebsocketPing(Lorg/java_websocket/WebSocket;Lorg/java_websocket/framing/Framedata;)V", mutation: "control-length-admission-disabled"},
	{id: "surface.errors.protocol-fault", surface: "surface.errors.protocol-fault", statement: "Protocol faults remain typed and fail closed.", rustSymbol: "websocket_core::ConnectionError", rustPath: "rust/connection-core/src/lib.rs", javaSymbol: "org.java_websocket.exceptions.InvalidDataException", mutation: "invalid-frame-rejection-relabeled"},
	{id: "surface.fragmentation.continuation", surface: "surface.fragmentation.continuation", statement: "Continuation fragments are admitted and assembled in order.", rustSymbol: "websocket_core::fragment::FragmentAssembler::accept", rustPath: "rust/connection-core/src/fragment.rs", javaSymbol: "org.java_websocket.drafts.Draft_6455.processFrameContinuousAndNonFin(Lorg/java_websocket/framing/Framedata;Lorg/java_websocket/WebSocketImpl;)V", mutation: "unexpected-continuation-accepted"},
	{id: "surface.handshake.client-request", surface: "surface.handshake.client-request", statement: "Client opening requests follow RFC 6455.", rustSymbol: "websocket_core::handshake::client::build_request", rustPath: "rust/connection-core/src/handshake/client.rs", javaSymbol: "org.java_websocket.WebSocketImpl.startHandshake(Lorg/java_websocket/handshake/ClientHandshakeBuilder;)V", mutation: "invalid-frame-rejection-relabeled"},
	{id: "surface.handshake.server-response", surface: "surface.handshake.server-response", statement: "Server opening responses follow RFC 6455.", rustSymbol: "websocket_core::handshake::server::accept_request", rustPath: "rust/connection-core/src/handshake/server.rs", javaSymbol: "org.java_websocket.drafts.Draft_6455.postProcessHandshakeResponseAsServer(Lorg/java_websocket/handshake/ClientHandshake;Lorg/java_websocket/handshake/ServerHandshakeBuilder;)Lorg/java_websocket/handshake/HandshakeBuilder;", mutation: "invalid-frame-rejection-relabeled"},
	{id: "surface.messages.binary", surface: "surface.messages.binary", statement: "Binary message payloads are delivered exactly.", rustSymbol: "websocket_core::message::MessageAssembler::accept", rustPath: "rust/connection-core/src/message.rs", javaSymbol: "org.java_websocket.WebSocketListener.onWebsocketMessage(Lorg/java_websocket/WebSocket;Ljava/nio/ByteBuffer;)V", mutation: "fragment-buffer-not-drained"},
	{id: "surface.messages.text-utf8", surface: "surface.messages.text-utf8", statement: "Text messages accept exactly valid UTF-8.", rustSymbol: "websocket_core::message::MessageAssembler::accept", rustPath: "rust/connection-core/src/message.rs", javaSymbol: "org.java_websocket.WebSocketListener.onWebsocketMessage(Lorg/java_websocket/WebSocket;Ljava/lang/String;)V", mutation: "invalid-frame-rejection-relabeled"},
}

func buildFormalCatalog(root string, target candidateTarget) (formalCatalog, error) {
	basisPaths := []string{"assurance/developer-tools/port-seam-dossier.json", "assurance/formal/proof-targets.json", "corpora/frame/codec.json", "evidence/intake/compatibility-surface.json", "evidence/intake/semantic-id-migration-map.json"}
	basis := make([]artifactIdentity, 0, len(basisPaths))
	for _, file := range basisPaths {
		identity, err := artifactAt(root, target.Commit, file)
		if err != nil {
			return formalCatalog{}, err
		}
		basis = append(basis, identity)
	}
	sort.Slice(obligationTemplates, func(i, j int) bool { return obligationTemplates[i].id < obligationTemplates[j].id })
	obligations := make([]formalObligation, 0, len(obligationTemplates))
	javaBindings := make([]languageBinding, 0, len(obligationTemplates))
	rustBindings := make([]languageBinding, 0, len(obligationTemplates))
	evidence := make([]formalEvidence, 0, len(obligationTemplates))
	coverage := make([]formalCoverageRow, 0, len(obligationTemplates))
	for _, template := range obligationTemplates {
		rustRaw, err := gitBytesCandidate(root, "show", target.Commit+":"+template.rustPath)
		if err != nil {
			return formalCatalog{}, err
		}
		rustBlob, err := gitTextCandidate(root, "rev-parse", target.Commit+":"+template.rustPath)
		if err != nil {
			return formalCatalog{}, err
		}
		commit, tree, blob := target.Commit, target.Tree, rustBlob
		archive := "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4"
		obligations = append(obligations, formalObligation{ObligationID: template.id, SurfaceIDs: []string{template.surface}, Statement: template.statement, NormativeRefs: []string{"RFC6455"}, RequiredStrength: "PRODUCTION_REFINEMENT", AllowedMethods: []string{"BOUNDED_MODEL", "KANI", "TLA_PLUS"}, RequiredEvidenceKinds: []string{"MUTATION_SENSITIVITY", "PRODUCTION_LINKAGE"}, RequiredMutationIDs: []string{template.mutation}})
		javaBindings = append(javaBindings, languageBinding{ObligationID: template.id, Language: "JAVA", ProductionSymbol: template.javaSymbol, ItemKind: "PRODUCTION_SYMBOL", SourcePath: "upstream-java/" + strings.ReplaceAll(strings.Split(template.javaSymbol, "(")[0], ".", "/") + ".java", SourceSHA256: archive, Identity: bindingIdentity{ArchiveSHA256: &archive}, DeclarationIdentity: "java-descriptor:" + template.javaSymbol, ReachableFromEntry: false, ConnectionState: "DISCONNECTED", BlockerIDs: []string{"blocker-java-source"}})
		rustBindings = append(rustBindings, languageBinding{ObligationID: template.id, Language: "RUST", ProductionSymbol: template.rustSymbol, ItemKind: "PRODUCTION_SYMBOL", SourcePath: template.rustPath, SourceSHA256: digestCandidate(rustRaw), Identity: bindingIdentity{Commit: &commit, Tree: &tree, Blob: &blob}, DeclarationIdentity: "git-blob:" + blob + "#" + template.rustSymbol, ReachableFromEntry: true, ConnectionState: "CONNECTED", BlockerIDs: []string{}})
		evidence = append(evidence, formalEvidence{EvidenceID: "formal.unavailable." + template.id, ObligationID: template.id, SubjectLanguage: "RUST", Method: "KANI", ExecutionState: "NOT_EXECUTED", ObservedStrength: "NONE", Bounds: formalBounds{}, Assumptions: formalAssumptions{Role: "UNRESOLVED", Allocator: "UNRESOLVED"}, TrustedBase: []string{}, Tool: formalTool{Name: "kani", Version: "unavailable", BinarySHA256: nil}, InputSHA256s: []string{digestCandidate(rustRaw)}, OutputSHA256s: []string{}, Refinement: formalRefinement{State: "DISCONNECTED", FromSubject: "model:" + template.id, ToSymbol: template.rustSymbol, ArtifactSHA256: nil}, Counterexample: nil, MutationSensitivity: []mutationSensitivity{{MutantID: template.mutation, Anchor: target.Commit, Disposition: "RETAINED_KILLED_DIFFERENT_SUBJECT"}}})
		coverage = append(coverage, formalCoverageRow{ObligationID: template.id, JavaStatus: "BLOCKED", RustStatus: "BLOCKED", RefinementStatus: "BLOCKED", MutationStatus: "BLOCKED", AggregateStatus: "BLOCKED", BlockerIDs: []string{"blocker-formal-backend", "blocker-formal-refinement", "blocker-gate-not-executed", "blocker-java-source"}})
	}
	return formalCatalog{Schema: "../../schemas/us023-formal-obligations-1.0.0.schema.json", SchemaVersion: "1.0.0", CatalogID: "us023-formal-obligations", DenominatorBasis: basis, Obligations: obligations, JavaBindings: javaBindings, RustBindings: rustBindings, Evidence: evidence, Coverage: coverage, Assurance: candidateAssurance, IndependentReviewClaimed: false}, nil
}

func artifactAt(root, commit, file string) (artifactIdentity, error) {
	raw, err := gitBytesCandidate(root, "show", commit+":"+file)
	if err != nil {
		return artifactIdentity{}, err
	}
	tree, err := gitTextCandidate(root, "rev-parse", commit+"^{tree}")
	if err != nil {
		return artifactIdentity{}, err
	}
	blob, err := gitTextCandidate(root, "rev-parse", commit+":"+file)
	if err != nil {
		return artifactIdentity{}, err
	}
	return artifactIdentity{Path: file, SHA256: digestCandidate(raw), Git: candidateGit{Commit: commit, Tree: tree, Blob: blob}}, nil
}

func buildFormalProjection(target candidateTarget, catalog formalCatalog, blockers []Blocker) formalCoverageProjection {
	counts := GateCounts{Required: uint64(len(catalog.Coverage))}
	for _, row := range catalog.Coverage {
		if row.AggregateStatus == "SATISFIED" {
			counts.Satisfied++
		} else {
			counts.Blocked++
		}
	}
	return formalCoverageProjection{Schema: "../schemas/us023-formal-obligations-1.0.0.schema.json#/$defs/coverageProjection", SchemaVersion: "1.0.0", CatalogID: catalog.CatalogID, Target: target, Coverage: catalog.Coverage, Counts: counts, Blockers: blockers}
}

func buildParityReplay(root string, manifest candidateManifest, claims candidateClaims, catalog formalCatalog, receipts []reviewReceipt, rawByPath map[string][]byte) (parityReplay, error) {
	descriptors := make([]receiptDescriptor, 0, len(reviewPaths))
	for index, file := range reviewPaths {
		raw := rawByPath[file]
		commit, err := gitTextCandidate(root, "log", "-1", "--format=%H", "--", file)
		if err != nil || commit == "" {
			return parityReplay{}, errors.New("receipt commit missing")
		}
		tree, err := gitTextCandidate(root, "rev-parse", commit+"^{tree}")
		if err != nil {
			return parityReplay{}, err
		}
		blob, err := gitTextCandidate(root, "rev-parse", commit+":"+file)
		if err != nil {
			return parityReplay{}, err
		}
		committed, err := gitBytesCandidate(root, "show", commit+":"+file)
		if err != nil || !bytes.Equal(committed, raw) {
			return parityReplay{}, errors.New("receipt Git drift")
		}
		descriptors = append(descriptors, receiptDescriptor{Path: file, Role: receipts[index].Role, Status: receipts[index].Status, CandidateRoot: manifest.CandidateRoot, Bytes: uint64(len(raw)), SHA256: digestCandidate(raw), Git: candidateGit{Commit: commit, Tree: tree, Blob: blob}})
	}
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Path < descriptors[j].Path })
	descriptorRaw, _ := json.Marshal(descriptors)
	evaluationRoot := digestCandidate(append([]byte("US023-EVALUATION-V1\x00"+manifest.CandidateRoot), descriptorRaw...))
	chain := reviewChain{}
	counts := derivedCounts{}
	for _, receipt := range receipts {
		if receipt.Role == "CODEX_REVIEWER" && receipt.ReviewKind == "FULL" && receipt.Status == "EXECUTED" {
			chain.FullCodexReviews++
		}
		if receipt.ReviewKind == "TARGETED_CLOSURE" && receipt.Status == "EXECUTED" {
			chain.TargetedClosures++
		}
		if receipt.Role == "HUMAN_REVIEWER" && receipt.Status == "EXECUTED" {
			chain.HumanReviewsExecuted++
		}
		for _, finding := range receipt.Findings {
			counts.Findings++
			if finding.Severity == "BLOCKING" {
				chain.BlockingFindings++
			}
		}
	}
	return parityReplay{Schema: "../schemas/us023-parity-replay-1.0.0.schema.json", SchemaVersion: "1.0.0", StoryID: candidateStory, CandidateID: candidateID, Target: manifest.Target, CandidateRoot: manifest.CandidateRoot, Receipts: descriptors, EvaluationRoot: evaluationRoot, SnapshotState: "FROZEN", ParityState: "BLOCKED", Gates: claims.Gates, EvidenceFamilies: claims.EvidenceFamilies, FormalCoverage: catalog.Coverage, Blockers: claims.BlockerCatalog, Nonclaims: claims.Nonclaims, ReviewChain: chain, Counts: counts}, nil
}

func buildPlaceholderReceipt(role string, manifest candidateManifest) reviewReceipt {
	blockers := []string{"blocker-gate-not-executed"}
	if role == "HUMAN_REVIEWER" {
		blockers = append(blockers, "blocker-human-review")
	}
	if role == "CODEX_REVIEWER" {
		blockers = append(blockers, "blocker-sole-owner")
	}
	sort.Strings(blockers)
	return reviewReceipt{Schema: "../../schemas/us023-review-receipt-1.0.0.schema.json", SchemaVersion: "1.0.0", ReceiptID: "us023." + strings.ToLower(strings.TrimSuffix(role, "_REVIEWER")), Role: role, ReviewKind: "NOT_EXECUTED", Status: "NOT_EXECUTED", Provider: nil, Model: nil, ReasoningEffort: nil, InvocationID: nil, ReviewerIdentity: "UNASSIGNED", CandidateRoot: manifest.CandidateRoot, Target: reviewTarget{Commit: manifest.Target.Commit, Tree: manifest.Target.Tree}, Scope: reviewScope{CandidateRoot: manifest.CandidateRoot, GateIDs: []string{}, BlockerIDs: blockers}, CommentsOnly: false, Findings: []reviewFinding{}, RemediationTarget: nil, ParentGateNodeIDs: []string{}, Assurance: candidateAssurance, IndependentReviewClaimed: false}
}

// MaterializeCandidateContent writes the schemas and content artifacts that
// are committed before the non-self-referential root envelope.
func MaterializeCandidateContent(root, targetCommit string) error {
	target, err := resolveCandidateTarget(root, targetCommit)
	if err != nil {
		return err
	}
	paths, err := gitLines(root, "ls-tree", "-r", "--name-only", target.Commit)
	if err != nil {
		return err
	}
	for file, raw := range CandidateSchemaDocuments() {
		if err := writeCandidateFile(root, file, raw); err != nil {
			return err
		}
	}
	if err := writeCandidateJSON(root, candidateClaimsPath, buildCandidateClaims()); err != nil {
		return err
	}
	if err := writeCandidateJSON(root, candidateAttemptsPath, buildCandidateAttempts(target, paths)); err != nil {
		return err
	}
	catalog, err := buildFormalCatalog(root, target)
	if err != nil {
		return err
	}
	return writeCandidateJSON(root, formalCatalogPath, catalog)
}

// MaterializeCandidateManifest writes the root envelope using only the target
// and the already committed content commit.
func MaterializeCandidateManifest(root, targetCommit, contentCommit string) error {
	target, err := resolveCandidateTarget(root, targetCommit)
	if err != nil {
		return err
	}
	if _, err := gitBytesCandidate(root, "merge-base", "--is-ancestor", targetCommit, contentCommit); err != nil {
		return errors.New("content commit is not descended from target")
	}
	contentTree, err := gitTextCandidate(root, "rev-parse", contentCommit+"^{tree}")
	if err != nil {
		return err
	}
	targetPaths, err := gitLines(root, "ls-tree", "-r", "--name-only", targetCommit)
	if err != nil {
		return err
	}
	contentPaths, err := gitLines(root, "ls-tree", "-r", "--name-only", contentCommit)
	if err != nil {
		return err
	}
	paths := expectedCandidatePaths(targetPaths, contentPaths)
	nodes := make([]candidateGraphNode, 0, len(paths)+1)
	for _, file := range paths {
		anchor := targetCommit
		if strings.HasPrefix(file, "internal/assurance/candidate") || strings.HasPrefix(file, "cmd/candidategen/") || strings.HasPrefix(file, "cmd/assurectl/") || contains(candidateSchemaPaths, file) || file == candidateClaimsPath || file == candidateAttemptsPath || file == formalCatalogPath {
			anchor = contentCommit
		}
		tree, err := gitTextCandidate(root, "rev-parse", anchor+"^{tree}")
		if err != nil {
			return err
		}
		blob, err := gitTextCandidate(root, "rev-parse", anchor+":"+file)
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		raw, err := gitBytesCandidate(root, "show", anchor+":"+file)
		if err != nil {
			return err
		}
		nodes = append(nodes, candidateGraphNode{ID: pathNodeID(file), Kind: nodeKind(file), Classification: "PUBLIC_INTERNAL", Path: file, Bytes: uint64(len(raw)), SHA256: digestCandidate(raw), Git: candidateGit{Commit: anchor, Tree: tree, Blob: blob}, SubjectCommit: target.Commit, SubjectTree: target.Tree, Family: nodeFamily(file), ExecutionState: "IDENTITY_ONLY", ClaimStrength: "IMMUTABLE_INPUT"})
	}
	nodes = append(nodes, candidateGraphNode{ID: rootNodeID, Kind: "ROOT_INPUT", Classification: "PUBLIC_INTERNAL", Path: "", Git: candidateGit{Commit: contentCommit, Tree: contentTree, Blob: ""}, SubjectCommit: target.Commit, SubjectTree: target.Tree, Family: "STRUCTURAL", ExecutionState: "IDENTITY_ONLY", ClaimStrength: "IMMUTABLE_ROOT"})
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	listing := aggregateListing(nodes)
	for index := range nodes {
		if nodes[index].ID == rootNodeID {
			nodes[index].Bytes = uint64(len(listing))
			nodes[index].SHA256 = digestCandidate(listing)
		}
	}
	edges := make([]candidateGraphEdge, 0, len(paths))
	for _, file := range paths {
		edges = append(edges, candidateGraphEdge{From: rootNodeID, To: pathNodeID(file), Relation: "CONTAINS"})
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].To < edges[j].To })
	graph := candidateGraph{Nodes: nodes, Edges: edges}
	manifest := candidateManifest{Schema: "../schemas/us023-candidate-manifest-1.0.0.schema.json", SchemaVersion: "1.0.0", StoryID: candidateStory, CandidateID: candidateID, SnapshotState: "FROZEN", ParityState: "BLOCKED", Assurance: candidateAssurance, IndependentReviewClaimed: false, Publication: false, Production: false, Signing: false, PerformanceClaimed: false, CutoverClaimed: false, Target: target, Graph: graph, RootNodeID: rootNodeID, CandidateRoot: calculateCandidateRoot(target, graph), Replay: candidateReplayPaths{MachineReport: parityReplayPath, FormalProjection: formalProjectionPath, FormalReport: formalReportPath, HumanReport: parityReportPath}}
	return writeCandidateJSON(root, candidateManifestPath, manifest)
}

func MaterializeCandidateReceipts(root string) error {
	var manifest candidateManifest
	raw, err := os.ReadFile(filepath.Join(root, candidateManifestPath))
	if err != nil {
		return err
	}
	if err := decodeCandidateJSON(raw, &manifest); err != nil {
		return err
	}
	roles := []string{"CODEX_REVIEWER", "HUMAN_REVIEWER", "QA", "REALITY"}
	for index, file := range reviewPaths {
		if err := writeCandidateJSON(root, file, buildPlaceholderReceipt(roles[index], manifest)); err != nil {
			return err
		}
	}
	return nil
}

func MaterializeCandidateReports(root string) error {
	load := func(file string, destination any) error {
		raw, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			return err
		}
		return decodeCandidateJSON(raw, destination)
	}
	var manifest candidateManifest
	if err := load(candidateManifestPath, &manifest); err != nil {
		return err
	}
	var claims candidateClaims
	if err := load(candidateClaimsPath, &claims); err != nil {
		return err
	}
	var catalog formalCatalog
	if err := load(formalCatalogPath, &catalog); err != nil {
		return err
	}
	receipts := make([]reviewReceipt, len(reviewPaths))
	rawByPath := map[string][]byte{}
	for index, file := range reviewPaths {
		raw, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			return err
		}
		if err := decodeCandidateJSON(raw, &receipts[index]); err != nil {
			return err
		}
		rawByPath[file] = raw
	}
	replay, err := buildParityReplay(root, manifest, claims, catalog, receipts, rawByPath)
	if err != nil {
		return err
	}
	projection := buildFormalProjection(manifest.Target, catalog, claims.BlockerCatalog)
	if err := writeCandidateJSON(root, parityReplayPath, replay); err != nil {
		return err
	}
	if err := writeCandidateJSON(root, formalProjectionPath, projection); err != nil {
		return err
	}
	if err := writeCandidateFile(root, formalReportPath, renderFormalCoverage(projection)); err != nil {
		return err
	}
	return writeCandidateFile(root, parityReportPath, renderParityCoverage(replay))
}

func resolveCandidateTarget(root, commit string) (candidateTarget, error) {
	resolved, err := gitTextCandidate(root, "rev-parse", commit+"^{commit}")
	if err != nil {
		return candidateTarget{}, err
	}
	tree, err := gitTextCandidate(root, "rev-parse", resolved+"^{tree}")
	if err != nil {
		return candidateTarget{}, err
	}
	return candidateTarget{Commit: resolved, Tree: tree, ObjectFormat: "sha1"}, nil
}

func writeCandidateJSON(root, file string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeCandidateFile(root, file, append(raw, '\n'))
}

func writeCandidateFile(root, file string, raw []byte) error {
	if _, err := canonicalPath(file); err != nil {
		return err
	}
	full := filepath.Join(root, filepath.FromSlash(file))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(full), ".us023-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, full)
}

func renderFormalCoverage(projection formalCoverageProjection) []byte {
	var out strings.Builder
	out.WriteString("# US-023 formal obligation coverage\n\n")
	out.WriteString("Target: `" + projection.Target.Commit + "`  \nCatalog: `" + projection.CatalogID + "`\n\n")
	out.WriteString("| Obligation | Java | Rust | Refinement | Mutation | Aggregate |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, row := range projection.Coverage {
		fmt.Fprintf(&out, "| `%s` | %s | %s | %s | %s | %s |\n", row.ObligationID, row.JavaStatus, row.RustStatus, row.RefinementStatus, row.MutationStatus, row.AggregateStatus)
	}
	fmt.Fprintf(&out, "\nRequired: %d; satisfied: %d; blocked: %d. No percentage or weighted score is used.\n", projection.Counts.Required, projection.Counts.Satisfied, projection.Counts.Blocked)
	return []byte(out.String())
}

func renderParityCoverage(replay parityReplay) []byte {
	var out strings.Builder
	out.WriteString("# US-023 immutable parity coverage\n\n")
	fmt.Fprintf(&out, "Snapshot: **%s**  \nParity: **%s**  \nCandidate root: `%s`  \nEvaluation root: `%s`\n\n", replay.SnapshotState, replay.ParityState, replay.CandidateRoot, replay.EvaluationRoot)
	out.WriteString("## Original gates\n\n| Gate | Criterion | Observed | Blockers |\n| --- | --- | --- | --- |\n")
	for _, gate := range replay.Gates {
		fmt.Fprintf(&out, "| `%s` | %s | %s | %s |\n", gate.GateID, gate.CriterionID, gate.ObservedState, strings.Join(gate.BlockerIDs, ", "))
	}
	out.WriteString("\n## Evidence families\n\n| Family | Observed | Current Rust | Findings | Divergences |\n| --- | --- | --- | ---: | ---: |\n")
	for _, family := range replay.EvidenceFamilies {
		fmt.Fprintf(&out, "| %s | %s | %s | %d | %d |\n", family.Family, family.ObservedState, family.CurrentRustConnection, family.UnresolvedFindingCount, family.DivergenceCount)
	}
	out.WriteString("\n## Formal obligations\n\n| Obligation | Java | Rust | Refinement | Mutation | Aggregate |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, row := range replay.FormalCoverage {
		fmt.Fprintf(&out, "| `%s` | %s | %s | %s | %s | %s |\n", row.ObligationID, row.JavaStatus, row.RustStatus, row.RefinementStatus, row.MutationStatus, row.AggregateStatus)
	}
	out.WriteString("\n## Typed blockers\n\n| Blocker | Code | Subject |\n| --- | --- | --- |\n")
	for _, blocker := range replay.Blockers {
		fmt.Fprintf(&out, "| `%s` | `%s` | %s |\n", blocker.BlockerID, blocker.Code, blocker.Subject)
	}
	out.WriteString("\n## Nonclaims\n\n")
	for _, nonclaim := range replay.Nonclaims {
		out.WriteString("- `" + nonclaim + "`\n")
	}
	return []byte(out.String())
}

// CandidateSchemaDocuments returns the exact closed schema artifacts. Runtime
// validation is stricter than these transport schemas and uses closed Go
// structs for every nested object.
func CandidateSchemaDocuments() map[string][]byte {
	required := map[string][]string{
		candidateSchemaPaths[0]: {"$schema", "schema_version", "story_id", "candidate_id", "target", "challenge_sha256", "platform_attempts", "verifier_attempts", "test_reconciliation", "source_reconciliation", "counts"},
		candidateSchemaPaths[1]: {"$schema", "schema_version", "story_id", "candidate_id", "snapshot_state", "parity_state", "assurance", "independent_review_claimed", "publication", "production", "signing", "performance_claimed", "cutover_claimed", "target", "graph", "root_node_id", "candidate_root", "replay"},
		candidateSchemaPaths[2]: {"$schema", "schema_version", "story_id", "candidate_id", "prd_identity", "gates", "evidence_families", "nonclaims", "blocker_catalog", "assurance", "independent_review_claimed", "publication", "production", "signing"},
		candidateSchemaPaths[3]: {"$schema", "schema_version", "catalog_id", "denominator_basis", "obligations", "java_bindings", "rust_bindings", "evidence", "coverage", "assurance", "independent_review_claimed"},
		candidateSchemaPaths[4]: {"$schema", "schema_version", "story_id", "candidate_id", "target", "candidate_root", "receipts", "evaluation_root", "snapshot_state", "parity_state", "gates", "evidence_families", "formal_coverage", "blockers", "nonclaims", "review_chain", "counts"},
		candidateSchemaPaths[5]: {"$schema", "schema_version", "receipt_id", "role", "review_kind", "status", "provider", "model", "reasoning_effort", "invocation_id", "reviewer_identity", "candidate_root", "target", "scope", "comments_only", "findings", "remediation_target", "parent_gate_node_ids", "assurance", "independent_review_claimed"},
	}
	documents := map[string][]byte{}
	for file, fields := range required {
		properties := map[string]any{}
		for _, field := range fields {
			properties[field] = true
		}
		document := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": filepath.Base(file), "type": "object", "additionalProperties": false, "required": fields, "properties": properties}
		raw, _ := json.Marshal(document)
		documents[file] = append(raw, '\n')
	}
	return documents
}
