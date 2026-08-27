package portplan

import (
	"fmt"
	"sort"
	"strings"
)

// sliceEvidence supplies the per-slice specification, oracle, vector, property, and formal
// obligations every migration row must bind.
type sliceEvidence struct {
	Specifications []string
	Behaviors      []string
	Oracles        []string
	Vectors        []string
	Properties     []string
	Formals        []string
	Applicability  []string
	NonEquivalence []string
}

var sliceEvidenceBySlice = map[string]sliceEvidence{
	"slice.connection-core": {
		Specifications: []string{"rfc6455.section-4", "rfc6455.section-7"},
		Behaviors:      []string{"behavior.connection.state-transitions"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0"},
		Vectors:        []string{"vector.handshake.corpus", "vector.autobahn.case-1"},
		Properties:     []string{"property.connection.state-machine-total"},
		Formals:        []string{"formal.connection.no-terminal-escape"},
		Applicability: []string{
			"applies to the single-connection state machine only",
			"applies when the transport is a plain byte stream supplied by the adapter",
		},
		NonEquivalence: []string{
			"Java exposes the connection through an abstract class hierarchy; the Rust port" +
				" exposes a single owned ConnectionCore with explicit command and event types",
			"Java's ReadyState transitions are observable through public getters at any time" +
				" from any thread; the Rust port serializes observation through the owner",
		},
	},
	"slice.client-handshake": {
		Specifications: []string{"rfc6455.section-4-1", "rfc6455.section-1-3"},
		Behaviors:      []string{"behavior.handshake.client-open"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0"},
		Vectors:        []string{"vector.handshake.client-corpus"},
		Properties:     []string{"property.handshake.key-accept-roundtrip"},
		Formals:        []string{"formal.handshake.accept-derivation"},
		Applicability: []string{
			"applies to the RFC 6455 opening handshake request and response parsing",
			"applies to Sec-WebSocket-Key generation and Sec-WebSocket-Accept derivation",
		},
		NonEquivalence: []string{
			"Java accepts header casing and folding variants through its own parser; the Rust" +
				" port must reproduce the accepted set exactly and reject the rest",
			"Java's handshake objects are mutable builders; the Rust port uses owned immutable" +
				" handshake values",
		},
	},
	"slice.server-handshake": {
		Specifications: []string{"rfc6455.section-4-2", "rfc6455.section-4-1"},
		Behaviors:      []string{"behavior.handshake.server-accept"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0"},
		Vectors:        []string{"vector.handshake.server-corpus"},
		Properties:     []string{"property.handshake.server-response-total"},
		Formals:        []string{"formal.handshake.accept-derivation"},
		Applicability: []string{
			"applies to server-side opening-handshake validation and response construction",
		},
		NonEquivalence: []string{
			"Java's server handshake is produced by the excluded NIO server topology; the Rust" +
				" port produces it from the adapter-independent core",
		},
	},
	"slice.framing": {
		Specifications: []string{"rfc6455.section-5-1", "rfc6455.section-5-2", "rfc6455.section-5-3"},
		Behaviors:      []string{"behavior.framing.parse-and-emit"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0", "oracle.autobahn.fuzzingserver"},
		Vectors:        []string{"vector.autobahn.case-2", "vector.framing.corpus"},
		Properties:     []string{"property.framing.mask-involution", "property.framing.roundtrip"},
		Formals:        []string{"formal.framing.length-bounds", "formal.framing.allocation-limit"},
		Applicability: []string{
			"applies to canonical RFC 6455 frame parsing and emission",
			"applies to masking, payload length encoding, and allocation limits",
		},
		NonEquivalence: []string{
			"Java allocates a fresh ByteBuffer per frame and relies on the GC; the Rust port" +
				" uses bounded, explicitly owned buffers",
			"Java signals framing faults through an exception hierarchy; the Rust port returns" +
				" typed protocol errors",
		},
	},
	"slice.messages": {
		Specifications: []string{"rfc6455.section-5-6", "rfc3629.utf8"},
		Behaviors:      []string{"behavior.messages.text-binary"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0", "oracle.autobahn.fuzzingserver"},
		Vectors:        []string{"vector.autobahn.case-6", "vector.utf8.corpus"},
		Properties:     []string{"property.messages.utf8-strictness"},
		Formals:        []string{"formal.messages.utf8-validation-total"},
		Applicability: []string{
			"applies to strict UTF-8 validation of text payloads",
			"applies to binary payload passthrough without transformation",
		},
		NonEquivalence: []string{
			"Java uses CharsetDecoder with REPORT actions; the Rust port validates UTF-8" +
				" incrementally and must reject the identical set of sequences",
		},
	},
	"slice.fragmentation": {
		Specifications: []string{"rfc6455.section-5-4"},
		Behaviors:      []string{"behavior.fragmentation.reassembly"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0", "oracle.autobahn.fuzzingserver"},
		Vectors:        []string{"vector.autobahn.case-5"},
		Properties:     []string{"property.fragmentation.bounded-state"},
		Formals:        []string{"formal.fragmentation.no-unbounded-growth"},
		Applicability: []string{
			"applies to continuation-frame reassembly and interleaved control frames",
		},
		NonEquivalence: []string{
			"Java buffers fragments in an unbounded list; the Rust port enforces a declared" +
				" maximum message size and fails closed at the limit",
		},
	},
	"slice.ping-pong": {
		Specifications: []string{"rfc6455.section-5-5-2", "rfc6455.section-5-5-3"},
		Behaviors:      []string{"behavior.control.ping-pong"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0", "oracle.autobahn.fuzzingserver"},
		Vectors:        []string{"vector.autobahn.case-2", "vector.autobahn.case-3"},
		Properties:     []string{"property.control.pong-echoes-ping-payload"},
		Formals:        []string{"formal.control.payload-length-bound"},
		Applicability: []string{
			"applies to ping and pong control frames with payloads of at most 125 octets",
		},
		NonEquivalence: []string{
			"Java's automatic keep-alive lives in the excluded AbstractWebSocket timer; the Rust" +
				" port exposes ping scheduling as an explicit caller-driven command",
		},
	},
	"slice.close-eof": {
		Specifications: []string{"rfc6455.section-5-5-1", "rfc6455.section-7-1", "rfc6455.section-7-4"},
		Behaviors:      []string{"behavior.close.terminal-state"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0", "oracle.autobahn.fuzzingserver"},
		Vectors:        []string{"vector.autobahn.case-7"},
		Properties:     []string{"property.close.code-validity"},
		Formals:        []string{"formal.close.terminal-absorbing"},
		Applicability: []string{
			"applies to the closing handshake, close codes, and EOF handling",
		},
		NonEquivalence: []string{
			"Java distinguishes close initiation by role through the excluded topology; the Rust" +
				" port models one absorbing terminal state reached identically from either side",
		},
	},
	"slice.concurrency": {
		Specifications: []string{"rfc6455.section-5-1"},
		Behaviors:      []string{"behavior.concurrency.bounded-commands"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0"},
		Vectors:        []string{"vector.concurrency.command-interleaving"},
		Properties:     []string{"property.concurrency.single-owner-serialization"},
		Formals:        []string{"formal.concurrency.no-data-race"},
		Applicability: []string{
			"applies to concurrent send and close commands against one connection",
		},
		NonEquivalence: []string{
			"Java uses synchronized regions plus an unbounded outgoing queue and a per-connection" +
				" worker thread; the Rust port uses one owner with a bounded queue and explicit" +
				" backpressure, so a full queue is observable where Java would grow without bound",
		},
	},
	"slice.tcp-adapter": {
		Specifications: []string{"rfc6455.section-1-7"},
		Behaviors:      []string{"behavior.adapter.blocking-io"},
		Oracles:        []string{"oracle.java-websocket.v1-6-0", "oracle.autobahn.fuzzingserver"},
		Vectors:        []string{"vector.autobahn.case-1"},
		Properties:     []string{"property.adapter.byte-stream-transparency"},
		Formals:        []string{"formal.adapter.no-protocol-logic"},
		Applicability: []string{
			"applies to the thin blocking TCP client and server adapters only",
		},
		NonEquivalence: []string{
			"Java multiplexes many connections on one NIO selector; the Rust adapter is a thin" +
				" blocking wrapper per connection and carries no protocol logic",
		},
	},
}

func buildMigrationMap(
	oracle OracleOutput,
	request DeriveRequest,
	selectedSet map[string]bool,
) (MigrationMap, error) {
	memberCounts := map[string]int{}
	for _, declaration := range oracle.Declarations {
		if declaration.InStudySurface && !declaration.IsType() {
			memberCounts[declaration.OwnerBinaryName]++
		}
	}

	var rows []MigrationRow
	for _, declaration := range oracle.Declarations {
		if !declaration.InStudySurface || !declaration.IsType() {
			continue
		}
		binaryName := declaration.OwnerBinaryName
		specs, assigned := sliceAssignment[binaryName]
		if !assigned || len(specs) == 0 {
			return MigrationMap{}, fmt.Errorf(
				"UNASSIGNED_SEMANTIC_TYPE: %s has no slice binding; refusing to sweep it in",
				binaryName)
		}

		bindings := make([]SliceBinding, 0, len(specs))
		evidenceUnion := map[string]bool{}
		applicability := map[string]bool{}
		nonEquivalence := map[string]bool{}
		specifications := map[string]bool{}
		behaviors := map[string]bool{}
		oracles := map[string]bool{}
		vectors := map[string]bool{}
		properties := map[string]bool{}
		formals := map[string]bool{}
		for _, spec := range specs {
			slice, known := sliceByID(spec.SliceID)
			if !known {
				return MigrationMap{}, fmt.Errorf(
					"UNKNOWN_SLICE: %s binds %s", binaryName, spec.SliceID)
			}
			behavior := spec.Behavior
			if behavior == "" {
				behavior = "entire declared surface of " + binaryName +
					" ports within this slice (" + slice.Title + ")"
			}
			bindingEvidence := evidenceObligationIDs(slice.ChildStoryID)
			for _, id := range bindingEvidence {
				evidenceUnion[id] = true
			}
			bindings = append(bindings, SliceBinding{
				PortSliceID:     slice.ID,
				ChildStoryID:    slice.ChildStoryID,
				TouchedBehavior: behavior,
				EvidenceIDs:     bindingEvidence,
			})
			evidence := sliceEvidenceBySlice[slice.ID]
			for _, value := range evidence.Applicability {
				applicability[value] = true
			}
			for _, value := range evidence.NonEquivalence {
				nonEquivalence[value] = true
			}
			for _, value := range evidence.Specifications {
				specifications[value] = true
			}
			for _, value := range evidence.Behaviors {
				behaviors[value] = true
			}
			for _, value := range evidence.Oracles {
				oracles[value] = true
			}
			for _, value := range evidence.Vectors {
				vectors[value] = true
			}
			for _, value := range evidence.Properties {
				properties[value] = true
			}
			for _, value := range evidence.Formals {
				formals[value] = true
			}
		}

		primary, _ := sliceByID(specs[0].SliceID)
		status := "PLANNED_RUST_IDENTITY_NOT_RESOLVER_VERIFIED"
		rustID := primary.RustModule + "::" + rustTypeName(binaryName)
		rustIdentityVerified := false
		if request.ToolchainRoot != "" {
			if reconciled, ok := us010SourceBoundRustIdentities[binaryName]; ok &&
				us010ClientHandshakePresent(workspaceProbeRoot(request)) {
				rustID = reconciled
			}
			if reconciled, ok := us011SourceBoundRustIdentities[binaryName]; ok &&
				us011ServerHandshakePresent(workspaceProbeRoot(request)) {
				rustID = reconciled
			}
			if reconciled, ok := us012SourceBoundRustIdentities[binaryName]; ok &&
				us012FrameCodecPresent(workspaceProbeRoot(request)) {
				rustID = reconciled
			}
			if resolved, ok := us009ResolvedRustIdentities[binaryName]; ok && rustWorkspacePresent(workspaceProbeRoot(request)) {
				rustID = resolved.RustSemanticID
				status = resolved.Status
				rustIdentityVerified = true
			}
		}
		if code, excludedCapability := capabilityExcluded[binaryName]; excludedCapability {
			status = "IN_SCOPE_SEMANTIC_ITEM_CAPABILITY_EXCLUDED"
			rustID = "(no Rust counterpart: " + code + ")"
			applicability["this Java type is inside the frozen study surface but its capability"+
				" is explicitly out of scope ("+code+")"] = true
			nonEquivalence["the Rust port intentionally provides no counterpart for "+binaryName+
				"; the behavior is excluded by "+code+" rather than reimplemented"] = true
		}

		rows = append(rows, MigrationRow{
			ID:                      stableID("migration", binaryName),
			JavaSemanticID:          binaryName,
			JavaBinaryName:          binaryName,
			JavaDescriptor:          declaration.Descriptor,
			JavaSignature:           declaration.GenericSignature,
			JavaKind:                declaration.Kind,
			JavaLookupStrength:      "semantic",
			JavaMemberCount:         memberCounts[binaryName],
			RustSemanticID:          rustID,
			RustResolver:            "rust-analyzer",
			RustIdentityVerified:    rustIdentityVerified,
			ApplicabilityConditions: sortedKeys(applicability),
			KnownNonEquivalentCases: sortedKeys(nonEquivalence),
			SourceRevision:          request.SourceCommit,
			DetectionQuery: fmt.Sprintf(
				"JavacTask.analyze() then Elements.getBinaryName(TypeElement) == %q at %s:%d",
				binaryName, declaration.File, declaration.Line),
			PortSlices:          bindings,
			TouchedFiles:        []string{declaration.File},
			SpecificationIDs:    sortedKeys(specifications),
			ObservedBehaviorIDs: sortedKeys(behaviors),
			OracleIDs:           sortedKeys(oracles),
			VectorIDs:           sortedKeys(vectors),
			PropertyClaimIDs:    sortedKeys(properties),
			FormalClaimIDs:      sortedKeys(formals),
			EvidenceIDs:         sortedKeys(evidenceUnion),
			Status:              status,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].JavaBinaryName < rows[j].JavaBinaryName })

	return MigrationMap{
		SchemaRef:     "../../schemas/semantic-id-migration-map-1.1.0.schema.json",
		SchemaVersion: "1.1.0",
		EntityType:    "MigrationMap",
		MapID:         "semantic-id-migration-map.us003",
		MapVersion:    "1.3.0",
		JavaIdentityMethod: JavaIdentityMethod{
			Tool:           "java-semantic-oracle 1.0.0",
			API:            oracle.IdentitySource,
			CompilerVendor: oracle.JDKVendor + " javac " + oracle.JDKVersion,
			CompilerFlags:  strings.Join(oracle.JavacOptions, " "),
			Strength:       "semantic",
			Statement: "Every Java identity in this map is the binary name and JVM descriptor" +
				" reported by javac's own symbol table after a zero-error JavacTask.analyze()" +
				" run. No identity in this map was obtained by text or grep matching, which the" +
				" story records as strictly weaker and unable to establish a proved claim.",
		},
		RustIdentityStatus: rustIdentityStatus(rustWorkspacePresent(workspaceProbeRoot(request))),
		Rows:               rows,
		Assurance:          ownerAttested,
	}, nil
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// computeSeamStatus derives a seam's resolution from its actual data instead of asserting it
// (review B2). The schema accepts only RESOLVED, so an unresolved seam fails derivation closed.
func computeSeamStatus(touchedFiles, obligations []string) string {
	if len(touchedFiles) == 0 || len(obligations) == 0 {
		return "UNRESOLVED"
	}
	return "RESOLVED"
}

// byteChannelContextSeam is the US-018 adapter surface over the excluded byte-channel wrappers
// (review B2): the adapter story's touched surface must include the files that define the
// byte-channel contract the Rust adapter replaces, with ISSLChannel as capability-excluded
// context.
func byteChannelContextSeam() Seam {
	touched := []string{
		"org/java_websocket/AbstractWrappedByteChannel.java",
		"org/java_websocket/WrappedByteChannel.java",
	}
	obligations := []string{
		stableID("evidence", "US-018-differential"),
		stableID("evidence", "US-018-property"),
	}
	return Seam{
		SurfaceID:             "seam.adapter.byte-channel-context",
		SemanticID:            stableID("migration", "org.java_websocket.interfaces.ISSLChannel"),
		Owner:                 "US-018",
		Category:              "adapter_seams",
		ChildStoryID:          "US-018",
		TouchedFiles:          touched,
		EvidenceObligationIDs: obligations,
		Status:                computeSeamStatus(touched, obligations),
	}
}

func buildSeamDossier(migration MigrationMap) (SeamDossier, error) {
	var seams []Seam
	for _, row := range migration.Rows {
		category, categorized := TypeCategories[row.JavaBinaryName]
		if !categorized {
			return SeamDossier{}, fmt.Errorf(
				"UNCATEGORIZED_SEMANTIC_TYPE: %s has no explicit seam category", row.JavaBinaryName)
		}
		for _, binding := range row.PortSlices {
			obligations := append(append([]string{}, binding.EvidenceIDs...),
				row.PropertyClaimIDs...)
			seams = append(seams, Seam{
				SurfaceID: stableID("seam",
					row.JavaBinaryName+"-"+strings.TrimPrefix(binding.PortSliceID, "slice.")),
				SemanticID:            row.ID,
				Owner:                 binding.ChildStoryID,
				Category:              category,
				ChildStoryID:          binding.ChildStoryID,
				TouchedFiles:          row.TouchedFiles,
				EvidenceObligationIDs: obligations,
				Status:                computeSeamStatus(row.TouchedFiles, obligations),
			})
		}
	}
	seams = append(seams, byteChannelContextSeam())
	sort.Slice(seams, func(i, j int) bool { return seams[i].SurfaceID < seams[j].SurfaceID })

	seamsByStory := map[string][]Seam{}
	for _, seam := range seams {
		seamsByStory[seam.ChildStoryID] = append(seamsByStory[seam.ChildStoryID], seam)
	}
	var stories []ImplementationStory
	for _, slice := range PortSlices {
		owned := seamsByStory[slice.ChildStoryID]
		seamIDs := make([]string, 0, len(owned))
		status := "TOUCHED_SURFACE_RESOLVED"
		if len(owned) == 0 {
			status = "TOUCHED_SURFACE_UNRESOLVED"
		}
		for _, seam := range owned {
			seamIDs = append(seamIDs, seam.SurfaceID)
			if seam.Status != "RESOLVED" {
				status = "TOUCHED_SURFACE_UNRESOLVED"
			}
		}
		sort.Strings(seamIDs)
		stories = append(stories, ImplementationStory{
			StoryID: slice.ChildStoryID,
			Title:   slice.Title,
			SeamIDs: seamIDs,
			Status:  status,
		})
	}

	return SeamDossier{
		SchemaRef:     "../../schemas/port-seam-dossier-1.0.0.schema.json",
		SchemaVersion: "1.0.0",
		EntityType:    "PortSeamDossier",
		DossierID:     "port-seam-dossier.us003",
		PublicBoundaries: []string{
			"org.java_websocket.WebSocket: the public connection interface (send, close, state)",
			"org.java_websocket.WebSocketListener: the public inbound callback boundary",
			"org.java_websocket.WebSocketAdapter: the default listener implementation",
			"org.java_websocket.drafts.Draft: the public protocol-strategy boundary",
			"org.java_websocket.framing.Framedata: the public frame accessor boundary",
			"org.java_websocket.handshake.Handshakedata: the public handshake accessor boundary",
		},
		InternalBoundaries: []string{
			"org.java_websocket.WebSocketImpl: the internal connection state machine",
			"org.java_websocket.drafts.Draft_6455: internal RFC 6455 draft implementation",
			"org.java_websocket.framing.FramedataImpl1: internal mutable frame representation",
			"org.java_websocket.handshake.HandshakedataImpl1: internal handshake representation",
		},
		Handshakes: []string{
			"client opening-handshake request construction and response validation (US-010)",
			"server opening-handshake validation and response construction (US-011)",
			"Sec-WebSocket-Key generation and Sec-WebSocket-Accept derivation via util.Base64",
			"HandshakeState decision surface (MATCHED / NOT_MATCHED)",
		},
		Frames: []string{
			"Opcode discrimination across continuous, text, binary, ping, pong, closing",
			"FramedataImpl1 fin/rsv/mask/payload-length decoding and encoding",
			"ControlFrame vs DataFrame validity rules",
			"CloseFrame code and reason encoding",
		},
		Ownership: []string{
			"Java: WebSocketImpl owns the connection state and is mutated from selector and" +
				" worker threads; the Rust port gives a single owner exclusive ownership",
			"Java: Framedata payload ByteBuffers are shared and mutable; the Rust port owns" +
				" payload bytes explicitly per frame",
			"Java: Draft instances are per-connection copies created by Draft.copyInstance()",
		},
		Buffers: []string{
			"WebSocketImpl inbound ByteBuffer accumulation across partial reads",
			"ByteBufferUtils.transferByteBuffer and empty-buffer sentinel behavior",
			"Draft_6455 incomplete-frame buffer retained between reads",
			"allocation limits enforced when decoding payload length",
		},
		Queues: []string{
			"WebSocketImpl.outQueue: outgoing BlockingQueue of ByteBuffers (unbounded in Java)," +
				" drained by the transport writer via onWriteDemand",
			"WebSocketImpl.inQueue (WebSocketImpl.java:102): inbound BlockingQueue declared on" +
				" the in-scope type but produced and drained exclusively by the excluded NIO" +
				" server topology (WebSocketServer.java:485,557,1135); inventoried explicitly," +
				" covered by EXCLUDED_JAVA_NIO_TOPOLOGY, no Rust counterpart",
			"the Rust port replaces outQueue with a bounded command queue with explicit" +
				" backpressure",
		},
		Threads: []string{
			"org.java_websocket.util.NamedThreadFactory: the study-surface thread seam",
			"Java's selector thread and worker pool live in the excluded server topology",
			"the Rust port runs the core on one owner with no interior threads",
		},
		Callbacks: []string{
			"WebSocketListener.onWebsocketOpen / onWebsocketMessage / onWebsocketClose /" +
				" onWebsocketError inbound callbacks",
			"WebSocketListener.onWriteDemand outbound demand signal",
			"WebSocketAdapter default onWebsocketPing automatic-pong reply",
			"the Rust port replaces callbacks with typed events drained by the caller",
		},
		WireFormats: []string{
			"RFC 6455 frame octets: fin, rsv1-3, opcode, mask bit, payload length, masking key",
			"RFC 6455 opening-handshake HTTP/1.1 request and 101 response octets",
			"close frame status code as a network-order unsigned 16-bit integer",
			"strict UTF-8 validity of text payloads (util.Charsetfunctions)",
		},
		Limits: []string{
			"maximum control-frame payload of 125 octets",
			"payload length encodings of 7, 7+16, and 7+64 bits",
			"LimitExceededException carries the exceeded limit",
			"the Rust port declares a maximum message size and fails closed at it",
		},
		TimeAndRandomness: []string{
			"Sec-WebSocket-Key generation uses randomness (Draft_6455 handshake path)",
			"masking-key generation uses randomness on the client side",
			"the excluded AbstractWebSocket carries the connection-lost timer; the Rust port" +
				" takes time and randomness as injected, testable inputs",
		},
		AdapterSeams: []string{
			"the byte-channel read and write seam consumed by US-018 (WrappedByteChannel," +
				" AbstractWrappedByteChannel define the wrapped-channel contract)",
			"the Autobahn conformance endpoint seam consumed by US-019",
			"ISSLChannel is an adapter seam whose TLS capability is explicitly excluded",
		},
		Seams:                 seams,
		ImplementationStories: stories,
		Assurance:             ownerAttested,
	}, nil
}

func requiredExclusionRecords() []ExclusionRecord {
	return []ExclusionRecord{
		{"EXCLUDED_TLS_WSS", "TLS and the wss:// scheme are out of scope. The port preserves the" +
			" RFC 6455 boundary over a plain byte stream; SSLSocketChannel, SSLSocketChannel2," +
			" and the TLS capability behind ISSLChannel are not ported."},
		{"EXCLUDED_PROXY_SUPPORT", "HTTP CONNECT proxy support is out of scope. The Java client" +
			" proxy path lives in the excluded client topology and has no Rust counterpart."},
		{"EXCLUDED_RECONNECT", "Automatic reconnect is out of scope. The Rust core models one" +
			" connection lifetime; reconnection is a caller policy, not ported behavior."},
		{"EXCLUDED_ANDROID", "Android-specific behavior and packaging are out of scope. No" +
			" Android runtime is an input to this laboratory."},
		{"EXCLUDED_RFC_7692_PERMESSAGE_DEFLATE", "RFC 7692 permessage-deflate is out of scope." +
			" The upstream extensions/permessage_deflate package is excluded from the study" +
			" surface and the port negotiates no compression extension."},
		{"EXCLUDED_JAVA_API_PARITY", "Java API parity is out of scope. The Rust port preserves" +
			" observable protocol behavior, not Java's class hierarchy, method names, or" +
			" exception types."},
		{"EXCLUDED_JAVA_NIO_TOPOLOGY", "Java's NIO topology is out of scope. The selector" +
			" thread, worker pool, and SocketChannel multiplexing are replaced by a thin" +
			" blocking adapter with no protocol logic."},
		{"EXCLUDED_EXTENSION_SUBPROTOCOL_PARITY", "Extension and subprotocol framework parity" +
			" is out of scope. The upstream extensions and protocols packages are excluded and" +
			" the port implements no negotiation framework."},
	}
}

func preservedBoundary(request DeriveRequest) PreservedBoundary {
	return PreservedBoundary{
		Standard:                       "RFC 6455",
		NormativeArtifactID:            "rfc6455-text",
		NormativeArtifactSHA256:        request.RFC6455SHA256,
		NormalizedCommandEventBehavior: true,
		WireOctetEquivalenceRequired:   true,
		Statement: "The preserved boundary is the RFC 6455 octet stream plus the normalized" +
			" command and event behavior of one connection. Parity is judged on wire octets and" +
			" normalized events, never on Java API shape.",
	}
}

func buildCompatibilitySurface(request DeriveRequest) CompatibilitySurface {
	edgeCases := []string{
		"nil", "empty", "malformed", "oversized", "duplicate", "interrupted", "stale",
		"upstream-error",
	}
	definitions := []struct {
		id    string
		kind  string
		story string
	}{
		{"surface.handshake.client-request", "wire", "US-010"},
		{"surface.handshake.server-response", "wire", "US-011"},
		{"surface.framing.frame-octets", "wire", "US-012"},
		{"surface.framing.masking", "wire", "US-012"},
		{"surface.messages.text-utf8", "wire", "US-013"},
		{"surface.messages.binary", "wire", "US-013"},
		{"surface.fragmentation.continuation", "wire", "US-014"},
		{"surface.control.ping-pong", "wire", "US-015"},
		{"surface.close.status-code", "wire", "US-016"},
		{"surface.close.terminal-state", "state", "US-016"},
		{"surface.concurrency.command-order", "state", "US-017"},
		{"surface.errors.protocol-fault", "error", "US-012"},
		{"surface.limits.allocation", "resource", "US-012"},
		{"surface.adapter.byte-stream", "operational", "US-018"},
	}
	items := make([]CompatibilityItem, 0, len(definitions))
	for _, definition := range definitions {
		items = append(items, CompatibilityItem{
			SurfaceID:             definition.id,
			Kind:                  definition.kind,
			EdgeCases:             edgeCases,
			OracleID:              "oracle.java-websocket.v1-6-0",
			EvidenceObligationIDs: evidenceObligationIDs(definition.story),
			CutoverObligationID:   stableID("cutover", definition.id),
			ObservationStatus:     "OBSERVED",
			BlockerCode:           "",
		})
	}
	return CompatibilitySurface{
		SchemaRef:         "../../schemas/compatibility-surface-1.0.0.schema.json",
		SchemaVersion:     "1.0.0",
		EntityType:        "CompatibilitySurface",
		SurfaceID:         "compatibility-surface.us003",
		PreservedBoundary: preservedBoundary(request),
		Items:             items,
		ExcludedSurfaces:  requiredExclusionRecords(),
		Assurance:         ownerAttested,
	}
}

func buildCutoverContract(request DeriveRequest) CutoverContract {
	definitions := []struct {
		id    string
		story string
	}{
		{"surface.handshake.client-request", "US-010"},
		{"surface.handshake.server-response", "US-011"},
		{"surface.framing.frame-octets", "US-012"},
		{"surface.framing.masking", "US-012"},
		{"surface.messages.text-utf8", "US-013"},
		{"surface.messages.binary", "US-013"},
		{"surface.fragmentation.continuation", "US-014"},
		{"surface.control.ping-pong", "US-015"},
		{"surface.close.status-code", "US-016"},
		{"surface.close.terminal-state", "US-016"},
		{"surface.concurrency.command-order", "US-017"},
		{"surface.errors.protocol-fault", "US-012"},
		{"surface.limits.allocation", "US-012"},
		{"surface.adapter.byte-stream", "US-018"},
	}
	obligations := make([]CutoverObligation, 0, len(definitions))
	for _, definition := range definitions {
		obligations = append(obligations, CutoverObligation{
			ID:           stableID("cutover", definition.id),
			SurfaceID:    definition.id,
			ChildStoryID: definition.story,
			Status:       "DECLARED",
			EvidenceIDs:  []string{},
		})
	}
	return CutoverContract{
		SchemaRef:     "../../schemas/cutover-contract-1.0.0.schema.json",
		SchemaVersion: "1.0.0",
		EntityType:    "CutoverContract",
		ContractID:    "cutover-contract.us003",
		ReplacementBoundary: "The replacement boundary is the in-process WebSocket connection" +
			" library surface behind the RFC 6455 wire boundary, exercised through the thin TCP" +
			" adapter and the pinned Autobahn conformance endpoint. Java remains the rollback" +
			" target for the whole boundary.",
		PreservedBoundary:   preservedBoundary(request),
		ExcludedBehaviors:   requiredExclusionRecords(),
		UnresolvedBehaviors: []string{},
		ReadinessLadder:     ReadinessLadder,
		Obligations:         obligations,
		Assurance:           ownerAttested,
	}
}

func evidenceObligationIDs(story string) []string {
	if story == "US-010" {
		return []string{"evidence.us-010-client-handshake"}
	}
	if story == "US-011" {
		return []string{"evidence.us-011-server-handshake"}
	}
	if story == "US-012" {
		return []string{"evidence.us-012-frame-codec"}
	}
	return []string{
		stableID("evidence", story+"-differential"),
		stableID("evidence", story+"-property"),
	}
}

// rustIdentityStatus states the live Rust-workspace fact honestly in both
// directions. The declared flag is probed from the repository at derive time
// (never hardcoded): US-003's lane derived before the rust/ workspace scaffold
// merged, and the hardcoded false broke mainline once both lanes landed.
// Either way every row stays rust_identity_verified=false until a resolver
// actually verifies it under US-009+.
func rustIdentityStatus(workspacePresent bool) RustIdentityStatus {
	if workspacePresent {
		return RustIdentityStatus{
			WorkspacePresent:  true,
			PlannedResolver:   "rust-analyzer",
			BlockerCode:       "RUST_IDENTITIES_PARTIALLY_RESOLVER_VERIFIED",
			CreatedByStory:    "US-009",
			Statement:         "The immutable US-009 pinned rust-analyzer SCIP receipt resolves exactly websocket_core::ConnectionCore, websocket_core::ConnectionState, and websocket_core::Role. US-010, US-011, and US-012 reconcile Java-shaped planned names to the small shipped public capability set, but the pinned resolver executable is no longer locally available, so every new handshake and frame identity remains explicitly resolver-unverified and no Java-shaped Rust alias is fabricated.",
			ResolutionReceipt: us009RustResolutionReceipt(),
		}
	}
	return RustIdentityStatus{
		WorkspacePresent: false,
		PlannedResolver:  "rust-analyzer",
		BlockerCode:      "RUST_WORKSPACE_NOT_YET_CREATED",
		CreatedByStory:   "US-009",
		Statement: "No Rust workspace exists in this repository yet, so rust-analyzer was" +
			" not run and no Rust identity here is resolver-verified. Every rust_semantic_id" +
			" is a planned identity and every row carries rust_identity_verified=false." +
			" US-009 creates the workspace; this map must be re-derived and each Rust" +
			" identity resolved before any row may claim verification.",
	}
}

type resolvedRustIdentity struct {
	RustSemanticID string
	Status         string
	SCIPSymbol     string
}

var us009ResolvedRustIdentities = map[string]resolvedRustIdentity{
	"org.java_websocket.WebSocketImpl":    {"websocket_core::ConnectionCore", "RESOLVER_VERIFIED_CAPABILITY_REPLACEMENT", "rust-analyzer cargo websocket-core 0.0.0 connection/ConnectionCore#"},
	"org.java_websocket.enums.ReadyState": {"websocket_core::ConnectionState", "RESOLVER_VERIFIED_CAPABILITY_REPLACEMENT", "rust-analyzer cargo websocket-core 0.0.0 connection/ConnectionState#"},
	"org.java_websocket.enums.Role":       {"websocket_core::Role", "RESOLVER_VERIFIED_DIRECT_IDENTITY", "rust-analyzer cargo websocket-core 0.0.0 connection/Role#"},
}

// us010SourceBoundRustIdentities reconciles pre-scaffold, Java-shaped planned
// names to the deliberately small public capability set actually shipped by
// US-010. These are source bindings only: unlike the three immutable US-009
// resolutions above, none may claim resolver verification without the exact
// pinned rust-analyzer executable.
var us010SourceBoundRustIdentities = map[string]string{
	"org.java_websocket.WebSocketAdapter":                        "websocket_core::LocalCommand",
	"org.java_websocket.WebSocketImpl":                           "websocket_core::ConnectionCore",
	"org.java_websocket.WebSocketListener":                       "websocket_core::SemanticEvent",
	"org.java_websocket.drafts.Draft":                            "websocket_core::ConnectionCore",
	"org.java_websocket.drafts.Draft_6455":                       "websocket_core::ConnectionCore",
	"org.java_websocket.enums.HandshakeState":                    "websocket_core::HandshakeFailure",
	"org.java_websocket.exceptions.IncompleteHandshakeException": "websocket_core::HandshakeFailure",
	"org.java_websocket.exceptions.InvalidDataException":         "websocket_core::HandshakeFailure",
	"org.java_websocket.exceptions.InvalidHandshakeException":    "websocket_core::HandshakeFailure",
	"org.java_websocket.handshake.ClientHandshake":               "websocket_core::ClientRequestDescriptor",
	"org.java_websocket.handshake.ClientHandshakeBuilder":        "websocket_core::ClientRequestDescriptor",
	"org.java_websocket.handshake.HandshakeBuilder":              "websocket_core::LocalCommand",
	"org.java_websocket.handshake.HandshakeImpl1Client":          "websocket_core::ClientRequestDescriptor",
	"org.java_websocket.handshake.Handshakedata":                 "websocket_core::ClientRequestDescriptor",
	"org.java_websocket.handshake.HandshakedataImpl1":            "websocket_core::ClientRequestDescriptor",
	"org.java_websocket.util.Base64":                             "websocket_core::ConnectionCore",
	"org.java_websocket.util.Base64$OutputStream":                "websocket_core::ConnectionCore",
}

// us011SourceBoundRustIdentities replaces stale Java-shaped server-handshake
// planning names with the small capability set actually shipped by US-011.
// ConnectionCore retains only its immutable US-009 resolver qualification;
// the descriptor, failure, and event identities remain source-bound.
var us011SourceBoundRustIdentities = map[string]string{
	"org.java_websocket.WebSocketAdapter":                 "websocket_core::ServerRequestDescriptor",
	"org.java_websocket.WebSocketImpl":                    "websocket_core::ConnectionCore",
	"org.java_websocket.WebSocketListener":                "websocket_core::SemanticEvent",
	"org.java_websocket.drafts.Draft":                     "websocket_core::ConnectionCore",
	"org.java_websocket.drafts.Draft_6455":                "websocket_core::ConnectionCore",
	"org.java_websocket.enums.HandshakeState":             "websocket_core::HandshakeFailure",
	"org.java_websocket.exceptions.InvalidDataException":  "websocket_core::HandshakeFailure",
	"org.java_websocket.handshake.HandshakeImpl1Server":   "websocket_core::ServerRequestDescriptor",
	"org.java_websocket.handshake.ServerHandshake":        "websocket_core::ServerRequestDescriptor",
	"org.java_websocket.handshake.ServerHandshakeBuilder": "websocket_core::ServerRequestDescriptor",
}

// us012SourceBoundRustIdentities replaces stale Java-shaped frame planning
// names only for types owned wholly by the framing slice. Shared connection,
// draft, and exception types retain their earlier capability identities: a
// later slice may not rewrite the whole migration row through one facet.
// These bindings name shipped public Rust symbols but remain resolver-
// unverified because the immutable US-009 resolver is unavailable.
var us012SourceBoundRustIdentities = map[string]string{
	"org.java_websocket.drafts.Draft_6455$TranslatedPayloadMetaData": "websocket_core::frame::decode::FrameHeader",
	"org.java_websocket.enums.Opcode":                                "websocket_core::frame::Opcode",
	"org.java_websocket.exceptions.IncompleteException":              "websocket_core::frame::decode::FrameHeaderDecode",
	"org.java_websocket.exceptions.InvalidFrameException":            "websocket_core::FrameFailure",
	"org.java_websocket.exceptions.LimitExceededException":           "websocket_core::FailureKind",
	"org.java_websocket.exceptions.NotSendableException":             "websocket_core::FrameFailure",
	"org.java_websocket.framing.ControlFrame":                        "websocket_core::frame::Frame",
	"org.java_websocket.framing.DataFrame":                           "websocket_core::frame::Frame",
	"org.java_websocket.framing.Framedata":                           "websocket_core::frame::Frame",
	"org.java_websocket.framing.FramedataImpl1":                      "websocket_core::frame::Frame",
	"org.java_websocket.util.ByteBufferUtils":                        "websocket_core::frame::Frame",
}

func us009RustResolutionReceipt() *RustIdentityResolutionReceipt {
	return &RustIdentityResolutionReceipt{
		StoryID:              "US-009",
		ResolverArtifactID:   "rust-analyzer-2026-08-17.4-aarch64-apple-darwin",
		ResolverVersion:      "2026-08-17.4 commit bb3bbbd9e4",
		ResolverBinarySHA256: "sha256:5142e0d6d0a48bc8ba0638125eaa68296defba7d32628362175eff967d12e145",
		Mode:                 "OFFLINE_SCIP_INDEX",
		Command:              []string{"rust-analyzer", "scip", "rust", "--output", "us009-websocket-core.scip", "--exclude-vendored-libraries"},
		Network:              "DENY_CARGO_NET_OFFLINE",
		IndexSHA256:          "sha256:233e079818fcc71ee9678774def67ef69e50e5a0cab990d645181eaddf3c250b",
		Resolutions: []RustIdentityResolution{
			{"org.java_websocket.WebSocketImpl", us009ResolvedRustIdentities["org.java_websocket.WebSocketImpl"].RustSemanticID, us009ResolvedRustIdentities["org.java_websocket.WebSocketImpl"].SCIPSymbol},
			{"org.java_websocket.enums.ReadyState", us009ResolvedRustIdentities["org.java_websocket.enums.ReadyState"].RustSemanticID, us009ResolvedRustIdentities["org.java_websocket.enums.ReadyState"].SCIPSymbol},
			{"org.java_websocket.enums.Role", us009ResolvedRustIdentities["org.java_websocket.enums.Role"].RustSemanticID, us009ResolvedRustIdentities["org.java_websocket.enums.Role"].SCIPSymbol},
		},
		UnresolvedScope: "All other migration rows remain rust_identity_verified=false and are not claimed by this receipt.",
	}
}

// workspaceProbeRoot names the repository whose Rust-workspace presence the
// migration map declares: the evidence-hosting repository (ToolchainRoot),
// never the derive OUTPUT root — reproduction derives into a temp directory,
// and probing that would blind the declaration to the real repository state.
func workspaceProbeRoot(request DeriveRequest) string {
	if request.ToolchainRoot != "" {
		return request.ToolchainRoot
	}
	return request.Root
}
