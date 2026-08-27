package linkage

// symbolSpec locates one landed Rust symbol for the deterministic
// declaration scan. File paths are repository-relative.
type symbolSpec struct {
	DeclKind string
	File     string
}

// symbolCatalog maps every landed Rust path referenced by a row mapping, a
// proof-target binding, or a story binding to its declaring file. The
// resolver refuses to emit any symbol that does not scan to a real
// declaration in the named file — a symbol is never claimed where it does
// not exist.
var symbolCatalog = map[string]symbolSpec{
	// ws_core::connection
	"ws_core::connection::ConnectionCore":                         {DeclKind: "struct", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::WebSocketImpl":                          {DeclKind: "type_alias", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::LocalCommand":                           {DeclKind: "enum", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::LocalCommand::SendClose":                {DeclKind: "enum_variant", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::Input":                                  {DeclKind: "enum", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::Input::TransportEof":                    {DeclKind: "enum_variant", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::TransportWrite":                         {DeclKind: "struct", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::DataOpcode":                             {DeclKind: "enum", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::ReadyState":                             {DeclKind: "enum", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::Role":                                   {DeclKind: "enum", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::CommandQueue":                           {DeclKind: "struct", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::CommandSender":                          {DeclKind: "struct", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::ConnectionCore::handle":                 {DeclKind: "method", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::ConnectionCore::handle_command":         {DeclKind: "method", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::ConnectionCore::handle_eof":             {DeclKind: "method", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::ConnectionCore::process_inbound":        {DeclKind: "method", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::ConnectionCore::finish_handshake_open":  {DeclKind: "method", File: "rust/ws-core/src/connection.rs"},
	"ws_core::connection::ConnectionCore::begin_client_handshake": {DeclKind: "method", File: "rust/ws-core/src/connection.rs"},

	// ws_core::event
	"ws_core::event::SemanticEvent":     {DeclKind: "struct", File: "rust/ws-core/src/event.rs"},
	"ws_core::event::SemanticEventKind": {DeclKind: "enum", File: "rust/ws-core/src/event.rs"},
	"ws_core::event::FrameRecord":       {DeclKind: "struct", File: "rust/ws-core/src/event.rs"},

	// ws_core::framing
	"ws_core::framing::Draft6455":                             {DeclKind: "struct", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::Opcode":                                {DeclKind: "enum", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::FrameHeader":                           {DeclKind: "struct", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::HeaderDecode":                          {DeclKind: "enum", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::HeaderDecode::Insufficient":            {DeclKind: "enum_variant", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::FrameReject":                           {DeclKind: "struct", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::DecodedFrame":                          {DeclKind: "struct", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::Draft6455::decode_frame_header":        {DeclKind: "method", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::Draft6455::apply_mask":                 {DeclKind: "method", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::Draft6455::encode_frame":               {DeclKind: "method", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::Draft6455::process_frame":              {DeclKind: "method", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::Draft6455::process_frame_continuous":   {DeclKind: "method", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::Draft6455::check_buffer_limit":         {DeclKind: "method", File: "rust/ws-core/src/framing.rs"},
	"ws_core::framing::Draft6455::accept_handshake_as_server": {DeclKind: "method", File: "rust/ws-core/src/handshake/server.rs"},
	"ws_core::framing::Draft6455::generate_accept_key":        {DeclKind: "method", File: "rust/ws-core/src/handshake/crypto.rs"},

	// ws_core::fragment
	"ws_core::fragment::ContinuousFrame": {DeclKind: "struct", File: "rust/ws-core/src/fragment.rs"},

	// ws_core::error
	"ws_core::error::FailureCode":                      {DeclKind: "enum", File: "rust/ws-core/src/error.rs"},
	"ws_core::error::FailureCode::JavaInvalidData":     {DeclKind: "enum_variant", File: "rust/ws-core/src/error.rs"},
	"ws_core::error::FailureCode::JavaNotSendable":     {DeclKind: "enum_variant", File: "rust/ws-core/src/error.rs"},
	"ws_core::error::FailureCode::StateViolation":      {DeclKind: "enum_variant", File: "rust/ws-core/src/error.rs"},
	"ws_core::error::FailureCode::InputLimitExceeded":  {DeclKind: "enum_variant", File: "rust/ws-core/src/error.rs"},
	"ws_core::error::FailureCode::BufferLimitExceeded": {DeclKind: "enum_variant", File: "rust/ws-core/src/error.rs"},
	"ws_core::error::TypedProtocolFailure":             {DeclKind: "struct", File: "rust/ws-core/src/error.rs"},

	// ws_core::close
	"ws_core::close::CloseDetail":               {DeclKind: "struct", File: "rust/ws-core/src/close.rs"},
	"ws_core::close::normalize_send_close_code": {DeclKind: "fn", File: "rust/ws-core/src/close.rs"},
	"ws_core::close::close_code_rejection":      {DeclKind: "fn", File: "rust/ws-core/src/close.rs"},

	// ws_core::message
	"ws_core::message::Charsetfunctions":                {DeclKind: "struct", File: "rust/ws-core/src/message.rs"},
	"ws_core::message::Charsetfunctions::is_valid_utf8": {DeclKind: "method", File: "rust/ws-core/src/message.rs"},
	"ws_core::message::Charsetfunctions::string_utf8":   {DeclKind: "method", File: "rust/ws-core/src/message.rs"},
	"ws_core::message::Utf8DecodeError":                 {DeclKind: "struct", File: "rust/ws-core/src/message.rs"},

	// ws_core::handshake
	"ws_core::handshake::RejectChannel":                   {DeclKind: "enum", File: "rust/ws-core/src/handshake.rs"},
	"ws_core::handshake::http::JavaHeaders":               {DeclKind: "struct", File: "rust/ws-core/src/handshake/http.rs"},
	"ws_core::handshake::http::JavaHead":                  {DeclKind: "struct", File: "rust/ws-core/src/handshake/http.rs"},
	"ws_core::handshake::http::JavaHeadParse":             {DeclKind: "enum", File: "rust/ws-core/src/handshake/http.rs"},
	"ws_core::handshake::http::JavaHeadParse::Incomplete": {DeclKind: "enum_variant", File: "rust/ws-core/src/handshake/http.rs"},
	"ws_core::handshake::http::HeadAccumulator":           {DeclKind: "struct", File: "rust/ws-core/src/handshake/http.rs"},
	"ws_core::handshake::client::ClientHandshake":         {DeclKind: "struct", File: "rust/ws-core/src/handshake/client.rs"},
	"ws_core::handshake::client::ClientRequestDescriptor": {DeclKind: "struct", File: "rust/ws-core/src/handshake/client.rs"},
	"ws_core::handshake::client::ClientHandshakeOutcome":  {DeclKind: "enum", File: "rust/ws-core/src/handshake/client.rs"},
	"ws_core::handshake::client::nonce_from_seed":         {DeclKind: "fn", File: "rust/ws-core/src/handshake/client.rs"},
	"ws_core::handshake::server::HandshakeState":          {DeclKind: "enum", File: "rust/ws-core/src/handshake/server.rs"},
	"ws_core::handshake::server::ServerHandshake":         {DeclKind: "struct", File: "rust/ws-core/src/handshake/server.rs"},
	"ws_core::handshake::server::ServerHandshakeOutcome":  {DeclKind: "enum", File: "rust/ws-core/src/handshake/server.rs"},
	"ws_core::handshake::crypto::encode_base64":           {DeclKind: "fn", File: "rust/ws-core/src/handshake/crypto.rs"},
	"ws_core::handshake::crypto::encode_nonce":            {DeclKind: "fn", File: "rust/ws-core/src/handshake/crypto.rs"},

	// ws_core::queue
	"ws_core::queue::BoundedQueue": {DeclKind: "struct", File: "rust/ws-core/src/queue.rs"},

	// ws_driver
	"ws_driver::ConnectionDriver":  {DeclKind: "struct", File: "rust/ws-driver/src/lib.rs"},
	"ws_driver::connection_driver": {DeclKind: "fn", File: "rust/ws-driver/src/lib.rs"},

	// ws_testee
	"ws_testee::io_loop::drive_connection":         {DeclKind: "fn", File: "rust/ws-testee/src/io_loop.rs"},
	"ws_testee::io_loop::IoBounds":                 {DeclKind: "struct", File: "rust/ws-testee/src/io_loop.rs"},
	"ws_testee::io_loop::LoopOutcome":              {DeclKind: "enum", File: "rust/ws-testee/src/io_loop.rs"},
	"ws_testee::io_loop::LoopOutcome::SocketError": {DeclKind: "enum_variant", File: "rust/ws-testee/src/io_loop.rs"},
	"ws_testee::client::run_client_once":           {DeclKind: "fn", File: "rust/ws-testee/src/client.rs"},
	"ws_testee::server::run_server_once":           {DeclKind: "fn", File: "rust/ws-testee/src/server.rs"},
}

// rowMapping is the curated, truthful landed mapping for one migration row.
type rowMapping struct {
	Disposition string
	Symbols     []string
	Rationale   string
}

// Row dispositions.
const (
	dispositionExact     = "exact"
	dispositionRelocated = "relocated"
	dispositionRenamed   = "renamed"
	dispositionAbsorbed  = "absorbed"
	dispositionExcluded  = "capability_excluded"
)

// rowMappings covers every row of the US-003 migration map by id. Dispositions:
//
//   - exact: the planned identity resolves as declared.
//   - relocated: the same named symbol landed in a different module.
//   - renamed: a one-to-one landed counterpart under a different name.
//   - absorbed: no distinct counterpart symbol; the row's ported behavior is
//     carried by the named landed symbols (rationale explains the collapse).
//   - capability_excluded: the map itself records no Rust counterpart; the
//     resolver confirms no such symbol landed.
var rowMappings = map[string]rowMapping{
	"migration.org-java-websocket-websocket": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::ConnectionCore",
			"ws_core::connection::LocalCommand",
			"ws_core::connection::CommandSender",
		},
		Rationale: "The WebSocket interface's command surface landed as the single owned ConnectionCore with the explicit LocalCommand vocabulary and CommandSender/CommandQueue owner seam — the collapse the map's own known_non_equivalent_cases declares (abstract class hierarchy -> one owned core with explicit command and event types). No trait named WebSocket exists.",
	},
	"migration.org-java-websocket-websocketadapter": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::event::SemanticEvent",
			"ws_core::event::SemanticEventKind",
		},
		Rationale: "The default-listener adapter landed as the semantic event stream: every callback WebSocketAdapter defaulted is observable as a SemanticEventKind value drained by the owner. Its default automatic pong does NOT exist in the core (quirk Q18, batch-C strip documented in ws-core/src/control.rs): auto-pong is adapter policy above the core, so no WebSocketAdapter symbol landed.",
	},
	"migration.org-java-websocket-websocketimpl": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::connection::WebSocketImpl",
			"ws_core::connection::ConnectionCore",
		},
		Rationale: "The planned identity exists verbatim as the deliberate alias `pub type WebSocketImpl = ConnectionCore` in connection.rs; ConnectionCore is the landed connection state machine behind it.",
	},
	"migration.org-java-websocket-websocketlistener": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::event::SemanticEvent",
			"ws_core::connection::TransportWrite",
		},
		Rationale: "The listener callback boundary landed as the two owner-drained output streams: SemanticEvent (semantic callbacks) and TransportWrite (onWriteDemand/wire writes). No WebSocketListener trait exists; the map's known_non_equivalent_cases predicted this serialization through the owner.",
	},
	"migration.org-java-websocket-drafts-draft": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::Draft6455",
		},
		Rationale: "The Draft strategy seam collapsed: this is a single-draft (RFC 6455 only) port, so the abstract Draft contract's touched behaviors (createHandshake/translate/createFrames/processFrame/continuousFrame state) landed directly on Draft6455 with no trait indirection. No Draft trait exists in ws_core::connection.",
	},
	"migration.org-java-websocket-drafts-draft-6455": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::framing::Draft6455",
		},
		Rationale: "Planned identity landed as declared.",
	},
	"migration.org-java-websocket-drafts-draft-6455-translatedpayloadmetadata": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::FrameHeader",
			"ws_core::framing::HeaderDecode",
		},
		Rationale: "TranslatedPayloadMetaData's payload-length/realpacketsize metadata landed inside FrameHeader and the HeaderDecode outcome of Draft6455::decode_frame_header; no separate metadata struct was needed.",
	},
	"migration.org-java-websocket-enums-closehandshaketype": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::ConnectionCore::handle_command",
			"ws_core::connection::ConnectionCore::process_inbound",
		},
		Rationale: "CloseHandshakeType existed to let Draft implementations declare NONE/ONEWAY/TWOWAY closing. The single-draft port hardwires the RFC 6455 two-way close inside ConnectionCore's command/inbound close arms, so the capability enum was eliminated with the Draft seam; no CloseHandshakeType enum exists.",
	},
	"migration.org-java-websocket-enums-handshakestate": {
		Disposition: dispositionRelocated,
		Symbols: []string{
			"ws_core::handshake::server::HandshakeState",
		},
		Rationale: "The enum landed with its planned name but in the server handshake module (its only Java consumer is acceptHandshakeAsServer/asClient matching; the Rust home is the server-side acceptance predicate file), not the planned ws_core::handshake::client module.",
	},
	"migration.org-java-websocket-enums-opcode": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::framing::Opcode",
		},
		Rationale: "Planned identity landed as declared.",
	},
	"migration.org-java-websocket-enums-readystate": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::connection::ReadyState",
		},
		Rationale: "Planned identity landed as declared.",
	},
	"migration.org-java-websocket-enums-role": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::connection::Role",
		},
		Rationale: "Planned identity landed as declared.",
	},
	"migration.org-java-websocket-exceptions-incompleteexception": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::HeaderDecode::Insufficient",
		},
		Rationale: "IncompleteException's control flow (frame needs more bytes) landed as the HeaderDecode::Insufficient outcome plus incomplete-frame buffering in the decode loop; exceptions-as-control-flow became typed outcomes (a declared known_non_equivalent_case).",
	},
	"migration.org-java-websocket-exceptions-incompletehandshakeexception": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::http::JavaHeadParse::Incomplete",
			"ws_core::handshake::http::HeadAccumulator",
		},
		Rationale: "IncompleteHandshakeException's keep-buffering path landed as the JavaHeadParse::Incomplete outcome of the budget-gated HeadAccumulator; the variant's doc names the exception path explicitly.",
	},
	"migration.org-java-websocket-exceptions-invaliddataexception": {
		Disposition: dispositionRenamed,
		Symbols: []string{
			"ws_core::error::FailureCode::JavaInvalidData",
			"ws_core::error::TypedProtocolFailure",
		},
		Rationale: "InvalidDataException landed one-to-one as the FailureCode::JavaInvalidData variant (wire code JAVA_INVALID_DATA), carried with its close code by TypedProtocolFailure — the typed-protocol-error rename the map's known_non_equivalent_cases declares.",
	},
	"migration.org-java-websocket-exceptions-invalidencodingexception": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::message::Utf8DecodeError",
			"ws_core::error::FailureCode::JavaInvalidData",
		},
		Rationale: "InvalidEncodingException (the UTF-8 subtype of InvalidDataException) landed as Utf8DecodeError at the strict string_utf8 gate, surfacing as JavaInvalidData with close code 1007; no separate encoding-exception type exists.",
	},
	"migration.org-java-websocket-exceptions-invalidframeexception": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::FrameReject",
			"ws_core::error::FailureCode::JavaInvalidData",
		},
		Rationale: "InvalidFrameException landed as the translate-stage FrameReject (typed failure plus the exact consumed-byte offset, quirk Q25) feeding the JavaInvalidData failure vocabulary; no frame-exception type exists.",
	},
	"migration.org-java-websocket-exceptions-invalidhandshakeexception": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::RejectChannel",
		},
		Rationale: "InvalidHandshakeException landed as the typed RejectChannel handshake-rejection vocabulary (parse-level and validation-level channels) instead of an exception type.",
	},
	"migration.org-java-websocket-exceptions-limitexceededexception": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::error::FailureCode::InputLimitExceeded",
			"ws_core::error::FailureCode::BufferLimitExceeded",
			"ws_core::framing::Draft6455::check_buffer_limit",
		},
		Rationale: "LimitExceededException (1009 family) landed as the typed limit failure codes plus the 1009 JavaInvalidData sites at the framing limit gates (check_buffer_limit and the length-limit checks in decode_frame_header); no exception type exists.",
	},
	"migration.org-java-websocket-exceptions-notsendableexception": {
		Disposition: dispositionRenamed,
		Symbols: []string{
			"ws_core::error::FailureCode::JavaNotSendable",
		},
		Rationale: "NotSendableException landed one-to-one as the FailureCode::JavaNotSendable variant (wire code JAVA_NOT_SENDABLE, send-path DFA rejection, quirk Q16).",
	},
	"migration.org-java-websocket-exceptions-websocketnotconnectedexception": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::error::FailureCode::StateViolation",
		},
		Rationale: "WebsocketNotConnectedException (send while not OPEN) landed inside the StateViolation failure code (the requireOpen gate, quirk Q26), which also covers the other closed/closing-state refusals; no dedicated not-connected type exists.",
	},
	"migration.org-java-websocket-exceptions-wrappedioexception": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_testee::io_loop::LoopOutcome::SocketError",
		},
		Rationale: "The planned ws_adapter crate landed as the ws-testee adapter (with ws-driver as the deterministic owner loop). WrappedIOException's wrapped-transport-error role landed as the normalized LoopOutcome::SocketError adapter outcome; no wrapper exception type exists.",
	},
	"migration.org-java-websocket-framing-binaryframe": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::DataOpcode",
			"ws_core::framing::DecodedFrame",
			"ws_core::event::SemanticEventKind",
		},
		Rationale: "The per-opcode frame class hierarchy landed as data: BinaryFrame is DecodedFrame with Opcode::Binary, delivered as the SemanticEventKind Binary event and sent via DataOpcode::Binary; no per-opcode frame types exist.",
	},
	"migration.org-java-websocket-framing-closeframe": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::close::CloseDetail",
			"ws_core::close::normalize_send_close_code",
			"ws_core::close::close_code_rejection",
		},
		Rationale: "CloseFrame's code/reason payload semantics landed as CloseDetail plus the US-009 owner-decision pure functions that mirror CloseFrame.setCode/isValid quirks exactly (Q13/Q14); no CloseFrame type exists.",
	},
	"migration.org-java-websocket-framing-continuousframe": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::fragment::ContinuousFrame",
		},
		Rationale: "Planned identity landed as declared (the inbound continuation accumulator).",
	},
	"migration.org-java-websocket-framing-controlframe": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::Draft6455::process_frame",
			"ws_core::framing::Opcode",
		},
		Rationale: "ControlFrame's shared control-validity checks (fin, reserved bits) landed at the Draft6455 translate/process gates over Opcode's control values; the deliberate absence of a >125 outbound preflight mirrors quirk Q17. No ControlFrame type exists (ws-core/src/control.rs is a documentation module that exports nothing by design).",
	},
	"migration.org-java-websocket-framing-dataframe": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::DecodedFrame",
			"ws_core::connection::DataOpcode",
		},
		Rationale: "DataFrame's data-opcode abstraction landed as DecodedFrame plus the DataOpcode send vocabulary; no DataFrame type exists.",
	},
	"migration.org-java-websocket-framing-framedata": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::FrameHeader",
			"ws_core::framing::DecodedFrame",
		},
		Rationale: "The Framedata interface (fin/rsv/opcode/payload accessors) landed as the plain data structs FrameHeader and DecodedFrame; no interface indirection exists.",
	},
	"migration.org-java-websocket-framing-framedataimpl1": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::DecodedFrame",
			"ws_core::event::FrameRecord",
		},
		Rationale: "FramedataImpl1's mutable frame carrier landed as the owned DecodedFrame (wire side) and FrameRecord (observable frame event); no builder-style frame implementation exists.",
	},
	"migration.org-java-websocket-framing-pingframe": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::Opcode",
			"ws_core::event::SemanticEventKind",
		},
		Rationale: "PingFrame landed as Opcode::Ping frames observed as the SemanticEventKind Ping event with the exact decoded payload; no PingFrame type exists (control dispatch lives in ConnectionCore::process_inbound, quirk Q18: no automatic pong).",
	},
	"migration.org-java-websocket-framing-pongframe": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::Opcode",
			"ws_core::event::SemanticEventKind",
		},
		Rationale: "PongFrame landed as Opcode::Pong frames observed as the SemanticEventKind Pong event; no PongFrame type exists.",
	},
	"migration.org-java-websocket-framing-textframe": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::DataOpcode",
			"ws_core::message::Charsetfunctions",
			"ws_core::event::SemanticEventKind",
		},
		Rationale: "TextFrame (whose isValid applies the UTF-8 DFA) landed as Opcode/DataOpcode Text values gated by Charsetfunctions' strict UTF-8 validation and delivered as the SemanticEventKind Text event; no TextFrame type exists.",
	},
	"migration.org-java-websocket-handshake-clienthandshake": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::handshake::client::ClientHandshake",
		},
		Rationale: "Planned identity landed as declared (the client handshake driver).",
	},
	"migration.org-java-websocket-handshake-clienthandshakebuilder": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::client::ClientRequestDescriptor",
			"ws_core::handshake::client::ClientHandshake",
		},
		Rationale: "The mutable ClientHandshakeBuilder landed as owned immutable values: ClientRequestDescriptor (validated resource/host) consumed by ClientHandshake's deterministic request emission — the builder-to-owned-values collapse the map's known_non_equivalent_cases declares.",
	},
	"migration.org-java-websocket-handshake-handshakebuilder": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::http::JavaHeaders",
		},
		Rationale: "The HandshakeBuilder mutable header-map surface landed as the owned JavaHeaders value (join-and-store multimap with Java's exact casing/duplicate semantics); no builder exists.",
	},
	"migration.org-java-websocket-handshake-handshakeimpl1client": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::client::ClientHandshake",
			"ws_core::handshake::client::ClientHandshakeOutcome",
		},
		Rationale: "The interface/impl split collapsed: HandshakeImpl1Client's concrete request state landed inside ClientHandshake and its outcome vocabulary; no separate impl type exists.",
	},
	"migration.org-java-websocket-handshake-handshakeimpl1server": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::server::ServerHandshake",
			"ws_core::handshake::server::ServerHandshakeOutcome",
		},
		Rationale: "HandshakeImpl1Server's concrete response state landed inside ServerHandshake and its outcome vocabulary; no separate impl type exists.",
	},
	"migration.org-java-websocket-handshake-handshakedata": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::http::JavaHead",
			"ws_core::handshake::http::JavaHeaders",
		},
		Rationale: "The Handshakedata read surface (iterateHttpFields/getFieldValue/getContent) landed as the owned JavaHead (parsed head) and JavaHeaders (field map) values; no interface exists.",
	},
	"migration.org-java-websocket-handshake-handshakedataimpl1": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::http::JavaHeaders",
		},
		Rationale: "HandshakedataImpl1's LinkedHashMap storage semantics (lower-cased un-trimmed keys, duplicate join) landed inside JavaHeaders, whose module doc pins those exact semantics; no impl type exists.",
	},
	"migration.org-java-websocket-handshake-serverhandshake": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::handshake::server::ServerHandshake",
		},
		Rationale: "Planned identity landed as declared (the server handshake driver).",
	},
	"migration.org-java-websocket-handshake-serverhandshakebuilder": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::server::ServerHandshake",
			"ws_core::handshake::server::ServerHandshakeOutcome",
		},
		Rationale: "The ServerHandshakeBuilder mutable response surface landed as ServerHandshake's owned deterministic 101-head emission (no Date/Server banner) and its outcome vocabulary; no builder exists.",
	},
	"migration.org-java-websocket-interfaces-isslchannel": {
		Disposition: dispositionExcluded,
		Symbols:     []string{},
		Rationale:   "The map records no Rust counterpart (EXCLUDED_TLS_WSS). Confirmed against the tree: no ISSLChannel declaration exists anywhere in the Rust workspace.",
	},
	"migration.org-java-websocket-util-base64": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::crypto::encode_base64",
			"ws_core::handshake::crypto::encode_nonce",
		},
		Rationale: "The vendored Base64 utility landed as the private zero-dependency base64 encoders in the handshake crypto module (accept-key digest encoding and the 24-byte nonce key); no public Base64 type exists and no decode surface was ported (Java only encodes).",
	},
	"migration.org-java-websocket-util-base64-outputstream": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::handshake::crypto::encode_base64",
		},
		Rationale: "Base64.OutputStream existed only to serve the vendored encoder's streaming API; the port encodes whole small buffers (20-byte SHA-1 digest, 16-byte nonce) in one call, so no streaming type landed.",
	},
	"migration.org-java-websocket-util-bytebufferutils": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::ConnectionCore",
		},
		Rationale: "ByteBufferUtils (transferByteBuffer/getEmptyByteBuffer) is a ByteBuffer-management shim with no Rust equivalent need: slice/Vec ownership subsumes it. Its remaining behavioral role (bounded wire-buffer accumulation across chunks) lives in ConnectionCore's pending-buffer accounting; no utility type exists.",
	},
	"migration.org-java-websocket-util-charsetfunctions": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::message::Charsetfunctions",
		},
		Rationale: "Planned identity landed as declared (both strict UTF-8 gates).",
	},
	"migration.org-java-websocket-util-namedthreadfactory": {
		Disposition: dispositionExcluded,
		Symbols:     []string{},
		Rationale:   "The map records no Rust counterpart (EXCLUDED_JAVA_NIO_TOPOLOGY). Confirmed against the tree: no NamedThreadFactory declaration exists anywhere in the Rust workspace.",
	},
}

// excludedNameProbes are the Java simple names whose absence the resolver
// confirms for the capability_excluded rows.
var excludedNameProbes = []string{"ISSLChannel", "NamedThreadFactory"}

// plannedSymbolBinding records how one US-006 proof-target production symbol
// (sym.*) landed in the merged tree.
type plannedSymbolBinding struct {
	Disposition string
	Symbols     []string
	Rationale   string
}

// proofTargetSymbolBindings covers every production symbol declared in
// assurance/formal/proof-targets.json. The DAG builder fails if the set
// drifts from the frozen proof-targets document in either direction.
var proofTargetSymbolBindings = map[string]plannedSymbolBinding{
	"sym.framing.decode-frame-header": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::decode_frame_header"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.framing.apply-mask": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::apply_mask"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.framing.encode-frame": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::encode_frame"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.allocation.check-alloc": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::framing::Draft6455::decode_frame_header",
		},
		Rationale: "No Draft trait landed (single-draft port), so Draft::check_alloc has no home; the pre-allocation guard the target names landed as the header-time declared-length gate inside Draft6455::decode_frame_header (1009 at the length site, before any payload allocation — derive.go:424-425). Distinct by design from the reassembly-time cumulative gate check_buffer_limit, which the frozen targets bind separately under fragmentation (review 01a04566 correction 1).",
	},
	"sym.allocation.decode-guarded-allocation": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::decode_frame_header"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.control.decode-length-gate": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::decode_frame_header"},
		Rationale:   "Planned symbol landed as declared (the control extended-length marker rejects at the 2-byte header site inside decode_frame_header).",
	},
	"sym.control.process-frame": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::process_frame"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.handshake.accept-as-server": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::accept_handshake_as_server"},
		Rationale:   "Planned symbol landed as declared; the impl block lives in handshake/server.rs (the acceptance predicate's home), still on the Draft6455 type.",
	},
	"sym.handshake.generate-accept": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::generate_accept_key"},
		Rationale:   "Planned symbol landed as declared; the impl block lives in handshake/crypto.rs, still on the Draft6455 type.",
	},
	"sym.close.close-connection": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::ConnectionCore::handle_command",
			"ws_core::connection::ConnectionCore::process_inbound",
			"ws_core::close::normalize_send_close_code",
		},
		Rationale: "closeConnection's terminal ladder landed across the command/inbound close arms plus the US-009 close-code pure functions; no single close_connection method exists.",
	},
	"sym.close.flush-and-close": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::ConnectionCore::handle_command",
			"ws_testee::io_loop::drive_connection",
		},
		Rationale: "flushAndClose split across the seam: the core emits the governed close write from its command arm and the adapter's bounded pump owns the actual flush before shutdown; no flush_and_close method exists.",
	},
	"sym.connection.close": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::LocalCommand::SendClose",
			"ws_core::connection::ConnectionCore::handle_command",
		},
		Rationale: "WebSocketImpl.close landed as the SendClose command handled by the command arm (Q13/Q14 code routing); no close method exists on the core.",
	},
	"sym.connection.open": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::ConnectionCore::finish_handshake_open",
		},
		Rationale: "WebSocketImpl.open's state transition landed as ConnectionCore::finish_handshake_open — the single declaration that sets ReadyState::Open after an accepted handshake (both roles route through it), stashing post-head remainder bytes under the Q24 cap. The handshake initiation/parser seams do not perform the transition (review 01a04566 correction 2).",
	},
	"sym.connection.eot": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::Input::TransportEof",
			"ws_core::connection::ConnectionCore::handle_eof",
		},
		Rationale: "WebSocketImpl.eot landed as the TransportEof input handled by handle_eof. Disclosed limit (dossier G11): the pre-handshake NotYetConnected EOF arms remain honest Unimplemented refusals.",
	},
	"sym.utf8.string-utf8": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::message::Charsetfunctions::string_utf8"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.utf8.is-valid-utf8": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::message::Charsetfunctions::is_valid_utf8"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.fragmentation.check-buffer-limit": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::check_buffer_limit"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.fragmentation.process-continuation": {
		Disposition: dispositionExact,
		Symbols:     []string{"ws_core::framing::Draft6455::process_frame_continuous"},
		Rationale:   "Planned symbol landed as declared.",
	},
	"sym.adapter.decode-ingress": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_core::connection::ConnectionCore::handle",
		},
		Rationale: "WebSocketImpl.decode's ingress loop landed inside ConnectionCore::handle (TransportBytes arm: incomplete-frame buffering over Draft6455 translate); no decode method exists.",
	},
	"sym.adapter.wrapped-io-error": {
		Disposition: dispositionAbsorbed,
		Symbols: []string{
			"ws_testee::io_loop::LoopOutcome::SocketError",
		},
		Rationale: "The planned ws_adapter::tcp::WrappedIOException landed as the normalized LoopOutcome::SocketError adapter outcome in ws-testee (the planned adapter crate landed as ws-testee); no wrapper exception type exists.",
	},
	"sym.concurrency.connection-owner": {
		Disposition: dispositionExact,
		Symbols: []string{
			"ws_core::connection::WebSocketImpl",
			"ws_driver::ConnectionDriver",
		},
		Rationale: "The single connection owner landed as declared (WebSocketImpl alias over ConnectionCore) with ws_driver::ConnectionDriver as the deterministic owner loop that serializes every observation (US-017).",
	},
}

// evidenceSpec is one digest-pinned in-repo evidence file for the DAG.
type evidenceSpec struct {
	Path    string
	Title   string
	Lineage string
}

// evidenceCatalog: every evidence node of the linkage DAG. All paths are
// in-repo so every digest is reproducible from a checkout.
var evidenceCatalog = map[string]evidenceSpec{
	"evidence.linkage.migration-map": {
		Path:    "evidence/intake/semantic-id-migration-map.json",
		Title:   "US-003 semantic-identity migration map (frozen derived document)",
		Lineage: "javac-semantic Java identities; rust identities planned, resolver-verified by this linkage layer's overlay",
	},
	"evidence.linkage.proof-targets": {
		Path:    "assurance/formal/proof-targets.json",
		Title:   "US-006 formal proof-target plan",
		Lineage: "plan-only: targets and planned symbols; no actual-code formal run exists (dossier G8)",
	},
	"evidence.linkage.us009-wired-baseline": {
		Path:    "rust/ws-oracle-harness/baseline/us009-public-wired-baseline.json",
		Title:   "US-009 wired public corpus baseline",
		Lineage: "reference-model-derived expectations (dossier E2/G2); no live-Java behavioral differential",
	},
	"evidence.linkage.corpus-baseline-batch-c": {
		Path:    "rust/ws-oracle-harness/baseline/borrow-batch-c-public-baseline.json",
		Title:   "Batch-C wired public corpus baseline (74/74)",
		Lineage: "reference-model-derived expectations pending live-oracle confirmation (dossier E1/E2/G2)",
	},
	"evidence.linkage.corpus-transcript-batch-c": {
		Path:    "rust/ws-oracle-harness/baseline/borrow-batch-c-public-transcript.jsonl",
		Title:   "Batch-C public corpus transcript (rerun byte-identical)",
		Lineage: "reference-model-derived expectations pending live-oracle confirmation (dossier E1/E2/G2)",
	},
	"evidence.linkage.public-scenarios": {
		Path:    "corpora/public/scenarios.jsonl",
		Title:   "Public behavior corpus (74 scenarios)",
		Lineage: "every expectation REFERENCE_MODEL_DERIVED_PENDING_ORACLE_CONFIRMATION (dossier E2)",
	},
	"evidence.linkage.handshake-cases": {
		Path:    "corpora/handshake/cases.jsonl",
		Title:   "Handshake corpus (49 cases, LIVE_EXECUTED against the pinned jar)",
		Lineage: "US-005 live Java execution (dossier E3)",
	},
	"evidence.linkage.handshake-exam-raw": {
		Path:    "drafts/us010-us011-handshake-exam/evaluate-raw-honest-runtime.json",
		Title:   "Batch-B handshake exam: raw honest run",
		Lineage: "0/49 solely on the evaluator's jar runtime-binding pin; zero behavioral failures (dossier E4)",
	},
	"evidence.linkage.handshake-exam-neutralized": {
		Path:    "drafts/us010-us011-handshake-exam/evaluate-runtime-neutralized.json",
		Title:   "Batch-B handshake exam: runtime-neutralized rescoring 49/49",
		Lineage: "disclosed mechanical shim over the recorded live transcript (dossier E4)",
	},
	"evidence.linkage.live-handshake-mapping": {
		Path:    "evidence/us005-handshake-live-mapping.json",
		Title:   "US-005 live handshake divergence mapping (16 RFC-reject/Java-accept sites)",
		Lineage: "live-recorded Java behavior; divergences documented here, not yet delta-ledgered (dossier E13/G3)",
	},
	"evidence.linkage.model-check-tlc": {
		Path:    "evidence/formal/us006-model-check-0125/tlc.out",
		Title:   "US-006 TLC run over the abstract lifecycle model",
		Lineage: "PROVED_MODEL_ONLY: abstract model, not actual code (dossier E9)",
	},
	"evidence.linkage.schedule-exploration": {
		Path:    "assurance/concurrency/results.json",
		Title:   "US-017 exhaustive bounded schedule exploration results (79920 schedules)",
		Lineage: "deterministic ws-driver schedule exploration with full-trace replay equality",
	},
	"evidence.linkage.us018-closure-receipt": {
		Path:    "drafts/us018-closure-receipt.json",
		Title:   "US-018 closure receipt (cross-peer exams, adapter-linkage gate, platform legs)",
		Lineage: "owner-attested receipt; 6/6 Java/Rust cross-peer exams against the digest-verified pinned jar",
	},
}

// storyEvidence binds each story node to its verifying evidence nodes.
var storyEvidence = map[string][]string{
	"US-009": {"evidence.linkage.migration-map", "evidence.linkage.us009-wired-baseline"},
	"US-010": {"evidence.linkage.handshake-cases", "evidence.linkage.handshake-exam-raw", "evidence.linkage.handshake-exam-neutralized", "evidence.linkage.live-handshake-mapping", "evidence.linkage.corpus-baseline-batch-c"},
	"US-011": {"evidence.linkage.handshake-cases", "evidence.linkage.handshake-exam-raw", "evidence.linkage.handshake-exam-neutralized", "evidence.linkage.live-handshake-mapping", "evidence.linkage.corpus-baseline-batch-c"},
	"US-012": {"evidence.linkage.public-scenarios", "evidence.linkage.corpus-baseline-batch-c", "evidence.linkage.corpus-transcript-batch-c"},
	"US-013": {"evidence.linkage.public-scenarios", "evidence.linkage.corpus-baseline-batch-c", "evidence.linkage.corpus-transcript-batch-c"},
	"US-014": {"evidence.linkage.public-scenarios", "evidence.linkage.corpus-baseline-batch-c", "evidence.linkage.corpus-transcript-batch-c"},
	"US-015": {"evidence.linkage.public-scenarios", "evidence.linkage.corpus-baseline-batch-c", "evidence.linkage.corpus-transcript-batch-c"},
	"US-016": {"evidence.linkage.public-scenarios", "evidence.linkage.corpus-baseline-batch-c", "evidence.linkage.corpus-transcript-batch-c", "evidence.linkage.model-check-tlc", "evidence.linkage.proof-targets"},
	"US-017": {"evidence.linkage.schedule-exploration"},
	"US-018": {"evidence.linkage.us018-closure-receipt"},
}

// storySymbols adds the driver/testee symbols that no migration row reaches
// (they are port-side architecture, not Java identities) to their stories.
var storySymbols = map[string][]string{
	"US-017": {"ws_driver::ConnectionDriver", "ws_driver::connection_driver", "ws_core::connection::CommandQueue", "ws_core::connection::CommandSender", "ws_core::queue::BoundedQueue"},
	"US-018": {"ws_testee::io_loop::drive_connection", "ws_testee::io_loop::IoBounds", "ws_testee::io_loop::LoopOutcome", "ws_testee::client::run_client_once", "ws_testee::server::run_server_once"},
}

// storyTitles names the story nodes.
var storyTitles = map[string]string{
	"US-009": "ConnectionCore contract and command surface",
	"US-010": "Client opening-handshake slice",
	"US-011": "Server opening-handshake slice",
	"US-012": "Canonical framing, masking, and allocation limits",
	"US-013": "Strict text and binary messages",
	"US-014": "Fragmented-message reassembly with bounded state",
	"US-015": "Ping and pong control behavior",
	"US-016": "Close, EOF, and terminal-state behavior",
	"US-017": "Deterministic owner loop and schedule exploration",
	"US-018": "Blocking TCP adapters and cross-peer integration",
}
