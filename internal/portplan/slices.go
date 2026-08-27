package portplan

// PortSlice is one vertical port slice owned by exactly one child implementation story.
type PortSlice struct {
	ID           string
	ChildStoryID string
	Title        string
	RustModule   string
}

// PortSlices are the AC4 implementation slices. Every in-scope semantic item is assigned to
// at least one of them, and every one of them is an implementation story in the parent PRD.
var PortSlices = []PortSlice{
	{"slice.connection-core", "US-009", "Safe Rust ConnectionCore contract", "ws_core::connection"},
	{"slice.client-handshake", "US-010", "Client opening-handshake slice", "ws_core::handshake::client"},
	{"slice.server-handshake", "US-011", "Server opening-handshake slice", "websocket_core::ConnectionCore"},
	{"slice.framing", "US-012", "Canonical framing, masking, allocation limits", "ws_core::framing"},
	{"slice.messages", "US-013", "Strict text and binary messages", "ws_core::message"},
	{"slice.fragmentation", "US-014", "Fragment reassembly with bounded state", "ws_core::fragment"},
	{"slice.ping-pong", "US-015", "Ping and pong control behavior", "ws_core::control"},
	{"slice.close-eof", "US-016", "Close, EOF, and terminal state", "ws_core::close"},
	{"slice.concurrency", "US-017", "Bounded concurrent commands through one owner", "ws_core::owner"},
	{"slice.tcp-adapter", "US-018", "Thin blocking TCP client and server adapters", "ws_adapter::tcp"},
}

// bindingSpec is one (slice, touched behavior) facet of a Java type. A type with a single
// bindingSpec ports wholly within that slice; a slice-crossing type carries one bindingSpec per
// behavioral facet (review B1).
type bindingSpec struct {
	SliceID  string
	Behavior string
}

// sliceAssignment maps each compiler-derived Java binary name in the study surface to the port
// slices that own its behavior. The table is explicit rather than pattern-matched: an unassigned
// type is a hard failure, so a new upstream type can never be silently swept into a slice.
// Slice-crossing types enumerate every behavioral facet the reviewer named; the primary
// (structure-owning) slice is listed first.
var sliceAssignment = map[string][]bindingSpec{
	// --- Root connection files (all four are slice-crossing) ---
	"org.java_websocket.WebSocket": {
		{"slice.connection-core", "connection command surface: readyState observation, attachment, local/remote addresses, hasBufferedData"},
		{"slice.messages", "send(String)/send(byte[])/send(ByteBuffer)/sendFrame message command surface"},
		{"slice.fragmentation", "sendFragmentedFrame(Opcode,ByteBuffer,boolean) continuation command surface (WebSocket.java:130)"},
		{"slice.ping-pong", "sendPing command surface"},
		{"slice.close-eof", "close(code,reason)/close(code)/closeConnection command surface"},
	},
	"org.java_websocket.WebSocketAdapter": {
		{"slice.connection-core", "default no-op listener implementation every callback flows through"},
		{"slice.client-handshake", "default onWebsocketHandshakeReceivedAsClient/onWebsocketHandshakeSentAsClient implementations (WebSocketAdapter.java:59,72)"},
		{"slice.server-handshake", "default onWebsocketHandshakeReceivedAsServer returning HandshakeImpl1Server (WebSocketAdapter.java:53)"},
		{"slice.ping-pong", "onWebsocketPing default automatic-pong reply and onWebsocketPong default"},
	},
	"org.java_websocket.WebSocketImpl": {
		{"slice.connection-core", "connection state machine: ReadyState transitions, open/error event normalization, attachment"},
		{"slice.client-handshake", "startHandshake request emission and client-role decodeHandshake path"},
		{"slice.server-handshake", "server-role decodeHandshake acceptance and 101-response write path"},
		{"slice.framing", "decode() incomplete-frame buffering and the decodeFrames loop over Draft.translateFrame"},
		{"slice.messages", "deliverMessage dispatch of completed text/binary payloads to the listener"},
		{"slice.fragmentation", "continuation delivery ordering through the frame-processing loop"},
		{"slice.ping-pong", "sendPing emission and onWebsocketPing dispatch producing the automatic pong"},
		{"slice.close-eof", "close/closeConnection/flushAndClose/eot terminal-state and close-code handling"},
		{"slice.concurrency", "synchronized send/close regions plus both declared BlockingQueues: outQueue (ported as the bounded owner queue) and inQueue (declared at WebSocketImpl.java:102 but produced/drained only by the excluded NIO server topology; inventoried explicitly, not ported)"},
		{"slice.tcp-adapter", "outQueue drain and onWriteDemand contract consumed by the byte-channel adapter"},
	},
	"org.java_websocket.WebSocketListener": {
		{"slice.connection-core", "callback boundary: onWebsocketOpen/onWebsocketError/onWriteDemand"},
		{"slice.client-handshake", "onWebsocketHandshakeReceivedAsClient/onWebsocketHandshakeSentAsClient validation callbacks"},
		{"slice.server-handshake", "onWebsocketHandshakeReceivedAsServer validation callback"},
		{"slice.messages", "onWebsocketMessage text and binary delivery callbacks"},
		{"slice.ping-pong", "onWebsocketPing/onWebsocketPong dispatch callbacks"},
		{"slice.close-eof", "onWebsocketClose/onWebsocketClosing/onWebsocketCloseInitiated callbacks"},
		{"slice.tcp-adapter", "onWriteDemand queued-write signal and the transport-facing getLocalSocketAddress/getRemoteSocketAddress accessors (WebSocketListener.java:184,191,199)"},
	},

	// --- Protocol draft strategy seam ---
	"org.java_websocket.drafts.Draft": {
		{"slice.connection-core", "protocol strategy seam: copyInstance, reset, role wiring"},
		{"slice.client-handshake", "createHandshake/postProcessHandshakeRequestAsClient/translateHandshake contract"},
		{"slice.server-handshake", "acceptHandshakeAsServer/postProcessHandshakeResponseAsServer contract"},
		{"slice.framing", "createFrames/translateFrame abstract framing contract"},
		{"slice.fragmentation", "continuousFrame(Opcode,ByteBuffer,boolean) and the continuousFrameType state (Draft.java:68,210)"},
		{"slice.messages", "processFrame(WebSocketImpl,Framedata) abstract dispatch of completed text/binary frames (Draft.java:207)"},
		{"slice.ping-pong", "processFrame abstract dispatch of ping/pong control frames (Draft.java:207)"},
		{"slice.close-eof", "processFrame close dispatch plus the getCloseHandshakeType() strategy (Draft.java:207,306)"},
	},
	"org.java_websocket.drafts.Draft_6455": {
		{"slice.framing", "RFC 6455 frame encode/decode: translateSingleFrame, createByteBufferFromFramedata, masking, payload-length encodings"},
		{"slice.client-handshake", "Sec-WebSocket-Key generation, postProcessHandshakeRequestAsClient, acceptHandshakeAsClient accept-derivation check"},
		{"slice.server-handshake", "acceptHandshakeAsServer validation and postProcessHandshakeResponseAsServer accept derivation"},
		{"slice.messages", "processFrameText strict UTF-8 enforcement and processFrameBinary delivery"},
		{"slice.fragmentation", "processFrameContinuousAndNonFin: currentContinuousFrame reassembly state, ordering checks, size accounting"},
		{"slice.ping-pong", "processFramePing/processFramePong dispatch including the automatic pong reply"},
		{"slice.close-eof", "processFrameClosing close-code extraction and validation"},
	},
	"org.java_websocket.drafts.Draft_6455$TranslatedPayloadMetaData": {
		{"slice.framing", "payload-length metadata for a translated frame"},
	},

	// --- Enums ---
	"org.java_websocket.enums.CloseHandshakeType": {
		{"slice.connection-core", "draft close-handshake capability declaration (Draft.getCloseHandshakeType)"},
		{"slice.close-eof", "governs one-way versus two-way closing-handshake behavior"},
	},
	"org.java_websocket.enums.HandshakeState": {
		{"slice.client-handshake", "acceptHandshakeAsClient MATCHED/NOT_MATCHED decision"},
		{"slice.server-handshake", "acceptHandshakeAsServer MATCHED/NOT_MATCHED decision"},
	},
	"org.java_websocket.enums.Opcode":     {{"slice.framing", ""}},
	"org.java_websocket.enums.ReadyState": {{"slice.connection-core", ""}},
	"org.java_websocket.enums.Role":       {{"slice.connection-core", ""}},

	// --- Interfaces ---
	"org.java_websocket.interfaces.ISSLChannel": {
		{"slice.tcp-adapter", "TLS engine accessor context at the adapter seam; capability excluded (EXCLUDED_TLS_WSS), no Rust counterpart"},
	},

	// --- Exceptions, assigned to the slices whose behavior raises them ---
	"org.java_websocket.exceptions.IncompleteException": {{"slice.framing", ""}},
	"org.java_websocket.exceptions.InvalidDataException": {
		{"slice.framing", "checked base carrying the close code for protocol violations found during frame decode"},
		{"slice.messages", "thrown by Charsetfunctions.stringUtf8 on invalid UTF-8 text payloads"},
		{"slice.fragmentation", "thrown on continuation-state violations during reassembly"},
		{"slice.close-eof", "its close code terminates the connection through the closing handshake"},
		{"slice.client-handshake", "declared rejection type of onWebsocketHandshakeReceivedAsClient/onWebsocketHandshakeSentAsClient (WebSocketListener.java:73,81)"},
		{"slice.server-handshake", "declared rejection type of onWebsocketHandshakeReceivedAsServer (WebSocketListener.java:60)"},
	},
	"org.java_websocket.exceptions.InvalidFrameException": {{"slice.framing", ""}},
	"org.java_websocket.exceptions.LimitExceededException": {
		{"slice.framing", "raised when a decoded payload length exceeds the allocation limit"},
		{"slice.fragmentation", "raised when the reassembled message size exceeds the declared maximum"},
	},
	"org.java_websocket.exceptions.InvalidEncodingException":       {{"slice.messages", ""}},
	"org.java_websocket.exceptions.IncompleteHandshakeException":   {{"slice.client-handshake", ""}},
	"org.java_websocket.exceptions.InvalidHandshakeException":      {{"slice.client-handshake", ""}},
	"org.java_websocket.exceptions.NotSendableException":           {{"slice.framing", "raised only from Draft_6455.createFrames when a frame cannot be constructed from the requested payload"}},
	"org.java_websocket.exceptions.WebsocketNotConnectedException": {{"slice.close-eof", ""}},
	"org.java_websocket.exceptions.WrappedIOException":             {{"slice.tcp-adapter", ""}},

	// --- Framing ---
	"org.java_websocket.framing.Framedata":       {{"slice.framing", ""}},
	"org.java_websocket.framing.FramedataImpl1":  {{"slice.framing", ""}},
	"org.java_websocket.framing.DataFrame":       {{"slice.framing", ""}},
	"org.java_websocket.framing.ControlFrame":    {{"slice.framing", ""}},
	"org.java_websocket.framing.BinaryFrame":     {{"slice.messages", ""}},
	"org.java_websocket.framing.TextFrame":       {{"slice.messages", ""}},
	"org.java_websocket.framing.ContinuousFrame": {{"slice.fragmentation", ""}},
	"org.java_websocket.framing.PingFrame":       {{"slice.ping-pong", ""}},
	"org.java_websocket.framing.PongFrame":       {{"slice.ping-pong", ""}},
	"org.java_websocket.framing.CloseFrame":      {{"slice.close-eof", ""}},

	// --- Handshake ---
	"org.java_websocket.handshake.Handshakedata":          {{"slice.client-handshake", ""}},
	"org.java_websocket.handshake.HandshakedataImpl1":     {{"slice.client-handshake", ""}},
	"org.java_websocket.handshake.HandshakeBuilder":       {{"slice.client-handshake", ""}},
	"org.java_websocket.handshake.ClientHandshake":        {{"slice.client-handshake", ""}},
	"org.java_websocket.handshake.ClientHandshakeBuilder": {{"slice.client-handshake", ""}},
	"org.java_websocket.handshake.HandshakeImpl1Client":   {{"slice.client-handshake", ""}},
	"org.java_websocket.handshake.ServerHandshake":        {{"slice.server-handshake", ""}},
	"org.java_websocket.handshake.ServerHandshakeBuilder": {{"slice.server-handshake", ""}},
	"org.java_websocket.handshake.HandshakeImpl1Server":   {{"slice.server-handshake", ""}},

	// --- Util ---
	"org.java_websocket.util.Base64":              {{"slice.client-handshake", ""}},
	"org.java_websocket.util.Base64$OutputStream": {{"slice.client-handshake", ""}},
	"org.java_websocket.util.ByteBufferUtils":     {{"slice.framing", ""}},
	"org.java_websocket.util.Charsetfunctions":    {{"slice.messages", ""}},
	"org.java_websocket.util.NamedThreadFactory": {
		{"slice.concurrency", "thread-naming seam; capability excluded (EXCLUDED_JAVA_NIO_TOPOLOGY): the Rust owner has no interior threads"},
	},
}

// TypeCategories assigns every study-surface type its seam-dossier boundary category by actual
// role (review I2). The table is explicit and total for the study surface; an uncategorized type
// is a hard derivation failure. Categories agree with the dossier narratives: WebSocketImpl,
// Draft_6455, and the Impl1 representations are internal; WebSocket, Draft, Framedata, and
// Handshakedata are the public accessor boundaries; listener types are callback seams.
var TypeCategories = map[string]string{
	"org.java_websocket.WebSocket":         "public_boundaries",
	"org.java_websocket.WebSocketAdapter":  "callbacks",
	"org.java_websocket.WebSocketImpl":     "internal_boundaries",
	"org.java_websocket.WebSocketListener": "callbacks",

	"org.java_websocket.drafts.Draft":                                "public_boundaries",
	"org.java_websocket.drafts.Draft_6455":                           "internal_boundaries",
	"org.java_websocket.drafts.Draft_6455$TranslatedPayloadMetaData": "internal_boundaries",

	"org.java_websocket.enums.CloseHandshakeType": "handshakes",
	"org.java_websocket.enums.HandshakeState":     "handshakes",
	"org.java_websocket.enums.Opcode":             "frames",
	"org.java_websocket.enums.ReadyState":         "internal_boundaries",
	"org.java_websocket.enums.Role":               "internal_boundaries",

	"org.java_websocket.interfaces.ISSLChannel": "adapter_seams",

	"org.java_websocket.exceptions.IncompleteException":            "frames",
	"org.java_websocket.exceptions.IncompleteHandshakeException":   "handshakes",
	"org.java_websocket.exceptions.InvalidDataException":           "frames",
	"org.java_websocket.exceptions.InvalidEncodingException":       "wire_formats",
	"org.java_websocket.exceptions.InvalidFrameException":          "frames",
	"org.java_websocket.exceptions.InvalidHandshakeException":      "handshakes",
	"org.java_websocket.exceptions.LimitExceededException":         "limits",
	"org.java_websocket.exceptions.NotSendableException":           "frames",
	"org.java_websocket.exceptions.WebsocketNotConnectedException": "internal_boundaries",
	"org.java_websocket.exceptions.WrappedIOException":             "adapter_seams",

	"org.java_websocket.framing.Framedata":       "public_boundaries",
	"org.java_websocket.framing.FramedataImpl1":  "internal_boundaries",
	"org.java_websocket.framing.BinaryFrame":     "frames",
	"org.java_websocket.framing.CloseFrame":      "frames",
	"org.java_websocket.framing.ContinuousFrame": "frames",
	"org.java_websocket.framing.ControlFrame":    "frames",
	"org.java_websocket.framing.DataFrame":       "frames",
	"org.java_websocket.framing.PingFrame":       "frames",
	"org.java_websocket.framing.PongFrame":       "frames",
	"org.java_websocket.framing.TextFrame":       "frames",

	"org.java_websocket.handshake.Handshakedata":          "public_boundaries",
	"org.java_websocket.handshake.HandshakedataImpl1":     "internal_boundaries",
	"org.java_websocket.handshake.HandshakeBuilder":       "handshakes",
	"org.java_websocket.handshake.ClientHandshake":        "handshakes",
	"org.java_websocket.handshake.ClientHandshakeBuilder": "handshakes",
	"org.java_websocket.handshake.HandshakeImpl1Client":   "handshakes",
	"org.java_websocket.handshake.ServerHandshake":        "handshakes",
	"org.java_websocket.handshake.ServerHandshakeBuilder": "handshakes",
	"org.java_websocket.handshake.HandshakeImpl1Server":   "handshakes",

	"org.java_websocket.util.Base64":              "handshakes",
	"org.java_websocket.util.Base64$OutputStream": "handshakes",
	"org.java_websocket.util.ByteBufferUtils":     "buffers",
	"org.java_websocket.util.Charsetfunctions":    "wire_formats",
	"org.java_websocket.util.NamedThreadFactory":  "threads",
}

// capabilityExcluded names study-surface types whose Java capability is explicitly out of scope
// for the port. They still get a migration row (they are in-scope semantic items under AC2), but
// their row records the exclusion as a known non-equivalence rather than implying a Rust port.
var capabilityExcluded = map[string]string{
	"org.java_websocket.interfaces.ISSLChannel":  "EXCLUDED_TLS_WSS",
	"org.java_websocket.util.NamedThreadFactory": "EXCLUDED_JAVA_NIO_TOPOLOGY",
}

func sliceByID(id string) (PortSlice, bool) {
	for _, slice := range PortSlices {
		if slice.ID == id {
			return slice, true
		}
	}
	return PortSlice{}, false
}
