package portplan

// PortSlice is one vertical port slice owned by exactly one child implementation story.
type PortSlice struct {
	ID           string
	ChildStoryID string
	Title        string
	RustModule   string
}

// PortSlices are the AC4 implementation slices. Every in-scope semantic item is assigned to
// exactly one of them, and every one of them is an implementation story in the parent PRD.
var PortSlices = []PortSlice{
	{"slice.connection-core", "US-009", "Safe Rust ConnectionCore contract", "ws_core::connection"},
	{"slice.client-handshake", "US-010", "Client opening-handshake slice", "ws_core::handshake::client"},
	{"slice.server-handshake", "US-011", "Server opening-handshake slice", "ws_core::handshake::server"},
	{"slice.framing", "US-012", "Canonical framing, masking, allocation limits", "ws_core::framing"},
	{"slice.messages", "US-013", "Strict text and binary messages", "ws_core::message"},
	{"slice.fragmentation", "US-014", "Fragment reassembly with bounded state", "ws_core::fragment"},
	{"slice.ping-pong", "US-015", "Ping and pong control behavior", "ws_core::control"},
	{"slice.close-eof", "US-016", "Close, EOF, and terminal state", "ws_core::close"},
	{"slice.concurrency", "US-017", "Bounded concurrent commands through one owner", "ws_core::owner"},
	{"slice.tcp-adapter", "US-018", "Thin blocking TCP client and server adapters", "ws_adapter::tcp"},
}

// sliceAssignment maps each compiler-derived Java binary name in the study surface to its port
// slice. The table is explicit rather than pattern-matched: an unassigned type is a hard failure,
// so a new upstream type can never be silently swept into a slice.
var sliceAssignment = map[string]string{
	// Root connection files.
	"org.java_websocket.WebSocket":         "slice.connection-core",
	"org.java_websocket.WebSocketAdapter":  "slice.connection-core",
	"org.java_websocket.WebSocketImpl":     "slice.connection-core",
	"org.java_websocket.WebSocketListener": "slice.connection-core",

	// Protocol draft strategy seam.
	"org.java_websocket.drafts.Draft":                                "slice.connection-core",
	"org.java_websocket.drafts.Draft_6455":                           "slice.framing",
	"org.java_websocket.drafts.Draft_6455$TranslatedPayloadMetaData": "slice.framing",

	// Enums.
	"org.java_websocket.enums.CloseHandshakeType": "slice.connection-core",
	"org.java_websocket.enums.HandshakeState":     "slice.connection-core",
	"org.java_websocket.enums.ReadyState":         "slice.connection-core",
	"org.java_websocket.enums.Role":               "slice.connection-core",
	"org.java_websocket.enums.Opcode":             "slice.framing",

	// Interfaces.
	"org.java_websocket.interfaces.ISSLChannel": "slice.connection-core",

	// Exceptions, assigned to the slice whose behavior raises them.
	"org.java_websocket.exceptions.IncompleteException":            "slice.framing",
	"org.java_websocket.exceptions.InvalidDataException":           "slice.framing",
	"org.java_websocket.exceptions.InvalidFrameException":          "slice.framing",
	"org.java_websocket.exceptions.LimitExceededException":         "slice.framing",
	"org.java_websocket.exceptions.InvalidEncodingException":       "slice.messages",
	"org.java_websocket.exceptions.IncompleteHandshakeException":   "slice.client-handshake",
	"org.java_websocket.exceptions.InvalidHandshakeException":      "slice.client-handshake",
	"org.java_websocket.exceptions.NotSendableException":           "slice.concurrency",
	"org.java_websocket.exceptions.WebsocketNotConnectedException": "slice.close-eof",
	"org.java_websocket.exceptions.WrappedIOException":             "slice.tcp-adapter",

	// Framing.
	"org.java_websocket.framing.Framedata":       "slice.framing",
	"org.java_websocket.framing.FramedataImpl1":  "slice.framing",
	"org.java_websocket.framing.DataFrame":       "slice.framing",
	"org.java_websocket.framing.ControlFrame":    "slice.framing",
	"org.java_websocket.framing.BinaryFrame":     "slice.messages",
	"org.java_websocket.framing.TextFrame":       "slice.messages",
	"org.java_websocket.framing.ContinuousFrame": "slice.fragmentation",
	"org.java_websocket.framing.PingFrame":       "slice.ping-pong",
	"org.java_websocket.framing.PongFrame":       "slice.ping-pong",
	"org.java_websocket.framing.CloseFrame":      "slice.close-eof",

	// Handshake.
	"org.java_websocket.handshake.Handshakedata":          "slice.client-handshake",
	"org.java_websocket.handshake.HandshakedataImpl1":     "slice.client-handshake",
	"org.java_websocket.handshake.HandshakeBuilder":       "slice.client-handshake",
	"org.java_websocket.handshake.ClientHandshake":        "slice.client-handshake",
	"org.java_websocket.handshake.ClientHandshakeBuilder": "slice.client-handshake",
	"org.java_websocket.handshake.HandshakeImpl1Client":   "slice.client-handshake",
	"org.java_websocket.handshake.ServerHandshake":        "slice.server-handshake",
	"org.java_websocket.handshake.ServerHandshakeBuilder": "slice.server-handshake",
	"org.java_websocket.handshake.HandshakeImpl1Server":   "slice.server-handshake",

	// Util.
	"org.java_websocket.util.Base64":              "slice.client-handshake",
	"org.java_websocket.util.Base64$OutputStream": "slice.client-handshake",
	"org.java_websocket.util.ByteBufferUtils":     "slice.framing",
	"org.java_websocket.util.Charsetfunctions":    "slice.messages",
	"org.java_websocket.util.NamedThreadFactory":  "slice.concurrency",
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
