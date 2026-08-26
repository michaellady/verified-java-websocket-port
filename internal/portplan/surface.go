// Package portplan freezes the Java-WebSocket intake surface, the semantic identity migration
// map, and the port seams for US-003.
//
// Every count and identity this package reports is derived from a compiler run over the
// digest-pinned Java-WebSocket source tree (see java-semantic-oracle). Nothing here is estimated.
package portplan

import (
	"sort"
	"strings"
)

// ProductionSourcePrefix is the package-relative root of the Java-WebSocket production tree.
const ProductionSourcePrefix = "org/java_websocket/"

// StudySurfaceRootFiles is the AC2 "four root connection files": the connection abstraction, its
// listener and adapter callback seams, and the connection state machine implementation.
var StudySurfaceRootFiles = []string{
	"org/java_websocket/WebSocket.java",
	"org/java_websocket/WebSocketAdapter.java",
	"org/java_websocket/WebSocketImpl.java",
	"org/java_websocket/WebSocketListener.java",
}

// StudySurfacePackages is the AC2 list of wholly-included packages, relative to
// ProductionSourcePrefix. Each is included in full and non-recursively: a nested subpackage is a
// distinct surface and must be named separately rather than swept in.
var StudySurfacePackages = []string{
	"drafts", "enums", "exceptions", "framing", "handshake", "interfaces", "util",
}

// ExclusionReason codes name why a production file is outside the frozen study surface.
const (
	ExclusionRootNotConnectionCore = "ROOT_FILE_NOT_A_CONNECTION_CORE_SEAM"
	ExclusionTLSOutOfScope         = "EXCLUDED_TLS_WSS_SURFACE"
	ExclusionClientTopology        = "EXCLUDED_JAVA_CLIENT_TOPOLOGY"
	ExclusionServerTopology        = "EXCLUDED_JAVA_NIO_SERVER_TOPOLOGY"
	ExclusionExtensionFramework    = "EXCLUDED_EXTENSION_FRAMEWORK_PARITY"
	ExclusionRFC7692               = "EXCLUDED_RFC_7692_PERMESSAGE_DEFLATE"
	ExclusionSubprotocolFramework  = "EXCLUDED_SUBPROTOCOL_FRAMEWORK_PARITY"
	ExclusionNestedSubpackage      = "EXCLUDED_NESTED_SUBPACKAGE_NOT_NAMED_BY_RULE"
)

// Selection is the AC2 partition of the production tree into the frozen study surface and the
// explicitly named exclusions. Every input path lands in exactly one side.
type Selection struct {
	Selected         []string
	Excluded         []string
	ExclusionReasons map[string]string
}

// SelectStudySurface applies the AC2 rule to a production file list. The partition is total: no
// file is silently dropped, and every exclusion carries a named reason.
func SelectStudySurface(paths []string) Selection {
	rootFiles := make(map[string]bool, len(StudySurfaceRootFiles))
	for _, path := range StudySurfaceRootFiles {
		rootFiles[path] = true
	}
	packages := make(map[string]bool, len(StudySurfacePackages))
	for _, name := range StudySurfacePackages {
		packages[name] = true
	}

	selection := Selection{ExclusionReasons: map[string]string{}}
	for _, path := range paths {
		if rootFiles[path] {
			selection.Selected = append(selection.Selected, path)
			continue
		}
		relative := strings.TrimPrefix(path, ProductionSourcePrefix)
		segments := strings.Split(relative, "/")
		switch {
		case len(segments) == 1:
			// A root-package file that the rule did not name.
			selection.Excluded = append(selection.Excluded, path)
			selection.ExclusionReasons[path] = rootExclusionReason(path)
		case len(segments) == 2 && packages[segments[0]]:
			selection.Selected = append(selection.Selected, path)
		default:
			selection.Excluded = append(selection.Excluded, path)
			selection.ExclusionReasons[path] = packageExclusionReason(segments)
		}
	}
	sort.Strings(selection.Selected)
	sort.Strings(selection.Excluded)
	return selection
}

func rootExclusionReason(path string) string {
	name := strings.TrimSuffix(strings.TrimPrefix(path, ProductionSourcePrefix), ".java")
	if strings.HasPrefix(name, "SSLSocketChannel") {
		return ExclusionTLSOutOfScope
	}
	return ExclusionRootNotConnectionCore
}

func packageExclusionReason(segments []string) string {
	if len(segments) == 0 {
		return ExclusionRootNotConnectionCore
	}
	switch segments[0] {
	case "client":
		return ExclusionClientTopology
	case "server":
		return ExclusionServerTopology
	case "protocols":
		return ExclusionSubprotocolFramework
	case "extensions":
		if len(segments) > 2 && segments[1] == "permessage_deflate" {
			return ExclusionRFC7692
		}
		return ExclusionExtensionFramework
	}
	// A nested subpackage under an otherwise-selected package is not swept in by the rule.
	return ExclusionNestedSubpackage
}
