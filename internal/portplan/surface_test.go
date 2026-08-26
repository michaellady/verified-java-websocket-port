package portplan

import (
	"strings"
	"testing"
)

// AC2: the study surface is exactly the four root connection files plus the drafts, enums,
// exceptions, framing, handshake, interfaces, and util packages.
func TestStudySurfaceRuleSelectsFourRootConnectionFiles(t *testing.T) {
	want := []string{
		"org/java_websocket/WebSocket.java",
		"org/java_websocket/WebSocketAdapter.java",
		"org/java_websocket/WebSocketImpl.java",
		"org/java_websocket/WebSocketListener.java",
	}
	if len(StudySurfaceRootFiles) != 4 {
		t.Fatalf("AC2 names four root connection files, rule has %d", len(StudySurfaceRootFiles))
	}
	for index, path := range want {
		if StudySurfaceRootFiles[index] != path {
			t.Fatalf("root file %d = %q, want %q", index, StudySurfaceRootFiles[index], path)
		}
	}
}

func TestStudySurfaceRuleSelectsNamedPackages(t *testing.T) {
	want := []string{"drafts", "enums", "exceptions", "framing", "handshake", "interfaces", "util"}
	if len(StudySurfacePackages) != len(want) {
		t.Fatalf("rule has %d packages, want %d", len(StudySurfacePackages), len(want))
	}
	for index, name := range want {
		if StudySurfacePackages[index] != name {
			t.Fatalf("package %d = %q, want %q", index, StudySurfacePackages[index], name)
		}
	}
}

func TestSelectStudySurfacePartitionsEveryProductionFile(t *testing.T) {
	all := []string{
		"org/java_websocket/WebSocket.java",
		"org/java_websocket/WebSocketAdapter.java",
		"org/java_websocket/WebSocketImpl.java",
		"org/java_websocket/WebSocketListener.java",
		"org/java_websocket/AbstractWebSocket.java",
		"org/java_websocket/SSLSocketChannel.java",
		"org/java_websocket/drafts/Draft.java",
		"org/java_websocket/util/Base64.java",
		"org/java_websocket/client/WebSocketClient.java",
		"org/java_websocket/server/WebSocketServer.java",
		"org/java_websocket/extensions/IExtension.java",
		"org/java_websocket/extensions/permessage_deflate/PerMessageDeflateExtension.java",
		"org/java_websocket/protocols/Protocol.java",
	}
	selection := SelectStudySurface(all)
	if len(selection.Selected)+len(selection.Excluded) != len(all) {
		t.Fatalf("partition lost files: %d + %d != %d",
			len(selection.Selected), len(selection.Excluded), len(all))
	}
	selected := map[string]bool{}
	for _, path := range selection.Selected {
		selected[path] = true
	}
	mustSelect := []string{
		"org/java_websocket/WebSocket.java",
		"org/java_websocket/WebSocketImpl.java",
		"org/java_websocket/drafts/Draft.java",
		"org/java_websocket/util/Base64.java",
	}
	for _, path := range mustSelect {
		if !selected[path] {
			t.Fatalf("%q must be in the study surface", path)
		}
	}
	mustExclude := []string{
		"org/java_websocket/AbstractWebSocket.java",
		"org/java_websocket/SSLSocketChannel.java",
		"org/java_websocket/client/WebSocketClient.java",
		"org/java_websocket/server/WebSocketServer.java",
		"org/java_websocket/extensions/IExtension.java",
		"org/java_websocket/extensions/permessage_deflate/PerMessageDeflateExtension.java",
		"org/java_websocket/protocols/Protocol.java",
	}
	for _, path := range mustExclude {
		if selected[path] {
			t.Fatalf("%q must be excluded from the study surface", path)
		}
	}
}

// A nested subpackage of an excluded package stays excluded; a nested subpackage of a selected
// package must not be silently swept in without being named.
func TestSelectStudySurfaceExcludesNestedSubpackageOfExcludedPackage(t *testing.T) {
	selection := SelectStudySurface([]string{
		"org/java_websocket/extensions/permessage_deflate/PerMessageDeflateExtension.java",
	})
	if len(selection.Selected) != 0 {
		t.Fatalf("permessage_deflate is RFC 7692 and must never be selected, got %v", selection.Selected)
	}
	if len(selection.Excluded) != 1 {
		t.Fatalf("permessage_deflate must be explicitly excluded, got %v", selection.Excluded)
	}
}

func TestEveryExclusionCarriesANamedReason(t *testing.T) {
	selection := SelectStudySurface([]string{
		"org/java_websocket/AbstractWebSocket.java",
		"org/java_websocket/SSLSocketChannel.java",
		"org/java_websocket/client/WebSocketClient.java",
		"org/java_websocket/server/WebSocketServer.java",
		"org/java_websocket/extensions/permessage_deflate/PerMessageDeflateExtension.java",
		"org/java_websocket/protocols/Protocol.java",
	})
	if len(selection.Excluded) != 6 {
		t.Fatalf("expected 6 exclusions, got %d", len(selection.Excluded))
	}
	for _, path := range selection.Excluded {
		reason := selection.ExclusionReasons[path]
		if strings.TrimSpace(reason) == "" {
			t.Fatalf("AC2 requires every exclusion be named; %q has no reason", path)
		}
	}
}
