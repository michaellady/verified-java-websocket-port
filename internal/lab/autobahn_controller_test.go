package lab

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func init() {
	if len(os.Args) == 4 && os.Args[1] == "attach" && os.Args[2] == "--sig-proxy=false" && os.Args[3] == "vjwt-relay-0123456789abcdef" {
		if err := writeAttachedFrame(os.Stdout, attachFrameData, []byte("x")); err != nil {
			os.Exit(91)
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
}

func TestReadDockerSaveTarBindsExactConfig(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	configName := strings.TrimPrefix(AutobahnImageConfigDigest, "sha256:") + ".json"
	manifest, err := intake.CanonicalJSON([]dockerSaveManifestRecord{{Config: configName, RepoTags: []string{"pinned"}, Layers: make([]string, AutobahnImageLayerCount)}})
	if err != nil {
		t.Fatal(err)
	}
	archive := dockerTar(t, map[string][]byte{configName: config, "manifest.json": manifest})
	configs, gotManifest, _, err := readDockerSaveTar(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configs[configName], config) || !bytes.Equal(gotManifest, manifest) {
		t.Fatal("saved metadata changed")
	}
	for name, data := range map[string][]byte{"../escape": []byte("x"), "manifest.json": manifest} {
		bad := dockerTar(t, map[string][]byte{name: data})
		if _, _, _, err := readDockerSaveTar(bytes.NewReader(bad)); err == nil {
			t.Fatalf("unsafe tar member %q accepted", name)
		}
	}
}

func TestDockerInspectIdentityRejectsSecurityMutations(t *testing.T) {
	valid := map[string]any{
		"Id": AutobahnImageManifestDigest, "RepoDigests": []string{AutobahnImageReference}, "Architecture": "amd64", "Os": "linux",
		"RootFS":                map[string]any{"Type": "layers", "Layers": make([]string, AutobahnImageLayerCount)},
		"Descriptor":            map[string]any{"mediaType": "application/vnd.docker.distribution.manifest.v2+json", "digest": AutobahnImageManifestDigest, "size": AutobahnImageManifestBytes},
		"IgnoredFutureMetadata": map[string]any{"safe_to_ignore": true},
	}
	encoded, err := intake.CanonicalJSON([]any{valid})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := parseDockerInspectIdentity(encoded)
	if err != nil || validateDockerInspectIdentity(identity) != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	mutations := map[string]func(map[string]any){
		"wrong digest":   func(value map[string]any) { value["Id"] = intake.DigestBytes([]byte("wrong")) },
		"wrong platform": func(value map[string]any) { value["Architecture"] = "arm64" },
		"wrong layers": func(value map[string]any) {
			value["RootFS"] = map[string]any{"Type": "layers", "Layers": []string{"one"}}
		},
		"missing field": func(value map[string]any) { delete(value, "Descriptor") },
		"wrong type":    func(value map[string]any) { value["RepoDigests"] = "not-an-array" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copyValue := cloneJSONMap(t, valid)
			mutate(copyValue)
			raw, err := intake.CanonicalJSON([]any{copyValue})
			if err != nil {
				t.Fatal(err)
			}
			parsed, parseErr := parseDockerInspectIdentity(raw)
			if parseErr == nil && validateDockerInspectIdentity(parsed) == nil {
				t.Fatal("security mutation accepted")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"duplicate security key": []byte(`[{"Id":"` + AutobahnImageManifestDigest + `","Id":"` + AutobahnImageManifestDigest + `"}]`),
		"trailing JSON":          append(append([]byte(nil), encoded...), []byte(` {}`)...),
		"multiple records":       []byte(`[{},{}]`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDockerInspectIdentity(raw); err == nil {
				t.Fatal("malformed inspect output accepted")
			}
		})
	}
}

func TestDockerNetworkIdentityAndFailureCleanup(t *testing.T) {
	name := "vjwt-autobahn-fixed"
	valid := map[string]any{
		"Name": name, "Driver": "bridge", "Scope": "local", "Internal": true, "Attachable": false, "Ingress": false,
		"IPAM":                  map[string]any{"Config": []any{map[string]any{"Subnet": autobahnNetworkSubnet, "Gateway": autobahnNetworkGateway}}},
		"IgnoredFutureMetadata": "ok",
	}
	raw, err := intake.CanonicalJSON([]any{valid})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := parseDockerNetworkInspect(raw)
	if err != nil || validateDockerNetworkInspect(identity, name) != nil {
		t.Fatalf("valid network rejected: %v", err)
	}
	mutations := map[string]func(map[string]any){
		"missing":     func(value map[string]any) { delete(value, "Internal") },
		"wrong type":  func(value map[string]any) { value["Internal"] = "true" },
		"external":    func(value map[string]any) { value["Internal"] = false },
		"attachable":  func(value map[string]any) { value["Attachable"] = true },
		"host driver": func(value map[string]any) { value["Driver"] = "host" },
		"wrong subnet": func(value map[string]any) {
			value["IPAM"] = map[string]any{"Config": []any{map[string]any{"Subnet": "172.30.243.0/24", "Gateway": autobahnNetworkGateway}}}
		},
		"missing gateway": func(value map[string]any) {
			value["IPAM"] = map[string]any{"Config": []any{map[string]any{"Subnet": autobahnNetworkSubnet}}}
		},
		"multiple subnets": func(value map[string]any) {
			value["IPAM"] = map[string]any{"Config": []any{
				map[string]any{"Subnet": autobahnNetworkSubnet, "Gateway": autobahnNetworkGateway},
				map[string]any{"Subnet": "172.30.243.0/24", "Gateway": "172.30.243.1"},
			}}
		},
	}
	for mutation, mutate := range mutations {
		t.Run(mutation, func(t *testing.T) {
			value := cloneJSONMap(t, valid)
			mutate(value)
			data, err := intake.CanonicalJSON([]any{value})
			if err != nil {
				t.Fatal(err)
			}
			parsed, parseErr := parseDockerNetworkInspect(data)
			if parseErr == nil && validateDockerNetworkInspect(parsed, name) == nil {
				t.Fatal("unsafe network identity accepted")
			}
		})
	}
	if _, err := parseDockerNetworkInspect([]byte(`[{"Name":"x","Name":"x"}]`)); err == nil {
		t.Fatal("duplicate security key accepted")
	}

	var removed bool
	fake := dockerController{run: func(_ context.Context, arguments ...string) ([]byte, error) {
		switch {
		case len(arguments) >= 2 && arguments[0] == "network" && arguments[1] == "create":
			return []byte("created\n"), nil
		case len(arguments) >= 2 && arguments[0] == "network" && arguments[1] == "inspect":
			return []byte(`[{"Name":7}]`), nil
		case len(arguments) >= 2 && arguments[0] == "network" && arguments[1] == "rm":
			removed = true
			return []byte("removed\n"), nil
		default:
			t.Fatalf("unexpected fake Docker call: %v", arguments)
			return nil, nil
		}
	}}
	if _, _, _, err := prepareAutobahnNetwork(context.Background(), fake, AutobahnRelayReceipt{}); err == nil {
		t.Fatal("post-create identity error accepted")
	}
	if !removed {
		t.Fatal("post-create failure did not remove internal network")
	}
}

func TestLoopbackPortBindingRejectsExposureAndAmbiguity(t *testing.T) {
	valid := []byte(`{"9011/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]}`)
	if port, err := parseLoopbackPortBinding(valid, "9011/tcp"); err != nil || port != 49152 {
		t.Fatalf("valid loopback binding rejected: %d %v", port, err)
	}
	for name, raw := range map[string][]byte{
		"wildcard":        []byte(`{"9011/tcp":[{"HostIp":"0.0.0.0","HostPort":"49152"}]}`),
		"ipv6 wildcard":   []byte(`{"9011/tcp":[{"HostIp":"::","HostPort":"49152"}]}`),
		"extra binding":   []byte(`{"9011/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"},{"HostIp":"::1","HostPort":"49152"}]}`),
		"extra port":      []byte(`{"9011/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}],"9010/tcp":null}`),
		"zero port":       []byte(`{"9011/tcp":[{"HostIp":"127.0.0.1","HostPort":"0"}]}`),
		"noncanonical":    []byte(`{"9011/tcp":[{"HostIp":"127.0.0.1","HostPort":"049152"}]}`),
		"unknown field":   []byte(`{"9011/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152","HostMode":"unsafe"}]}`),
		"duplicate field": []byte(`{"9011/tcp":[{"HostIp":"127.0.0.1","HostIp":"127.0.0.1","HostPort":"49152"}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLoopbackPortBinding(raw, "9011/tcp"); err == nil {
				t.Fatal("unsafe resolved port binding accepted")
			}
		})
	}
}

func TestRelayContainerIdentityRejectsAttachSecurityMutations(t *testing.T) {
	const name = "vjwt-relay-0123456789abcdef"
	const network = "vjwt-autobahn-0123456789abcdef"
	const binary = "/private/tmp/exact-relay"
	const configMount = "/private/tmp/empty-config"
	const reportsMount = "/private/tmp/empty-reports"
	valid := map[string]any{
		"Name": "/" + name, "Image": AutobahnImageManifestDigest, "Path": "/autobahn-relay", "Args": []any{},
		"Config": map[string]any{
			"OpenStdin": true, "Tty": false, "User": "65532:65532", "Entrypoint": []any{"/autobahn-relay"},
			"Env":    []any{"PATH=/usr/bin", "HOME=/nonexistent", "AUTOBAHN_RELAY_ROLE=listen", "AUTOBAHN_RELAY_TEST_PEER=" + autobahnFuzzingClientAddress},
			"Labels": map[string]any{"org.verified-java-websocket.scope": "us002-relay", "org.verified-java-websocket.role": "listen"},
		},
		"HostConfig": map[string]any{
			"NetworkMode": network, "ReadonlyRootfs": true, "Privileged": false, "CapDrop": []any{"ALL"},
			"SecurityOpt": []any{"no-new-privileges"}, "PortBindings": map[string]any{}, "PidsLimit": 16,
			"Memory": 64 << 20, "NanoCpus": 1_000_000_000,
		},
		"NetworkSettings": map[string]any{"Ports": map[string]any{}, "Networks": map[string]any{network: map[string]any{"IPAddress": autobahnRelayAddress}}},
		"Mounts": []any{
			map[string]any{"Type": "bind", "Source": binary, "Destination": "/autobahn-relay", "RW": false},
			map[string]any{"Type": "bind", "Source": configMount, "Destination": "/config", "RW": false},
			map[string]any{"Type": "bind", "Source": reportsMount, "Destination": "/reports", "RW": false},
		},
		"IgnoredFutureMetadata": map[string]any{"safe": true},
	}
	encode := func(value map[string]any) []byte {
		raw, err := intake.CanonicalJSON([]any{value})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if err := validateRelayContainerInspect(encode(valid), name, network, "listen", autobahnFuzzingClientAddress, binary, configMount, reportsMount); err != nil {
		t.Fatalf("valid attach identity rejected: %v", err)
	}
	mutations := map[string]func(map[string]any){
		"wrong image":          func(value map[string]any) { value["Image"] = AutobahnImageConfigDigest },
		"tty":                  func(value map[string]any) { value["Config"].(map[string]any)["Tty"] = true },
		"closed stdin":         func(value map[string]any) { value["Config"].(map[string]any)["OpenStdin"] = false },
		"arbitrary entrypoint": func(value map[string]any) { value["Path"] = "/bin/sh" },
		"published port": func(value map[string]any) {
			value["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{"9010/tcp": []any{map[string]any{"HostIp": "127.0.0.1", "HostPort": "49152"}}}
		},
		"wildcard resolved port": func(value map[string]any) {
			value["NetworkSettings"].(map[string]any)["Ports"] = map[string]any{"9010/tcp": []any{map[string]any{"HostIp": "0.0.0.0", "HostPort": "49152"}}}
		},
		"wrong address": func(value map[string]any) {
			value["NetworkSettings"].(map[string]any)["Networks"] = map[string]any{network: map[string]any{"IPAddress": autobahnFuzzingClientAddress}}
		},
		"writable mount": func(value map[string]any) { value["Mounts"].([]any)[0].(map[string]any)["RW"] = true },
		"wrong peer": func(value map[string]any) {
			value["Config"].(map[string]any)["Env"] = []any{"HOME=/nonexistent", "AUTOBAHN_RELAY_ROLE=listen", "AUTOBAHN_RELAY_TEST_PEER=" + autobahnFuzzingServerAddress}
		},
		"privileged": func(value map[string]any) { value["HostConfig"].(map[string]any)["Privileged"] = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := cloneJSONMap(t, valid)
			mutate(value)
			if err := validateRelayContainerInspect(encode(value), "vjwt-relay-0123456789abcdef", network, "listen", autobahnFuzzingClientAddress, binary, configMount, reportsMount); err == nil {
				t.Fatal("unsafe attach container identity accepted")
			}
		})
	}
	if err := validateRelayContainerInspect([]byte(`[{"Name":"/x","Name":"/x"}]`), name, network, "listen", autobahnFuzzingClientAddress, binary, configMount, reportsMount); err == nil {
		t.Fatal("duplicate security key accepted")
	}
}

func TestAttachedFrameCodecRejectsMalformedSequences(t *testing.T) {
	encoded, err := encodeAttachedBytes([]byte("independent-half-close"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAttachedBytes(encoded)
	if err != nil || string(decoded) != "independent-half-close" {
		t.Fatalf("valid attached frames changed: %q %v", decoded, err)
	}
	frame := func(frameType byte, length uint32, payload []byte) []byte {
		value := make([]byte, attachFrameHeader+len(payload))
		value[0] = frameType
		binary.BigEndian.PutUint32(value[1:], length)
		copy(value[attachFrameHeader:], payload)
		return value
	}
	data := frame(attachFrameData, 1, []byte("x"))
	end := frame(attachFrameEnd, 0, nil)
	for name, value := range map[string][]byte{
		"missing end":    data,
		"truncated head": {attachFrameData, 0},
		"truncated data": frame(attachFrameData, 2, []byte("x")),
		"unknown":        frame(9, 0, nil),
		"zero data":      frame(attachFrameData, 0, nil),
		"oversize data":  frame(attachFrameData, attachMaximumPayload+1, nil),
		"end payload":    frame(attachFrameEnd, 1, []byte("x")),
		"duplicate end":  append(append([]byte(nil), end...), end...),
		"data after end": append(append([]byte(nil), end...), data...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAttachedBytes(value); err == nil {
				t.Fatal("malformed attached frame sequence accepted")
			}
		})
	}
}

func TestReadAutobahnReportsReconcilesExactTerminalResults(t *testing.T) {
	registry, selection := smallAutobahnSelection(t)
	directory := t.TempDir()
	index := make(map[string]map[string]autobahnReportSummary)
	cases := make(map[string]autobahnReportSummary)
	for _, caseID := range selection.SelectedCaseIDs {
		filename := autobahnReportFilename(AutobahnEndpointAgent, caseID)
		summary := autobahnReportSummary{Behavior: "OK", BehaviorClose: "OK", RemoteCloseCode: json.RawMessage("1000"), Duration: json.RawMessage("1"), ReportFile: filename}
		cases[caseID] = summary
		detail := map[string]any{"id": caseID, "agent": AutobahnEndpointAgent, "behavior": "OK", "received": "exact"}
		writeCanonicalTestFile(t, filepath.Join(directory, filename), detail)
	}
	index[AutobahnEndpointAgent] = cases
	writeCanonicalTestFile(t, filepath.Join(directory, "index.json"), index)
	results, digest, err := ReadAutobahnReports(directory, AutobahnEndpointAgent, registry, selection, "client")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(selection.SelectedCaseIDs) || !isDigest(digest) {
		t.Fatalf("unexpected normalized result: %d %s", len(results), digest)
	}
	index[AutobahnEndpointAgent][selection.SelectedCaseIDs[0]] = autobahnReportSummary{Behavior: "SKIPPED", BehaviorClose: "OK", RemoteCloseCode: json.RawMessage("1000"), Duration: json.RawMessage("1"), ReportFile: autobahnReportFilename(AutobahnEndpointAgent, selection.SelectedCaseIDs[0])}
	writeCanonicalReplace(t, filepath.Join(directory, "index.json"), index)
	if _, _, err := ReadAutobahnReports(directory, AutobahnEndpointAgent, registry, selection, "client"); err == nil {
		t.Fatal("nonterminal result accepted")
	}
}

func TestAutobahnDockerArgumentsAreClosed(t *testing.T) {
	runner := exactRunnerTestReceipt("/private/tmp/autobahn-runner")
	arguments := autobahnDockerRunArguments("fixed-network", "/private/tmp/config", "fuzzingclient", "vjwt-fuzzclient-0123456789abcdef", strings.Repeat("a", 64), runner)
	joined := strings.Join(arguments, " ")
	for _, required := range []string{"--detach", "--interactive", "--pull=never", "--network fixed-network", "--ip " + autobahnFuzzingClientAddress, "/reports:rw,noexec,nosuid,nodev,size=256m,mode=0700", "dst=/autobahn-runner,readonly", "AUTOBAHN_RUNNER_ROLE=fuzzingclient", "--entrypoint /autobahn-runner", AutobahnImageReference} {
		if !strings.Contains(joined, required) {
			t.Fatalf("fixed argument missing: %s", required)
		}
	}
	for _, forbidden := range []string{"--network host", "--privileged", "--add-host", "0.0.0.0:", "--publish", "dst=/reports"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("forbidden argument present: %s", forbidden)
		}
	}
}

func TestRunnerReadinessRequiresExactChildAndServerMarkersBeforeUse(t *testing.T) {
	container := autobahnRunnerContainer{
		name: "vjwt-fuzzserver-0123456789abcdef", role: "fuzzingserver",
		configDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	ready := "RUNNER_READY role=fuzzingserver config=" + container.configDigest + " wstest=" + AutobahnWSTestDigest + " interpreter=" + AutobahnPyPyDigest
	var calls []string
	docker := dockerController{run: func(_ context.Context, arguments ...string) ([]byte, error) {
		calls = append(calls, strings.Join(arguments, " "))
		if arguments[0] == "logs" {
			if len(calls) == 1 {
				return []byte(ready + "\n"), nil
			}
			return []byte(ready + "\nAutobahn WebSocket 25.10.1/0.10.9 Fuzzing Server (Port 9001)\nOk, will run 1 test cases for any clients connecting\n"), nil
		}
		if arguments[0] == "inspect" {
			return []byte("true\n"), nil
		}
		return nil, errors.New("unexpected operation")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitAutobahnRunnerReady(ctx, docker, container); err != nil {
		t.Fatal(err)
	}
	if len(calls) < 3 || !strings.HasPrefix(calls[len(calls)-1], "inspect ") {
		t.Fatalf("runner was inspected before exact readiness: %v", calls)
	}

	cancelled, stop := context.WithCancel(context.Background())
	stop()
	docker.run = func(_ context.Context, _ ...string) ([]byte, error) { return []byte(ready + "\n"), nil }
	if err := waitAutobahnRunnerReady(cancelled, docker, container); err == nil {
		t.Fatal("accepted runner without exact accepted server readiness marker")
	}
}

func TestRunnerContainerInspectRejectsIdentityIsolationAndMountDrift(t *testing.T) {
	container := autobahnRunnerContainer{
		name: "vjwt-fuzzclient-0123456789abcdef", role: "fuzzingclient", token: strings.Repeat("a", 64),
		configDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	configPath, binaryPath, network := "/private/tmp/config", "/private/tmp/runner", "fixed-network"
	valid := validRunnerInspectFixture(container, network, configPath, binaryPath)
	encoded, err := json.Marshal([]any{valid})
	if err != nil || validateAutobahnRunnerContainerInspect(encoded, container, network, configPath, binaryPath) != nil {
		t.Fatalf("valid runner inspect rejected: %v", err)
	}
	mutations := map[string]func(map[string]any){
		"wrong image": func(value map[string]any) { value["Image"] = AutobahnImageConfigDigest },
		"wildcard port": func(value map[string]any) {
			value["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{"9001/tcp": []any{map[string]any{"HostIp": "0.0.0.0", "HostPort": "1"}}}
		},
		"wrong address": func(value map[string]any) {
			value["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)[network].(map[string]any)["IPAddress"] = autobahnFuzzingServerAddress
		},
		"extra environment": func(value map[string]any) {
			config := value["Config"].(map[string]any)
			config["Env"] = append(config["Env"].([]string), "SECRET=value")
		},
		"writable binary": func(value map[string]any) { value["Mounts"].([]any)[1].(map[string]any)["RW"] = true },
		"anonymous volume": func(value map[string]any) {
			value["Mounts"] = append(value["Mounts"].([]any), map[string]any{"Type": "volume", "Source": "anonymous", "Destination": "/data", "RW": true})
		},
		"oversized reports": func(value map[string]any) {
			value["HostConfig"].(map[string]any)["Tmpfs"].(map[string]any)["/reports"] = "rw,size=1g"
		},
		"missing reports tmpfs": func(value map[string]any) {
			delete(value["HostConfig"].(map[string]any)["Tmpfs"].(map[string]any), "/reports")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := validRunnerInspectFixture(container, network, configPath, binaryPath)
			mutate(fixture)
			raw, err := json.Marshal([]any{fixture})
			if err != nil {
				t.Fatal(err)
			}
			assertFinding(t, validateAutobahnRunnerContainerInspect(raw, container, network, configPath, binaryPath), "AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH")
		})
	}
}

func TestRetainedRunnerInspectAcceptsDockerResolvedEnvironmentOrder(t *testing.T) {
	container := autobahnRunnerContainer{
		name: "vjwt-fuzzclient-0123456789abcdef", role: "fuzzingclient", token: strings.Repeat("a", 64),
		configDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	configPath, binaryPath, network := "/private/tmp/config", "/private/tmp/runner", "fixed-network"
	fixture := validRunnerInspectFixture(container, network, configPath, binaryPath)
	fixture["Config"].(map[string]any)["Env"] = []string{
		"AUTOBAHN_RUNNER_ROLE=" + container.role, "AUTOBAHN_RUNNER_TOKEN=" + container.token,
		"PATH=/opt/pypy/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PYPY_VERSION=7.3.20",
		"DEBIAN_FRONTEND=noninteractive", "NODE_PATH=/usr/local/lib/node_modules/",
	}
	raw, err := json.Marshal([]any{fixture})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAutobahnRunnerContainerInspect(raw, container, network, configPath, binaryPath); err != nil {
		t.Fatalf("retained Docker-resolved runner identity rejected: %v", err)
	}
}

func TestRetainedRunnerInspectAcceptsDockerResolvedTmpfsMountRepresentation(t *testing.T) {
	container := autobahnRunnerContainer{
		name: "vjwt-fuzzclient-0123456789abcdef", role: "fuzzingclient", token: strings.Repeat("a", 64),
		configDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	configPath, binaryPath, network := "/private/tmp/config", "/private/tmp/runner", "fixed-network"
	fixture := validRunnerInspectFixture(container, network, configPath, binaryPath)
	fixture["Mounts"] = fixture["Mounts"].([]any)[:2]
	raw, err := json.Marshal([]any{fixture})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAutobahnRunnerContainerInspect(raw, container, network, configPath, binaryPath); err != nil {
		t.Fatalf("retained Docker-resolved tmpfs representation rejected: %v", err)
	}
}

func validRunnerInspectFixture(container autobahnRunnerContainer, network, configPath, binaryPath string) map[string]any {
	environment := []string{
		"PATH=/opt/pypy/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PYPY_VERSION=7.3.20",
		"DEBIAN_FRONTEND=noninteractive", "NODE_PATH=/usr/local/lib/node_modules/", "AUTOBAHN_RUNNER_ROLE=" + container.role, "AUTOBAHN_RUNNER_TOKEN=" + container.token,
	}
	return map[string]any{
		"Name": "/" + container.name, "Image": AutobahnImageManifestDigest, "Path": "/autobahn-runner", "Args": []string{},
		"Config":          map[string]any{"OpenStdin": true, "Tty": false, "User": "", "Entrypoint": []string{"/autobahn-runner"}, "Env": environment, "Labels": map[string]string{"org.verified-java-websocket.scope": "us002-autobahn", "org.verified-java-websocket.role": container.role}},
		"HostConfig":      map[string]any{"NetworkMode": network, "ReadonlyRootfs": true, "Privileged": false, "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges"}, "PortBindings": map[string]any{}, "Tmpfs": map[string]any{"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777", "/reports": "rw,noexec,nosuid,nodev,size=256m,mode=0700"}, "PidsLimit": int64(128), "Memory": int64(1 << 30), "NanoCpus": int64(2_000_000_000)},
		"NetworkSettings": map[string]any{"Ports": map[string]any{"9001/tcp": nil}, "Networks": map[string]any{network: map[string]any{"IPAddress": autobahnFuzzingClientAddress}}},
		"Mounts": []any{
			map[string]any{"Type": "bind", "Source": configPath, "Destination": "/config", "RW": false},
			map[string]any{"Type": "bind", "Source": binaryPath, "Destination": "/autobahn-runner", "RW": false},
		},
	}
}

func TestLiveTmpfsReportsCopyBeforeAuthenticatedRelease(t *testing.T) {
	var order []string
	digest, err := copyThenReleaseAutobahnReports(func() (string, error) {
		order = append(order, "copy-live-tmpfs")
		return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
	}, func() error {
		order = append(order, "authenticated-release")
		return nil
	})
	if err != nil || !isDigest(digest) || !equalStrings(order, []string{"copy-live-tmpfs", "authenticated-release"}) {
		t.Fatalf("digest=%s order=%v err=%v", digest, order, err)
	}
	order = nil
	_, err = copyThenReleaseAutobahnReports(func() (string, error) {
		order = append(order, "copy-live-tmpfs")
		return "", errors.New("hostile copy denied")
	}, func() error {
		order = append(order, "authenticated-release")
		return nil
	})
	if err == nil || !equalStrings(order, []string{"copy-live-tmpfs"}) {
		t.Fatalf("release ran after failed copy: order=%v err=%v", order, err)
	}
}

func TestCancelledAttachedRelayClosesLoopbackBeforeWaitingForInput(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, attachErr := runAttachedRelayTCP(ctx, dockerController{path: os.Args[0]}, "vjwt-relay-0123456789abcdef", server)
		done <- attachErr
	}()
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	marker := make([]byte, 1)
	if _, err := io.ReadFull(client, marker); err != nil || string(marker) != "x" {
		t.Fatalf("fake attach did not start: marker=%q err=%v", marker, err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled attach unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		_ = client.Close()
		<-done
		t.Fatal("cancelled attach waited on loopback input beyond its cleanup bound")
	}
}

func exactRunnerTestReceipt(path string) AutobahnRunnerReceipt {
	return AutobahnRunnerReceipt{
		Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", Qualification: "QUALIFIED_NOT_PROMOTED",
		Source: AutobahnArtifactBinding{Digest: AutobahnRunnerSourceDigest}, Binary: AutobahnArtifactBinding{Path: path, Digest: AutobahnRunnerBinaryDigest, Bytes: 1, Links: 1},
		GoExecutable: AutobahnArtifactBinding{Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		GoVersion:    AutobahnRelayGoVersion, GoRootDigest: AutobahnRelayGoRootDigest, WSTestPath: AutobahnWSTestPath,
		WSTestDigest: AutobahnWSTestDigest, InterpreterPath: AutobahnPyPyPath, InterpreterDigest: AutobahnPyPyDigest,
		RepeatableBuild: true, LinuxAMD64StaticELF: true, SourceUnchanged: true, ToolchainUnchanged: true,
	}
}

func TestCopiedAutobahnReportsRejectHostileEntries(t *testing.T) {
	const caseID = "1.1.1"
	jsonName := autobahnReportFilename(AutobahnEndpointAgent, caseID)
	htmlName := strings.TrimSuffix(jsonName, ".json") + ".html"
	writeExact := func(t *testing.T, directory string) {
		t.Helper()
		for _, name := range []string{"index.json", "index.html", jsonName, htmlName} {
			if err := os.WriteFile(filepath.Join(directory, name), []byte("exact:"+name), 0o400); err != nil {
				t.Fatal(err)
			}
		}
	}
	directory := t.TempDir()
	writeExact(t, directory)
	if digest, err := validateCopiedAutobahnReports(directory, caseID); err != nil || !isDigest(digest) {
		t.Fatalf("exact extracted set rejected: %s %v", digest, err)
	}
	for name, mutate := range map[string]func(*testing.T, string){
		"extra": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "extra"), []byte("x"), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, htmlName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(directory, "index.html"), filepath.Join(directory, htmlName)); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, htmlName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(directory, "index.html"), filepath.Join(directory, htmlName)); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, htmlName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(directory, htmlName), 0o500); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			writeExact(t, directory)
			mutate(t, directory)
			if _, err := validateCopiedAutobahnReports(directory, caseID); err == nil {
				t.Fatal("hostile copied report entry accepted")
			}
		})
	}
}

func TestAuthenticatedReportArchiveReplacesEmptyDockerTmpfsCopy(t *testing.T) {
	const caseID = "1.1.1"
	jsonName := autobahnReportFilename(AutobahnEndpointAgent, caseID)
	htmlName := strings.TrimSuffix(jsonName, ".json") + ".html"
	want := map[string][]byte{
		"index.json": []byte("index-json"), "index.html": []byte("index-html"),
		jsonName: []byte("case-json"), htmlName: []byte("case-html"),
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, name := range []string{"index.html", "index.json", htmlName, jsonName} {
		data := want[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o400, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	digest, err := extractAutobahnReportArchive(&archive, directory, caseID)
	if err != nil || !isDigest(digest) {
		t.Fatalf("authenticated tmpfs archive rejected: digest=%s err=%v", digest, err)
	}
	if archive.Len() != 0 {
		t.Fatalf("authenticated report archive left %d unread bytes", archive.Len())
	}
	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("extracted %q=%q err=%v", name, got, err)
		}
	}
}

func TestAuthenticatedReportArchiveRejectsHostileMembers(t *testing.T) {
	const caseID = "1.1.1"
	for name, header := range map[string]tar.Header{
		"path escape": {Name: "../index.json", Mode: 0o400, Size: 1, Typeflag: tar.TypeReg},
		"link":        {Name: "index.json", Linkname: "target", Typeflag: tar.TypeSymlink},
		"oversize":    {Name: "index.json", Mode: 0o400, Size: (64 << 20) + 1, Typeflag: tar.TypeReg},
	} {
		t.Run(name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			if err := writer.WriteHeader(&header); err != nil {
				t.Fatal(err)
			}
			if header.Size == 1 {
				_, _ = writer.Write([]byte("x"))
			}
			_ = writer.Close()
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := extractAutobahnReportArchive(&archive, directory, caseID); err == nil {
				t.Fatal("hostile archive member accepted")
			}
		})
	}
}

func TestClientEndpointFailurePreservesRelayDiagnostic(t *testing.T) {
	detail := clientEndpointFailureDetail(
		[]byte("ENDPOINT_DENIED did not connect"), errors.New("exit status 2"),
		finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay.attach", "RELAY_DENIED dial-timeout"),
		[]byte("RUNNER_READY role=fuzzingserver"),
	)
	for _, required := range []string{"AUTOBAHN_RELAY_ATTACH_FAILED", "RELAY_DENIED dial-timeout", "ENDPOINT_DENIED did not connect", "RUNNER_READY role=fuzzingserver"} {
		if !strings.Contains(detail, required) {
			t.Fatalf("client failure detail discarded %q: %s", required, detail)
		}
	}
}

func TestAutobahnControllerPreflightE2E(t *testing.T) {
	source := os.Getenv("AUTOBAHN_E2E_SOURCE")
	jdk := os.Getenv("AUTOBAHN_E2E_JDK_HOME")
	runtime := os.Getenv("AUTOBAHN_E2E_RUNTIME")
	closure := os.Getenv("AUTOBAHN_E2E_CLOSURE")
	archive := os.Getenv("AUTOBAHN_E2E_ARCHIVE")
	relaySource := os.Getenv("AUTOBAHN_RELAY_E2E_SOURCE")
	runnerSource := os.Getenv("AUTOBAHN_RUNNER_E2E_SOURCE")
	goRoot := os.Getenv("AUTOBAHN_RELAY_E2E_GOROOT")
	if source == "" || jdk == "" || runtime == "" || closure == "" || archive == "" || relaySource == "" || runnerSource == "" || goRoot == "" {
		t.Skip("exact local Autobahn E2E fixtures are not configured")
	}
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	work = filepath.Join(work, "endpoint")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	endpoint, err := BuildAutobahnEndpoint(ctx, AutobahnEndpointBuildConfig{SourcePath: source, JDKHome: jdk, RuntimePath: runtime, ClosureDirectory: closure, WorkDirectory: work})
	if err != nil {
		t.Fatal(err)
	}
	if !endpoint.RuntimeByteCopy || !endpoint.RuntimeSourceUnchanged || !endpoint.SelfTestPassed || endpoint.Support.Digest != AutobahnSLF4JAPIDigest {
		t.Fatalf("endpoint gates incomplete: %+v", endpoint)
	}
	relay, err := BuildAutobahnRelay(ctx, AutobahnRelayBuildConfig{SourcePath: relaySource, GoRoot: goRoot, WorkDirectory: filepath.Join(work, "relay")})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := BuildAutobahnRunner(ctx, AutobahnRunnerBuildConfig{SourcePath: runnerSource, GoRoot: goRoot, WorkDirectory: filepath.Join(work, "runner")})
	if err != nil {
		t.Fatal(err)
	}
	docker, cli, err := newDockerController()
	if err != nil {
		t.Fatal(err)
	}
	image, err := verifyAutobahnImage(ctx, docker, cli)
	if err != nil {
		t.Fatal(err)
	}
	if image.ConfigDigest != AutobahnImageConfigDigest || !image.IdentityVerified {
		t.Fatalf("image proof incomplete: %+v", image)
	}
	name, network, cleanup, err := prepareAutobahnNetwork(ctx, docker, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if name == "" || !network.Internal || !network.ExternalNetworkDenied || !network.ReverseRelayCanary || !network.UnknownPeerDenied || !network.CrossSessionDenied || network.JavaServerBind != "127.0.0.1" {
		t.Fatalf("network proof incomplete: %+v", network)
	}
	archiveBytes, err := readBoundedRegular(archive, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := ParsePinnedAutobahnRegistryArchive(archiveBytes, PinnedAutobahnSourceArchiveDigest)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := SelectAutobahnRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.SelectedCaseIDs) != AutobahnSelectedCaseCount || len(selection.ExcludedCaseIDs) != AutobahnExcludedCaseCount {
		t.Fatalf("selection counts differ: %d/%d", len(selection.SelectedCaseIDs), len(selection.ExcludedCaseIDs))
	}
	plan, digest, err := buildAutobahnExecutionPlan(endpoint, relay, runner, image, network, selection)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ClientTransportSessions != AutobahnSelectedCaseCount*2 || plan.ServerTransportSessions != AutobahnSelectedCaseCount || !isDigest(digest) {
		t.Fatalf("execution plan mismatch: %+v %s", plan, digest)
	}
	t.Logf("AUTOBAHN_EXECUTION_PLAN_DIGEST=%s", digest)
}

func smallAutobahnSelection(t *testing.T) (AutobahnRegistry, AutobahnSelection) {
	t.Helper()
	ids := []string{"1.1.1", "2.1", "3.1", "4.1", "5.1", "6.1", "7.1", "9.1", "10.1", "12.1.1", "13.1.1"}
	registry := AutobahnRegistry{SchemaVersion: "1.0.0", SourceDigest: PinnedAutobahnRegistryDigest, CaseIDs: ids, UnresolvedGenerators: []string{}, sourceValidated: true, caseIDsDigest: digestStringSlice(ids)}
	selection, err := SelectAutobahnRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	return registry, selection
}

func dockerTar(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for name, data := range members {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o400, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeCanonicalTestFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := intake.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o400); err != nil {
		t.Fatal(err)
	}
}

func writeCanonicalReplace(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := intake.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o400); err != nil {
		t.Fatal(err)
	}
}

func cloneJSONMap(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var copyValue map[string]any
	if err := json.Unmarshal(raw, &copyValue); err != nil {
		t.Fatal(err)
	}
	return copyValue
}
