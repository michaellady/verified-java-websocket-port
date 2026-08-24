package lab

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	AutobahnImageReference       = "crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
	AutobahnImageManifestDigest  = "sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"
	AutobahnImageManifestBytes   = int64(3477)
	AutobahnImageConfigDigest    = "sha256:b0475418d42ae284876bd695f0282fbe6684e00f745d787b095d60e55727a06f"
	AutobahnImageLayerCount      = 15
	AutobahnSelectedCaseCount    = 247
	AutobahnExcludedCaseCount    = 271
	AutobahnAcceptedRootDigest   = "sha256:5713245496362ece061c769bc4ee8eb909bfcc6d7d319bc3fc9b750f6e0a4ad8"
	autobahnControllerVersion    = "1.0.0"
	autobahnDockerMaximumOutput  = 16 << 20
	autobahnReportMaximumBytes   = 8 << 20
	autobahnNetworkSubnet        = "172.30.242.0/24"
	autobahnNetworkGateway       = "172.30.242.1"
	autobahnRelayAddress         = "172.30.242.2"
	autobahnFuzzingClientAddress = "172.30.242.3"
	autobahnFuzzingServerAddress = "172.30.242.4"
)

var dockerSaveConfigName = regexp.MustCompile(`^([0-9a-f]{64})\.json$`)

type AutobahnImageProof struct {
	Reference        string                  `json:"reference"`
	ManifestDigest   string                  `json:"manifest_digest"`
	ManifestBytes    int64                   `json:"manifest_bytes"`
	ConfigDigest     string                  `json:"config_digest"`
	Platform         string                  `json:"platform"`
	Layers           int                     `json:"layers"`
	PullPolicy       string                  `json:"pull_policy"`
	DockerCLI        AutobahnArtifactBinding `json:"docker_cli"`
	IdentityVerified bool                    `json:"identity_verified"`
}

type AutobahnNetworkProof struct {
	Driver                 string `json:"driver"`
	Scope                  string `json:"scope"`
	Subnet                 string `json:"subnet"`
	Gateway                string `json:"gateway"`
	Internal               bool   `json:"internal"`
	ExternalNetworkDenied  bool   `json:"external_network_denied"`
	ReverseRelayCanary     bool   `json:"reverse_relay_canary"`
	UnknownPeerDenied      bool   `json:"unknown_peer_denied"`
	CrossSessionDenied     bool   `json:"cross_session_denied"`
	GatewayStrategy        string `json:"gateway_strategy"`
	JavaServerBind         string `json:"java_server_bind"`
	FuzzingServerAddress   string `json:"fuzzing_server_address"`
	ControlTransport       string `json:"control_transport"`
	LifecycleChannel       string `json:"lifecycle_channel"`
	HostPortsPublished     bool   `json:"host_ports_published"`
	RejectedPublishFinding string `json:"rejected_publish_finding"`
}

type AutobahnModeReceipt struct {
	Mode                     string           `json:"mode"`
	PlanDigest               string           `json:"plan_digest"`
	Executed                 bool             `json:"executed"`
	SelectedCount            int              `json:"selected_count"`
	ResultCount              int              `json:"result_count"`
	ConfigurationDigest      string           `json:"configuration_digest"`
	NormalizedReportDigest   string           `json:"normalized_report_digest"`
	ExtractionManifestDigest string           `json:"extraction_manifest_digest"`
	TransportSessions        int              `json:"transport_sessions"`
	Results                  []AutobahnResult `json:"results"`
}

type AutobahnExecutionPlan struct {
	SchemaVersion              string   `json:"schema_version"`
	AcceptedRootDigest         string   `json:"accepted_root_digest"`
	ArchiveDigest              string   `json:"archive_digest"`
	RegistryDigest             string   `json:"registry_digest"`
	SelectedCaseIDsDigest      string   `json:"selected_case_ids_digest"`
	ExcludedCaseIDsDigest      string   `json:"excluded_case_ids_digest"`
	SelectedCount              int      `json:"selected_count"`
	ExcludedCount              int      `json:"excluded_count"`
	SelectedFamilies           []string `json:"selected_families"`
	ExcludedFamilies           []string `json:"excluded_families"`
	RuntimeDigest              string   `json:"runtime_digest"`
	AdapterDigest              string   `json:"adapter_digest"`
	SupportDigest              string   `json:"support_digest"`
	RelaySourceDigest          string   `json:"relay_source_digest"`
	RelayBinaryDigest          string   `json:"relay_binary_digest"`
	RunnerSourceDigest         string   `json:"runner_source_digest"`
	RunnerBinaryDigest         string   `json:"runner_binary_digest"`
	WSTestDigest               string   `json:"wstest_digest"`
	InterpreterDigest          string   `json:"interpreter_digest"`
	ReportSourceDigest         string   `json:"report_source_digest"`
	ImageManifestDigest        string   `json:"image_manifest_digest"`
	ImageConfigDigest          string   `json:"image_config_digest"`
	NetworkSubnet              string   `json:"network_subnet"`
	ControlTransport           string   `json:"control_transport"`
	FrameProtocol              string   `json:"frame_protocol"`
	ConfigMount                string   `json:"config_mount"`
	ReportsTransport           string   `json:"reports_transport"`
	ReportsTmpfsBytes          int64    `json:"reports_tmpfs_bytes"`
	ExpectedReportFilesPerCase int      `json:"expected_report_files_per_case"`
	FailurePolicy              string   `json:"failure_policy"`
	ClientTransportSessions    int      `json:"client_transport_sessions"`
	ServerTransportSessions    int      `json:"server_transport_sessions"`
	Assurance                  string   `json:"assurance"`
	IndependentReviewClaimed   bool     `json:"independent_review_claimed"`
}

type AutobahnQualificationReceipt struct {
	SchemaVersion            string                    `json:"schema_version"`
	AcceptedRootDigest       string                    `json:"accepted_root_digest"`
	Status                   string                    `json:"status"`
	Assurance                string                    `json:"assurance"`
	IndependentReviewClaimed bool                      `json:"independent_review_claimed"`
	Endpoint                 AutobahnEndpointReceipt   `json:"endpoint"`
	Relay                    AutobahnRelayReceipt      `json:"relay"`
	Runner                   AutobahnRunnerReceipt     `json:"runner"`
	Image                    AutobahnImageProof        `json:"image"`
	Network                  AutobahnNetworkProof      `json:"network"`
	Plan                     AutobahnExecutionPlan     `json:"plan"`
	PlanDigest               string                    `json:"plan_digest"`
	RegistryDigest           string                    `json:"registry_digest"`
	ArchiveDigest            string                    `json:"archive_digest"`
	SelectedFamilies         []string                  `json:"selected_families"`
	ExcludedFamilies         []string                  `json:"excluded_families"`
	SelectedCaseIDs          []string                  `json:"selected_case_ids"`
	ExcludedCaseIDs          []string                  `json:"excluded_case_ids"`
	Client                   AutobahnModeReceipt       `json:"client"`
	Server                   AutobahnModeReceipt       `json:"server"`
	Blockers                 []AutobahnBlockingFinding `json:"blockers"`
	Production               bool                      `json:"production"`
	Publication              bool                      `json:"publication"`
}

type AutobahnBlockingFinding struct {
	Mode   string `json:"mode"`
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

type AutobahnControllerConfig struct {
	AcceptedRootDigest string
	ExpectedPlanDigest string
	ArchivePath        string
	Endpoint           AutobahnEndpointBuildConfig
	Relay              AutobahnRelayBuildConfig
	Runner             AutobahnRunnerBuildConfig
}

type dockerController struct {
	path string
	run  func(context.Context, ...string) ([]byte, error)
}

func newDockerController() (dockerController, AutobahnArtifactBinding, error) {
	resolved, err := exec.LookPath("docker")
	if err != nil {
		return dockerController{}, AutobahnArtifactBinding{}, finding("DOCKER_UNAVAILABLE", "$.docker", "Docker CLI is not available")
	}
	if !filepath.IsAbs(resolved) {
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return dockerController{}, AutobahnArtifactBinding{}, finding("DOCKER_UNAVAILABLE", "$.docker", err.Error())
		}
	}
	real, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return dockerController{}, AutobahnArtifactBinding{}, finding("DOCKER_UNAVAILABLE", "$.docker", err.Error())
	}
	binding, err := boundArtifactAnyDigest("docker-cli", real, 256<<20)
	if err != nil {
		return dockerController{}, AutobahnArtifactBinding{}, err
	}
	return dockerController{path: real}, binding, nil
}

func (d dockerController) output(ctx context.Context, arguments ...string) ([]byte, error) {
	if d.run != nil {
		return d.run(ctx, arguments...)
	}
	return runBounded(ctx, "/private/tmp", []string{"HOME=/private/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TZ=UTC"}, d.path, arguments...)
}

func verifyAutobahnImage(ctx context.Context, docker dockerController, cli AutobahnArtifactBinding) (AutobahnImageProof, error) {
	output, err := docker.output(ctx, "image", "inspect", AutobahnImageReference)
	if err != nil {
		return AutobahnImageProof{}, finding("AUTOBAHN_IMAGE_UNAVAILABLE", "$.image", err.Error())
	}
	identity, err := parseDockerInspectIdentity(output)
	if err != nil {
		return AutobahnImageProof{}, err
	}
	if err := validateDockerInspectIdentity(identity); err != nil {
		return AutobahnImageProof{}, err
	}
	configDigest, err := verifyDockerSaveConfig(ctx, docker)
	if err != nil {
		return AutobahnImageProof{}, err
	}
	if configDigest != AutobahnImageConfigDigest {
		return AutobahnImageProof{}, finding("AUTOBAHN_IMAGE_CONFIG_MISMATCH", "$.image.config_digest", "saved image config bytes differ from the accepted config")
	}
	return AutobahnImageProof{
		Reference: AutobahnImageReference, ManifestDigest: AutobahnImageManifestDigest, ManifestBytes: AutobahnImageManifestBytes,
		ConfigDigest: configDigest, Platform: "linux/amd64", Layers: AutobahnImageLayerCount, PullPolicy: "never", DockerCLI: cli, IdentityVerified: true,
	}, nil
}

func validateDockerInspectIdentity(identity dockerInspectIdentity) error {
	if identity.ID != AutobahnImageManifestDigest || identity.Architecture != "amd64" || identity.OS != "linux" || identity.RootFS.Type != "layers" || len(identity.RootFS.Layers) != AutobahnImageLayerCount || identity.Descriptor.Digest != AutobahnImageManifestDigest || identity.Descriptor.Size != AutobahnImageManifestBytes || identity.Descriptor.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		return finding("AUTOBAHN_IMAGE_IDENTITY_MISMATCH", "$.image.inspect", "manifest, descriptor, platform, or layer identity differs from the exact accepted image")
	}
	if !contains(identity.RepoDigests, AutobahnImageReference) {
		return finding("AUTOBAHN_IMAGE_IDENTITY_MISMATCH", "$.image.repo_digests", "exact accepted repository digest is not locally present")
	}
	return nil
}

type dockerInspectIdentity struct {
	ID           string
	RepoDigests  []string
	Architecture string
	OS           string
	RootFS       struct {
		Type   string   `json:"Type"`
		Layers []string `json:"Layers"`
	}
	Descriptor struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
}

func parseDockerInspectIdentity(output []byte) (dockerInspectIdentity, error) {
	var records []map[string]json.RawMessage
	if err := intake.DecodeStrict(output, &records); err != nil || len(records) != 1 {
		return dockerInspectIdentity{}, finding("AUTOBAHN_IMAGE_IDENTITY_MISMATCH", "$.image.inspect", "Docker inspect did not return one strict record")
	}
	record := records[0]
	var identity dockerInspectIdentity
	if decodeDockerInspectField(record, "Id", &identity.ID) != nil || decodeDockerInspectField(record, "RepoDigests", &identity.RepoDigests) != nil || decodeDockerInspectField(record, "Architecture", &identity.Architecture) != nil || decodeDockerInspectField(record, "Os", &identity.OS) != nil || decodeDockerInspectField(record, "RootFS", &identity.RootFS) != nil || decodeDockerInspectField(record, "Descriptor", &identity.Descriptor) != nil {
		return dockerInspectIdentity{}, finding("AUTOBAHN_IMAGE_IDENTITY_MISMATCH", "$.image.inspect", "required Docker identity fields are missing or malformed")
	}
	return identity, nil
}

func decodeDockerInspectField(record map[string]json.RawMessage, name string, destination any) error {
	raw, exists := record[name]
	if !exists || len(raw) == 0 {
		return errors.New("missing field")
	}
	return intake.DecodeStrict(raw, destination)
}

type dockerSaveManifestRecord struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

func verifyDockerSaveConfig(ctx context.Context, docker dockerController) (string, error) {
	command := exec.CommandContext(ctx, docker.path, "image", "save", AutobahnImageReference)
	command.Env = []string{"HOME=/private/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TZ=UTC"}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return "", finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image", err.Error())
	}
	stderr := &boundedBuffer{limit: autobahnDockerMaximumOutput}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return "", finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image", err.Error())
	}
	metadata, manifestBytes, blobs, parseErr := readDockerSaveTar(stdout)
	if parseErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return "", parseErr
	}
	waitErr := command.Wait()
	if waitErr != nil {
		return "", finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image", boundedDetail(stderr.buffer.Bytes(), waitErr))
	}
	if metadata["index.json"] != nil {
		if err := verifyOCIDockerSave(metadata, blobs); err != nil {
			return "", err
		}
	} else if manifestBytes != nil {
		var manifest []dockerSaveManifestRecord
		if err := intake.DecodeStrict(manifestBytes, &manifest); err != nil || len(manifest) != 1 {
			return "", finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.manifest", "saved image manifest is not one strict record")
		}
		record := manifest[0]
		match := dockerSaveConfigName.FindStringSubmatch(record.Config)
		if len(match) != 2 || "sha256:"+match[1] != AutobahnImageConfigDigest || len(record.Layers) != AutobahnImageLayerCount || len(record.RepoTags) == 0 {
			return "", finding("AUTOBAHN_IMAGE_CONFIG_MISMATCH", "$.image.manifest", fmt.Sprintf("save manifest config=%q layers=%d tags=%d does not bind the exact accepted identity", record.Config, len(record.Layers), len(record.RepoTags)))
		}
		if intake.DigestBytes(metadata[record.Config]) != AutobahnImageConfigDigest {
			return "", finding("AUTOBAHN_IMAGE_CONFIG_MISMATCH", "$.image.config", "saved config content digest differs")
		}
	} else {
		return "", finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image", "saved image contains neither an OCI graph nor legacy manifest")
	}
	return AutobahnImageConfigDigest, nil
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type dockerSavedBlob struct {
	Digest string
	Size   int64
}

func verifyOCIDockerSave(metadata map[string][]byte, blobs map[string]dockerSavedBlob) error {
	indexBytes := metadata["index.json"]
	manifestPath := "blobs/sha256/" + strings.TrimPrefix(AutobahnImageManifestDigest, "sha256:")
	configPath := "blobs/sha256/" + strings.TrimPrefix(AutobahnImageConfigDigest, "sha256:")
	manifestBytes := metadata[manifestPath]
	configBytes := metadata[configPath]
	if intake.DigestBytes(manifestBytes) != AutobahnImageManifestDigest || intake.DigestBytes(configBytes) != AutobahnImageConfigDigest {
		return finding("AUTOBAHN_IMAGE_CONFIG_MISMATCH", "$.image.oci", "OCI save lacks the exact manifest or config content bytes")
	}
	var index map[string]json.RawMessage
	if err := intake.DecodeStrict(indexBytes, &index); err != nil {
		return finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.oci.index", "OCI index is not strict JSON")
	}
	var schemaVersion int
	var manifests []map[string]json.RawMessage
	if decodeDockerInspectField(index, "schemaVersion", &schemaVersion) != nil || decodeDockerInspectField(index, "manifests", &manifests) != nil || schemaVersion != 2 || len(manifests) != 1 {
		return finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.oci.index", "OCI index does not contain one schema-2 manifest")
	}
	var manifestDescriptor ociDescriptor
	if decodeDockerInspectField(manifests[0], "mediaType", &manifestDescriptor.MediaType) != nil || decodeDockerInspectField(manifests[0], "digest", &manifestDescriptor.Digest) != nil || decodeDockerInspectField(manifests[0], "size", &manifestDescriptor.Size) != nil || manifestDescriptor.Digest != AutobahnImageManifestDigest || manifestDescriptor.Size != AutobahnImageManifestBytes {
		return finding("AUTOBAHN_IMAGE_IDENTITY_MISMATCH", "$.image.oci.index", "OCI index descriptor differs from the accepted manifest")
	}
	var manifest map[string]json.RawMessage
	if err := intake.DecodeStrict(manifestBytes, &manifest); err != nil {
		return finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.oci.manifest", "OCI manifest is not strict JSON")
	}
	var manifestSchema int
	var config ociDescriptor
	var layers []ociDescriptor
	if decodeDockerInspectField(manifest, "schemaVersion", &manifestSchema) != nil || decodeDockerInspectField(manifest, "config", &config) != nil || decodeDockerInspectField(manifest, "layers", &layers) != nil || manifestSchema != 2 || config.Digest != AutobahnImageConfigDigest || config.Size != int64(len(configBytes)) || len(layers) != AutobahnImageLayerCount {
		return finding("AUTOBAHN_IMAGE_CONFIG_MISMATCH", "$.image.oci.manifest", "OCI manifest config or layer binding differs from the accepted image")
	}
	seen := make(map[string]struct{}, len(layers))
	for index, layer := range layers {
		if !isDigest(layer.Digest) || layer.Size <= 0 || layer.Size > 2<<30 {
			return finding("AUTOBAHN_IMAGE_LAYER_MISMATCH", fmt.Sprintf("$.image.oci.layers[%d]", index), "layer descriptor is malformed or unbounded")
		}
		if _, duplicate := seen[layer.Digest]; duplicate {
			return finding("AUTOBAHN_IMAGE_LAYER_MISMATCH", fmt.Sprintf("$.image.oci.layers[%d]", index), "ordered manifest contains a duplicate layer digest")
		}
		seen[layer.Digest] = struct{}{}
		path := "blobs/sha256/" + strings.TrimPrefix(layer.Digest, "sha256:")
		blob, exists := blobs[path]
		if !exists || blob.Digest != layer.Digest || blob.Size != layer.Size {
			return finding("AUTOBAHN_IMAGE_LAYER_MISMATCH", fmt.Sprintf("$.image.oci.layers[%d]", index), "referenced layer content digest or size differs")
		}
	}
	return nil
}

func readDockerSaveTar(input io.Reader) (map[string][]byte, []byte, map[string]dockerSavedBlob, error) {
	reader := tar.NewReader(io.LimitReader(input, 2<<30))
	metadata := make(map[string][]byte)
	blobs := make(map[string]dockerSavedBlob)
	var manifest []byte
	entries := 0
	var total int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "saved image is not a valid bounded tar stream")
		}
		entries++
		if entries > 4096 || header.Size < 0 || total > 2<<30-header.Size {
			return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "saved image exceeds fixed archive bounds")
		}
		total += header.Size
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.Contains(name, "..") || strings.Contains(name, "\\") {
			return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "saved image contains an unsafe member path")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "saved image contains links or special entries")
		}
		if strings.HasPrefix(name, "blobs/sha256/") {
			if !regexp.MustCompile(`^blobs/sha256/[0-9a-f]{64}$`).MatchString(name) {
				return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "OCI blob path is malformed")
			}
			hash := sha256.New()
			wantedMetadata := name == "blobs/sha256/"+strings.TrimPrefix(AutobahnImageManifestDigest, "sha256:") || name == "blobs/sha256/"+strings.TrimPrefix(AutobahnImageConfigDigest, "sha256:")
			var destination io.Writer = hash
			var buffer bytes.Buffer
			if wantedMetadata {
				if header.Size > 8<<20 {
					return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "manifest or config blob exceeds metadata bound")
				}
				destination = io.MultiWriter(hash, &buffer)
			}
			written, copyErr := io.CopyN(destination, reader, header.Size)
			actualDigest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
			expectedDigest := "sha256:" + strings.TrimPrefix(name, "blobs/sha256/")
			if copyErr != nil || written != header.Size || actualDigest != expectedDigest {
				return nil, nil, nil, finding("AUTOBAHN_IMAGE_BLOB_MISMATCH", name, "OCI blob content does not match its path digest and size")
			}
			if _, duplicate := blobs[name]; duplicate {
				return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "duplicate OCI blob")
			}
			blobs[name] = dockerSavedBlob{Digest: actualDigest, Size: header.Size}
			if wantedMetadata {
				metadata[name] = buffer.Bytes()
			}
			continue
		}
		manifestBlob := "blobs/sha256/" + strings.TrimPrefix(AutobahnImageManifestDigest, "sha256:")
		configBlob := "blobs/sha256/" + strings.TrimPrefix(AutobahnImageConfigDigest, "sha256:")
		legacyConfig := strings.TrimPrefix(AutobahnImageConfigDigest, "sha256:") + ".json"
		if name != "manifest.json" && name != "index.json" && name != manifestBlob && name != configBlob && name != legacyConfig {
			continue
		}
		if header.Size > 8<<20 {
			return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "saved image metadata exceeds fixed bounds")
		}
		data, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "saved image metadata is truncated")
		}
		if name == "manifest.json" {
			if manifest != nil {
				return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "duplicate manifest")
			}
			manifest = data
		} else {
			if _, duplicate := metadata[name]; duplicate {
				return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "duplicate config candidate")
			}
			metadata[name] = data
		}
	}
	if manifest == nil && metadata["index.json"] == nil || len(metadata) == 0 {
		return nil, nil, nil, finding("AUTOBAHN_IMAGE_SAVE_FAILED", "$.image.tar", "saved image lacks manifest or config metadata")
	}
	return metadata, manifest, blobs, nil
}

type dockerNetworkInspect struct {
	Name       string
	Driver     string
	Scope      string
	Internal   bool
	Attachable bool
	Ingress    bool
	IPAMConfig []struct {
		Subnet  string `json:"Subnet"`
		Gateway string `json:"Gateway"`
	}
}

type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

func prepareAutobahnNetwork(ctx context.Context, docker dockerController, relay AutobahnRelayReceipt) (string, AutobahnNetworkProof, func(), error) {
	name, err := randomAutobahnName("vjwt-autobahn-")
	if err != nil {
		return "", AutobahnNetworkProof{}, nil, err
	}
	output, err := docker.output(ctx, "network", "create", "--driver", "bridge", "--internal", "--subnet", autobahnNetworkSubnet, "--gateway", autobahnNetworkGateway, "--label", "org.verified-java-websocket.scope=us002", name)
	if err != nil || strings.TrimSpace(string(output)) == "" {
		return "", AutobahnNetworkProof{}, nil, finding("AUTOBAHN_NETWORK_CREATE_FAILED", "$.network", boundedDetail(output, err))
	}
	cleanup := func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = docker.output(cleanupContext, "network", "rm", name)
	}
	keep := false
	defer func() {
		if !keep {
			cleanup()
		}
	}()
	inspectOutput, err := docker.output(ctx, "network", "inspect", name)
	if err != nil {
		return "", AutobahnNetworkProof{}, nil, finding("AUTOBAHN_NETWORK_IDENTITY_MISMATCH", "$.network", err.Error())
	}
	record, err := parseDockerNetworkInspect(inspectOutput)
	if err != nil {
		return "", AutobahnNetworkProof{}, nil, err
	}
	if err := validateDockerNetworkInspect(record, name); err != nil {
		return "", AutobahnNetworkProof{}, nil, err
	}
	if err := canaryNetworkNone(ctx, docker); err != nil {
		return "", AutobahnNetworkProof{}, nil, err
	}
	if err := canaryExternalNetworkDenied(ctx, docker, name); err != nil {
		return "", AutobahnNetworkProof{}, nil, err
	}
	if err := canaryReverseRelay(ctx, docker, name, relay); err != nil {
		return "", AutobahnNetworkProof{}, nil, err
	}
	keep = true
	return name, AutobahnNetworkProof{
		Driver: "bridge", Scope: "local", Subnet: autobahnNetworkSubnet, Gateway: autobahnNetworkGateway,
		Internal: true, ExternalNetworkDenied: true, ReverseRelayCanary: true, UnknownPeerDenied: true, CrossSessionDenied: true,
		GatewayStrategy: "single-session-docker-attach-relay", JavaServerBind: "127.0.0.1", FuzzingServerAddress: autobahnFuzzingServerAddress + ":9001",
		ControlTransport: "docker-attach-stdio", LifecycleChannel: "stderr", HostPortsPublished: false,
		RejectedPublishFinding: "DOCKER_INTERNAL_NETWORK_PORT_PUBLICATION_UNAVAILABLE_NON_AUTHORITATIVE",
	}, cleanup, nil
}

func parseDockerNetworkInspect(output []byte) (dockerNetworkInspect, error) {
	var records []map[string]json.RawMessage
	if err := intake.DecodeStrict(output, &records); err != nil || len(records) != 1 {
		return dockerNetworkInspect{}, finding("AUTOBAHN_NETWORK_IDENTITY_MISMATCH", "$.network", "network inspect did not return one strict record")
	}
	record := records[0]
	var identity dockerNetworkInspect
	var ipam map[string]json.RawMessage
	if decodeDockerInspectField(record, "Name", &identity.Name) != nil || decodeDockerInspectField(record, "Driver", &identity.Driver) != nil || decodeDockerInspectField(record, "Scope", &identity.Scope) != nil || decodeDockerInspectField(record, "Internal", &identity.Internal) != nil || decodeDockerInspectField(record, "Attachable", &identity.Attachable) != nil || decodeDockerInspectField(record, "Ingress", &identity.Ingress) != nil || decodeDockerInspectField(record, "IPAM", &ipam) != nil || decodeDockerInspectField(ipam, "Config", &identity.IPAMConfig) != nil {
		return dockerNetworkInspect{}, finding("AUTOBAHN_NETWORK_IDENTITY_MISMATCH", "$.network", "required network identity fields are missing or malformed")
	}
	return identity, nil
}

func validateDockerNetworkInspect(record dockerNetworkInspect, expectedName string) error {
	if record.Name != expectedName || record.Driver != "bridge" || record.Scope != "local" || !record.Internal || record.Ingress || record.Attachable || len(record.IPAMConfig) != 1 || record.IPAMConfig[0].Subnet != autobahnNetworkSubnet || record.IPAMConfig[0].Gateway != autobahnNetworkGateway {
		return finding("AUTOBAHN_NETWORK_IDENTITY_MISMATCH", "$.network", "network is not a non-attachable internal local bridge")
	}
	return nil
}

func canaryNetworkNone(ctx context.Context, docker dockerController) error {
	output, err := docker.output(ctx, "run", "--rm", "--pull=never", "--platform", "linux/amd64", "--network", "none",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "256m", "--cpus", "1",
		AutobahnImageReference, "wstest", "--help")
	if err != nil || !bytes.Contains(output, []byte("Usage")) {
		return finding("AUTOBAHN_NETWORK_NONE_CANARY_FAILED", "$.network", boundedDetail(output, err))
	}
	return nil
}

func canaryExternalNetworkDenied(ctx context.Context, docker dockerController, network string) error {
	const program = "import socket,sys;s=socket.socket();s.settimeout(2);sys.exit(s.connect_ex(('1.1.1.1',443)) == 0)"
	output, err := docker.output(ctx, "run", "--rm", "--pull=never", "--platform", "linux/amd64", "--network", network,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "256m", "--cpus", "1",
		AutobahnImageReference, "pypy", "-c", program)
	if err != nil {
		return finding("AUTOBAHN_EXTERNAL_NETWORK_CANARY_FAILED", "$.network", boundedDetail(output, err))
	}
	return nil
}

func canaryReverseRelay(ctx context.Context, docker dockerController, network string, relay AutobahnRelayReceipt) error {
	const dialCanary = "import socket,sys;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',9001));s.listen(1);c,a=s.accept();d=c.recv(64);c.sendall(d);c.close();s.close();sys.exit(0 if d=='verified-relay-dial' else 1)"
	echoName, err := randomAutobahnName("vjwt-relay-echo-")
	if err != nil {
		return err
	}
	echoOutput, err := docker.output(ctx, "run", "--detach", "--pull=never", "--platform", "linux/amd64", "--network", network, "--ip", autobahnFuzzingServerAddress,
		"--name", echoName, "--label", "org.verified-java-websocket.scope=us002-relay-canary", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "16", "--memory", "64m", "--cpus", "1", "--entrypoint", "pypy", AutobahnImageReference, "-c", dialCanary)
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(strings.TrimSpace(string(echoOutput))) {
		return finding("AUTOBAHN_REVERSE_RELAY_CANARY_FAILED", "$.network", boundedDetail(echoOutput, err))
	}
	echoCleanup := func() { removeAutobahnContainer(docker, echoName) }
	defer echoCleanup()
	dialContainer, dialCleanup, err := startRelayContainer(ctx, docker, network, relay, "dial", "")
	if err != nil {
		return err
	}
	defer dialCleanup()
	dialOutput, dialLifecycle, attachErr := runAttachedRelay(ctx, docker, dialContainer, []byte("verified-relay-dial"))
	if attachErr != nil || string(dialOutput) != "verified-relay-dial" || !exactRelayLifecycle(dialLifecycle, "dial", true) {
		return finding("AUTOBAHN_REVERSE_RELAY_CANARY_FAILED", "$.network", boundedString(boundedDetail(dialLifecycle, attachErr)+" raw="+string(dialOutput), 2048))
	}
	if err := waitContainerExit(ctx, docker, dialContainer, "0"); err != nil || waitContainerExit(ctx, docker, echoName, "0") != nil {
		return finding("AUTOBAHN_REVERSE_RELAY_CANARY_FAILED", "$.network", "dial relay or fixed echo peer did not exit successfully")
	}
	dialCleanup()
	echoCleanup()

	listenContainer, listenCleanup, err := startRelayContainer(ctx, docker, network, relay, "listen", autobahnFuzzingClientAddress)
	if err != nil {
		return err
	}
	defer listenCleanup()
	type attachedResult struct {
		raw       []byte
		lifecycle []byte
		err       error
	}
	attached := make(chan attachedResult, 1)
	go func() {
		raw, lifecycle, attachErr := runAttachedRelay(ctx, docker, listenContainer, []byte("verified-relay-listen"))
		attached <- attachedResult{raw: raw, lifecycle: lifecycle, err: attachErr}
	}()
	const listenCanary = "import socket,sys;s=socket.create_connection((sys.argv[1],9010),5);d=s.recv(64);s.sendall(d);s.close();x=socket.socket();x.settimeout(1);r=x.connect_ex((sys.argv[1],9010));x.close();sys.exit(0 if d=='verified-relay-listen' and r!=0 else 1)"
	canaryOutput, canaryErr := docker.output(ctx, "run", "--rm", "--pull=never", "--platform", "linux/amd64", "--network", network, "--ip", autobahnFuzzingClientAddress,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "16", "--memory", "64m", "--cpus", "1",
		AutobahnImageReference, "pypy", "-c", listenCanary, listenContainer)
	if canaryErr != nil {
		return finding("AUTOBAHN_REVERSE_RELAY_CANARY_FAILED", "$.network", boundedDetail(canaryOutput, canaryErr))
	}
	select {
	case result := <-attached:
		if result.err != nil || string(result.raw) != "verified-relay-listen" || !exactRelayLifecycle(result.lifecycle, "listen", true) {
			return finding("AUTOBAHN_REVERSE_RELAY_CANARY_FAILED", "$.network", boundedString(boundedDetail(result.lifecycle, result.err)+" raw="+string(result.raw), 2048))
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := waitContainerExit(ctx, docker, listenContainer, "0"); err != nil {
		return err
	}
	listenCleanup()

	denialContainer, denialCleanup, err := startRelayContainer(ctx, docker, network, relay, "listen", autobahnFuzzingClientAddress)
	if err != nil {
		return err
	}
	defer denialCleanup()
	denied := make(chan attachedResult, 1)
	go func() {
		raw, lifecycle, attachErr := runAttachedRelay(ctx, docker, denialContainer, nil)
		denied <- attachedResult{raw: raw, lifecycle: lifecycle, err: attachErr}
	}()
	const attacker = "import socket,sys;s=socket.socket();s.settimeout(5);sys.exit(s.connect_ex((sys.argv[1],9010)))"
	attackOutput, attackErr := docker.output(ctx, "run", "--rm", "--pull=never", "--platform", "linux/amd64", "--network", network, "--ip", autobahnFuzzingServerAddress,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "16", "--memory", "64m", "--cpus", "1",
		AutobahnImageReference, "pypy", "-c", attacker, denialContainer)
	if attackErr != nil {
		return finding("AUTOBAHN_RELAY_PEER_CANARY_FAILED", "$.network", boundedDetail(attackOutput, attackErr))
	}
	select {
	case result := <-denied:
		if result.err == nil || len(result.raw) != 0 || !bytes.Contains(result.lifecycle, []byte("RELAY_DENIED unknown-peer")) {
			return finding("AUTOBAHN_RELAY_PEER_CANARY_FAILED", "$.network", boundedDetail(result.lifecycle, result.err))
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := waitContainerExit(ctx, docker, denialContainer, "1"); err != nil {
		return err
	}
	denialCleanup()
	return nil
}

func startRelayContainer(ctx context.Context, docker dockerController, network string, relay AutobahnRelayReceipt, role, expectedTestPeer string) (string, func(), error) {
	if relay.Binary.Digest != AutobahnRelayBinaryDigest || !relay.RepeatableBuild || !relay.LinuxAMD64StaticELF || relay.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || relay.IndependentReviewClaimed || !relay.EmptyMountsVerified || !exactNeutralizedRelayVolumes(relay.NeutralizedVolumes) {
		return "", nil, finding("AUTOBAHN_RELAY_IDENTITY_MISMATCH", "$.relay", "relay has not passed the exact owner-qualified build")
	}
	if strings.ContainsAny(relay.Binary.Path+relay.emptyConfigDirectory+relay.emptyReportsDirectory, ",:\r\n\t") || role != "listen" && role != "dial" || role == "listen" && expectedTestPeer != autobahnFuzzingClientAddress || role == "dial" && expectedTestPeer != "" {
		return "", nil, finding("INVALID_AUTOBAHN_RELAY_CONFIG", "$.relay", "relay path, role, and fixed peer must equal the closed controller contract")
	}
	if err := verifyEmptyRelayMount(relay.emptyConfigDirectory); err != nil {
		return "", nil, err
	}
	if err := verifyEmptyRelayMount(relay.emptyReportsDirectory); err != nil {
		return "", nil, err
	}
	name, err := randomAutobahnName("vjwt-relay-")
	if err != nil {
		return "", nil, err
	}
	arguments := []string{"run", "--detach", "--interactive", "--pull=never", "--platform", "linux/amd64", "--network", network, "--ip", autobahnRelayAddress,
		"--name", name, "--hostname", name, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "16", "--memory", "64m", "--cpus", "1", "--user", "65532:65532", "--label", "org.verified-java-websocket.scope=us002-relay", "--label", "org.verified-java-websocket.role=" + role,
		"--env", "HOME=/nonexistent", "--env", "AUTOBAHN_RELAY_ROLE=" + role}
	if role == "listen" {
		arguments = append(arguments, "--env", "AUTOBAHN_RELAY_TEST_PEER="+expectedTestPeer)
	}
	arguments = append(arguments,
		"--mount", "type=bind,src="+relay.Binary.Path+",dst=/autobahn-relay,readonly",
		"--mount", "type=bind,src="+relay.emptyConfigDirectory+",dst=/config,readonly",
		"--mount", "type=bind,src="+relay.emptyReportsDirectory+",dst=/reports,readonly",
		"--entrypoint", "/autobahn-relay", AutobahnImageReference)
	output, err := docker.output(ctx, arguments...)
	containerID := strings.TrimSpace(string(output))
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(containerID) {
		return "", nil, finding("AUTOBAHN_RELAY_START_FAILED", "$.relay", boundedDetail(output, err))
	}
	cleanupOnce := sync.Once{}
	cleanup := func() {
		cleanupOnce.Do(func() {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, _ = docker.output(cleanupContext, "rm", "--force", name)
		})
	}
	ready := false
	defer func() {
		if !ready {
			cleanup()
		}
	}()
	if err := verifyRelayContainerIdentity(ctx, docker, name, network, role, expectedTestPeer, relay); err != nil {
		return "", nil, err
	}
	expectedReady := "RELAY_READY role=" + role
	for attempt := 0; attempt < 50; attempt++ {
		logs, _ := docker.output(ctx, "logs", name)
		if bytes.Contains(logs, []byte(expectedReady)) {
			ready = true
			return name, cleanup, nil
		}
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return "", nil, finding("AUTOBAHN_RELAY_START_FAILED", "$.relay", "relay did not emit its exact readiness binding")
}

func exactNeutralizedRelayVolumes(volumes []AutobahnNeutralizedVolume) bool {
	return len(volumes) == 2 && volumes[0] == (AutobahnNeutralizedVolume{ContainerPath: "/config", ContentDigest: intake.DigestBytes(nil), ReadOnly: true}) && volumes[1] == (AutobahnNeutralizedVolume{ContainerPath: "/reports", ContentDigest: intake.DigestBytes(nil), ReadOnly: true})
}

func verifyEmptyRelayMount(directory string) error {
	clean, err := cleanAbsoluteDirectory(directory, "$.relay.empty_mount")
	if err != nil || clean != directory || requireRealDirectory(directory) != nil {
		return finding("AUTOBAHN_RELAY_VOLUME_MISMATCH", "$.relay.empty_mount", "neutralized volume source is not an exact real directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		return finding("AUTOBAHN_RELAY_VOLUME_MISMATCH", "$.relay.empty_mount", "neutralized volume source is not empty")
	}
	return nil
}

func waitContainerExit(ctx context.Context, docker dockerController, container, expectedExit string) error {
	waitOutput, err := docker.output(ctx, "wait", container)
	if err != nil || strings.TrimSpace(string(waitOutput)) != expectedExit {
		return finding("AUTOBAHN_RELAY_EXIT_MISMATCH", "$.relay", boundedDetail(waitOutput, err))
	}
	return nil
}

func runAttachedRelay(ctx context.Context, docker dockerController, container string, input []byte) ([]byte, []byte, error) {
	if docker.path == "" || !regexp.MustCompile(`^vjwt-relay-[0-9a-f]{16}$`).MatchString(container) {
		return nil, nil, finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay", "attach requires the exact local Docker CLI and relay container identity")
	}
	framedInput, err := encodeAttachedBytes(input)
	if err != nil {
		return nil, nil, err
	}
	command := exec.CommandContext(ctx, docker.path, "attach", "--sig-proxy=false", container)
	command.Dir = "/private/tmp"
	command.Env = []string{"HOME=/private/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TZ=UTC"}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, nil, finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay.attach", "Docker attach stdin pipe is unavailable")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay.attach", "Docker attach stdout pipe is unavailable")
	}
	lifecycle := &boundedBuffer{limit: 64 << 10}
	command.Stderr = lifecycle
	if err := command.Start(); err != nil {
		return nil, append([]byte(nil), lifecycle.buffer.Bytes()...), err
	}
	writeDone := make(chan error, 1)
	go func() {
		written, writeErr := stdin.Write(framedInput)
		if writeErr == nil && written != len(framedInput) {
			writeErr = io.ErrShortWrite
		}
		writeDone <- writeErr
	}()
	decoded := &boundedBuffer{limit: autobahnDockerMaximumOutput}
	decodeErr := decodeAttachedStream(stdout, decoded)
	if decodeErr != nil {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		logs, _ := docker.output(context.Background(), "logs", "--tail", "20", container)
		return nil, append([]byte(nil), lifecycle.buffer.Bytes()...), finding("AUTOBAHN_RELAY_FRAME_MALFORMED", "$.relay.attach", boundedString(decodeErr.Error()+" log_hex="+hex.EncodeToString(logs), 2048))
	}
	extra, extraErr := io.ReadAll(io.LimitReader(stdout, 2))
	_ = stdin.Close()
	waitErr := command.Wait()
	writeErr := <-writeDone
	if extraErr != nil || len(extra) != 0 {
		return nil, append([]byte(nil), lifecycle.buffer.Bytes()...), finding("AUTOBAHN_RELAY_FRAME_MALFORMED", "$.relay.attach", "bytes follow the terminal output END frame")
	}
	if writeErr != nil || waitErr != nil {
		return nil, append([]byte(nil), lifecycle.buffer.Bytes()...), finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay.attach", boundedString(boundedDetail(lifecycle.buffer.Bytes(), waitErr)+" write="+boundedDetail(nil, writeErr), 2048))
	}
	return append([]byte(nil), decoded.buffer.Bytes()...), append([]byte(nil), lifecycle.buffer.Bytes()...), nil
}

const (
	attachFrameData       = byte(1)
	attachFrameEnd        = byte(2)
	attachFrameHeader     = 5
	attachMaximumPayload  = 64 << 10
	attachMaximumTransfer = int64(256 << 20)
)

func encodeAttachedBytes(input []byte) ([]byte, error) {
	if int64(len(input)) > attachMaximumTransfer {
		return nil, finding("AUTOBAHN_RELAY_FRAME_LIMIT", "$.relay.attach", "attached input exceeds the fixed direction bound")
	}
	var output bytes.Buffer
	for len(input) > 0 {
		length := len(input)
		if length > attachMaximumPayload {
			length = attachMaximumPayload
		}
		if err := writeAttachedFrame(&output, attachFrameData, input[:length]); err != nil {
			return nil, err
		}
		input = input[length:]
	}
	if err := writeAttachedFrame(&output, attachFrameEnd, nil); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func decodeAttachedBytes(input []byte) ([]byte, error) {
	reader := bytes.NewReader(input)
	var output bytes.Buffer
	if err := decodeAttachedStream(reader, &output); err != nil {
		return nil, err
	}
	if reader.Len() != 0 {
		return nil, finding("AUTOBAHN_RELAY_FRAME_MALFORMED", "$.relay.attach", "frame data follows the terminal END marker")
	}
	return output.Bytes(), nil
}

func decodeAttachedStream(reader io.Reader, output io.Writer) error {
	var total int64
	for {
		header := make([]byte, attachFrameHeader)
		if _, err := io.ReadFull(reader, header); err != nil {
			return finding("AUTOBAHN_RELAY_FRAME_MALFORMED", "$.relay.attach", "frame header is truncated")
		}
		length := int64(binary.BigEndian.Uint32(header[1:]))
		switch header[0] {
		case attachFrameData:
			if length < 1 || length > attachMaximumPayload || total > attachMaximumTransfer-length {
				return finding("AUTOBAHN_RELAY_FRAME_LIMIT", "$.relay.attach", "DATA frame or cumulative transfer exceeds its fixed bound")
			}
			payload := make([]byte, int(length))
			if _, err := io.ReadFull(reader, payload); err != nil {
				return finding("AUTOBAHN_RELAY_FRAME_MALFORMED", "$.relay.attach", "DATA frame is truncated")
			}
			written, err := output.Write(payload)
			if err != nil || written != len(payload) {
				return finding("AUTOBAHN_RELAY_FRAME_FAILED", "$.relay.attach", "decoded output exceeded its bound or could not be written")
			}
			total += length
		case attachFrameEnd:
			if length != 0 {
				return finding("AUTOBAHN_RELAY_FRAME_MALFORMED", "$.relay.attach", "END frame carries a payload")
			}
			return nil
		default:
			return finding("AUTOBAHN_RELAY_FRAME_MALFORMED", "$.relay.attach", "unknown frame type")
		}
	}
}

func writeAttachedFrame(destination io.Writer, frameType byte, payload []byte) error {
	if frameType == attachFrameData && (len(payload) == 0 || len(payload) > attachMaximumPayload) || frameType == attachFrameEnd && len(payload) != 0 || frameType != attachFrameData && frameType != attachFrameEnd {
		return finding("AUTOBAHN_RELAY_FRAME_MALFORMED", "$.relay.attach", "controller attempted an invalid fixed frame")
	}
	header := make([]byte, attachFrameHeader)
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	for _, value := range [][]byte{header, payload} {
		if len(value) == 0 {
			continue
		}
		written, err := destination.Write(value)
		if err != nil || written != len(value) {
			return finding("AUTOBAHN_RELAY_FRAME_FAILED", "$.relay.attach", "fixed frame write was incomplete")
		}
	}
	return nil
}

func encodeAttachedStream(source io.Reader, destination io.Writer) error {
	buffer := make([]byte, attachMaximumPayload)
	var total int64
	for {
		read, err := source.Read(buffer)
		if read > 0 {
			if total > attachMaximumTransfer-int64(read) {
				return finding("AUTOBAHN_RELAY_FRAME_LIMIT", "$.relay.attach", "streamed input exceeds its fixed direction bound")
			}
			if frameErr := writeAttachedFrame(destination, attachFrameData, buffer[:read]); frameErr != nil {
				return frameErr
			}
			total += int64(read)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				return finding("AUTOBAHN_RELAY_FRAME_FAILED", "$.relay.attach", "loopback input stream failed")
			}
			return writeAttachedFrame(destination, attachFrameEnd, nil)
		}
	}
}

func runAttachedRelayTCP(ctx context.Context, docker dockerController, container string, connection *net.TCPConn) ([]byte, error) {
	if docker.path == "" || connection == nil || !tcpConnectionIsLoopback(connection) || !regexp.MustCompile(`^vjwt-relay-[0-9a-f]{16}$`).MatchString(container) {
		return nil, finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay", "streaming attach requires the exact Docker CLI, relay identity, and loopback TCP peer")
	}
	defer connection.Close()
	deadline := time.Now().Add(180 * time.Second)
	_ = connection.SetDeadline(deadline)
	command := exec.CommandContext(ctx, docker.path, "attach", "--sig-proxy=false", container)
	command.Dir = "/private/tmp"
	command.Env = []string{"HOME=/private/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TZ=UTC"}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay.attach", "Docker attach stdin pipe is unavailable")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay.attach", "Docker attach stdout pipe is unavailable")
	}
	lifecycle := &boundedBuffer{limit: 64 << 10}
	command.Stderr = lifecycle
	if err := command.Start(); err != nil {
		return lifecycle.buffer.Bytes(), err
	}
	inputDone := make(chan error, 1)
	go func() { inputDone <- encodeAttachedStream(connection, stdin) }()
	decodeErr := decodeAttachedStream(stdout, connection)
	if decodeErr == nil {
		_ = connection.CloseWrite()
	}
	extra, extraErr := io.ReadAll(io.LimitReader(stdout, 2))
	waitErr := command.Wait()
	_ = stdin.Close()
	inputErr := <-inputDone
	if decodeErr != nil || inputErr != nil || extraErr != nil || len(extra) != 0 || waitErr != nil || !exactRelayLifecycle(lifecycle.buffer.Bytes(), relayRoleFromLifecycle(lifecycle.buffer.Bytes()), true) {
		detail := boundedString(boundedDetail(lifecycle.buffer.Bytes(), waitErr), 2048)
		return append([]byte(nil), lifecycle.buffer.Bytes()...), finding("AUTOBAHN_RELAY_ATTACH_FAILED", "$.relay.attach", detail)
	}
	return append([]byte(nil), lifecycle.buffer.Bytes()...), nil
}

func relayRoleFromLifecycle(lifecycle []byte) string {
	for _, role := range []string{"listen", "dial"} {
		if bytes.Contains(lifecycle, []byte("RELAY_PAIRED role="+role)) {
			return role
		}
	}
	return ""
}

func tcpConnectionIsLoopback(connection *net.TCPConn) bool {
	local, localOK := connection.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := connection.RemoteAddr().(*net.TCPAddr)
	return localOK && remoteOK && local.IP.IsLoopback() && remote.IP.IsLoopback()
}

func exactRelayLifecycle(lifecycle []byte, role string, complete bool) bool {
	if bytes.Contains(lifecycle, []byte("RELAY_DENIED")) || !bytes.Contains(lifecycle, []byte("RELAY_PAIRED role="+role)) {
		return false
	}
	return !complete || bytes.Contains(lifecycle, []byte("RELAY_COMPLETE role="+role))
}

func removeAutobahnContainer(docker dockerController, name string) {
	cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = docker.output(cleanupContext, "rm", "--force", name)
}

func verifyRelayContainerIdentity(ctx context.Context, docker dockerController, name, network, role, peer string, relay AutobahnRelayReceipt) error {
	output, err := docker.output(ctx, "inspect", name)
	if err != nil {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container", boundedDetail(output, err))
	}
	return validateRelayContainerInspect(output, name, network, role, peer, relay.Binary.Path, relay.emptyConfigDirectory, relay.emptyReportsDirectory)
}

func validateRelayContainerInspect(output []byte, name, network, role, peer, binaryPath, configPath, reportsPath string) error {
	var records []map[string]json.RawMessage
	if err := intake.DecodeStrict(output, &records); err != nil || len(records) != 1 {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container", "container inspect did not return one strict record")
	}
	record := records[0]
	var actualName, image, executable string
	var arguments []string
	var config, host, networkSettings map[string]json.RawMessage
	var mounts []map[string]json.RawMessage
	if decodeDockerInspectField(record, "Name", &actualName) != nil || decodeDockerInspectField(record, "Image", &image) != nil || decodeDockerInspectField(record, "Path", &executable) != nil || decodeDockerInspectField(record, "Args", &arguments) != nil || decodeDockerInspectField(record, "Config", &config) != nil || decodeDockerInspectField(record, "HostConfig", &host) != nil || decodeDockerInspectField(record, "NetworkSettings", &networkSettings) != nil || decodeDockerInspectField(record, "Mounts", &mounts) != nil {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container", "required container identity fields are missing or malformed")
	}
	var openStdin, tty bool
	var user string
	var entrypoint, environment []string
	var labels map[string]string
	if decodeDockerInspectField(config, "OpenStdin", &openStdin) != nil || decodeDockerInspectField(config, "Tty", &tty) != nil || decodeDockerInspectField(config, "User", &user) != nil || decodeDockerInspectField(config, "Entrypoint", &entrypoint) != nil || decodeDockerInspectField(config, "Env", &environment) != nil || decodeDockerInspectField(config, "Labels", &labels) != nil {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.config", "required attach configuration is missing")
	}
	var networkMode string
	var readOnly, privileged bool
	var capDrop, securityOptions []string
	var portBindings map[string]json.RawMessage
	var pidsLimit, memory, nanoCPUs int64
	if decodeDockerInspectField(host, "NetworkMode", &networkMode) != nil || decodeDockerInspectField(host, "ReadonlyRootfs", &readOnly) != nil || decodeDockerInspectField(host, "Privileged", &privileged) != nil || decodeDockerInspectField(host, "CapDrop", &capDrop) != nil || decodeDockerInspectField(host, "SecurityOpt", &securityOptions) != nil || decodeDockerInspectField(host, "PortBindings", &portBindings) != nil || decodeDockerInspectField(host, "PidsLimit", &pidsLimit) != nil || decodeDockerInspectField(host, "Memory", &memory) != nil || decodeDockerInspectField(host, "NanoCpus", &nanoCPUs) != nil {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.host_config", "required isolation configuration is missing")
	}
	var ports, networks map[string]json.RawMessage
	if decodeDockerInspectField(networkSettings, "Ports", &ports) != nil || decodeDockerInspectField(networkSettings, "Networks", &networks) != nil || len(networks) != 1 {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.network", "resolved network configuration is missing or ambiguous")
	}
	for _, bindings := range ports {
		if !bytes.Equal(bytes.TrimSpace(bindings), []byte("null")) {
			return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.ports", "attach relay must not publish a host port")
		}
	}
	attachedRaw, exists := networks[network]
	var attached map[string]json.RawMessage
	var address string
	if !exists || intake.DecodeStrict(attachedRaw, &attached) != nil || decodeDockerInspectField(attached, "IPAddress", &address) != nil || address != autobahnRelayAddress {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.network", "relay is not solely attached at its fixed internal address")
	}
	if actualName != "/"+name || image != AutobahnImageManifestDigest || executable != "/autobahn-relay" || len(arguments) != 0 || !openStdin || tty || user != "65532:65532" || len(entrypoint) != 1 || entrypoint[0] != "/autobahn-relay" || networkMode != network || !readOnly || privileged || !equalStrings(capDrop, []string{"ALL"}) || !equalStrings(securityOptions, []string{"no-new-privileges"}) || len(portBindings) != 0 || pidsLimit != 16 || memory != 64<<20 || nanoCPUs != 1_000_000_000 {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container", "entrypoint, image, stdio, resource, privilege, or no-publication identity differs")
	}
	if labels["org.verified-java-websocket.scope"] != "us002-relay" || labels["org.verified-java-websocket.role"] != role || countExactEnvironment(environment, "AUTOBAHN_RELAY_ROLE="+role) != 1 || countEnvironmentPrefix(environment, "HOME=") != 1 || countExactEnvironment(environment, "HOME=/nonexistent") != 1 {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.labels", "relay role labels or environment differ")
	}
	peerCount := countEnvironmentPrefix(environment, "AUTOBAHN_RELAY_TEST_PEER=")
	if role == "listen" && (peerCount != 1 || countExactEnvironment(environment, "AUTOBAHN_RELAY_TEST_PEER="+peer) != 1) || role == "dial" && peerCount != 0 {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.environment", "relay peer environment differs from the fixed role")
	}
	expectedMounts := map[string]string{"/autobahn-relay": binaryPath, "/config": configPath, "/reports": reportsPath}
	if len(mounts) != len(expectedMounts) {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.mount", "relay mount set includes an anonymous or undeclared mount")
	}
	for _, mount := range mounts {
		var mountType, source, destination string
		var writable bool
		if decodeDockerInspectField(mount, "Type", &mountType) != nil || decodeDockerInspectField(mount, "Source", &source) != nil || decodeDockerInspectField(mount, "Destination", &destination) != nil || decodeDockerInspectField(mount, "RW", &writable) != nil || mountType != "bind" || expectedMounts[destination] != source || writable {
			return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.mount", "relay artifact or neutralized volume mount differs from its exact read-only binding")
		}
		delete(expectedMounts, destination)
	}
	if len(expectedMounts) != 0 {
		return finding("AUTOBAHN_RELAY_CONTAINER_IDENTITY_MISMATCH", "$.relay.container.mount", "required relay mounts are missing")
	}
	return nil
}

func countExactEnvironment(environment []string, expected string) int {
	count := 0
	for _, value := range environment {
		if value == expected {
			count++
		}
	}
	return count
}

func countEnvironmentPrefix(environment []string, prefix string) int {
	count := 0
	for _, value := range environment {
		if strings.HasPrefix(value, prefix) {
			count++
		}
	}
	return count
}

func randomAutobahnName(prefix string) (string, error) {
	data := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", finding("RANDOMNESS_UNAVAILABLE", "$", err.Error())
	}
	return prefix + hex.EncodeToString(data), nil
}

type autobahnReportSummary struct {
	Behavior        string          `json:"behavior"`
	BehaviorClose   string          `json:"behaviorClose"`
	RemoteCloseCode json.RawMessage `json:"remoteCloseCode"`
	Duration        json.RawMessage `json:"duration"`
	ReportFile      string          `json:"reportfile"`
}

func ReadAutobahnReports(directory, expectedAgent string, registry AutobahnRegistry, selection AutobahnSelection, mode string) ([]AutobahnResult, string, error) {
	results, digest, err := readAutobahnReportSubset(directory, expectedAgent, selection.SelectedCaseIDs, mode)
	if err != nil {
		return nil, "", err
	}
	if err := ReconcileAutobahn(registry, selection, mode, results); err != nil {
		return nil, "", err
	}
	return results, digest, nil
}

func readAutobahnReportSubset(directory, expectedAgent string, expectedCaseIDs []string, mode string) ([]AutobahnResult, string, error) {
	clean, err := cleanAbsoluteDirectory(directory, "$.report_directory")
	if err != nil {
		return nil, "", err
	}
	if err := requireRealDirectory(clean); err != nil {
		return nil, "", err
	}
	if expectedAgent != AutobahnEndpointAgent || mode != "client" && mode != "server" {
		return nil, "", finding("INVALID_AUTOBAHN_REPORT", "$", "agent and mode must equal the fixed endpoint contract")
	}
	indexBytes, err := readBoundedRegular(filepath.Join(clean, "index.json"), autobahnReportMaximumBytes)
	if err != nil {
		return nil, "", err
	}
	var agents map[string]map[string]autobahnReportSummary
	if err := intake.DecodeStrict(indexBytes, &agents); err != nil || len(agents) != 1 {
		return nil, "", finding("INVALID_AUTOBAHN_REPORT", "$.index", "master report must contain exactly the bound endpoint agent")
	}
	cases, exists := agents[expectedAgent]
	if !exists || len(cases) != len(expectedCaseIDs) {
		return nil, "", finding("AUTOBAHN_RESULT_MISMATCH", "$.index", "master report agent or exact case count differs from selection")
	}
	expected, err := exactSet(expectedCaseIDs, "$.selected_case_ids", 100000)
	if err != nil {
		return nil, "", err
	}
	results := make([]AutobahnResult, 0, len(cases))
	for caseID, summary := range cases {
		if _, ok := expected[caseID]; !ok {
			return nil, "", finding("AUTOBAHN_RESULT_MISMATCH", "$.index."+caseID, "report includes an unknown or excluded case")
		}
		if _, ok := terminalAutobahnStatuses[summary.Behavior]; !ok {
			return nil, "", finding("NONTERMINAL_AUTOBAHN_STATUS", "$.index."+caseID+".behavior", "report behavior is not an exact terminal status")
		}
		expectedFile := autobahnReportFilename(expectedAgent, caseID)
		if summary.ReportFile != expectedFile || filepath.Base(summary.ReportFile) != summary.ReportFile {
			return nil, "", finding("INVALID_AUTOBAHN_REPORT", "$.index."+caseID+".reportfile", "detail report filename differs from the fixed agent/case identity")
		}
		if !validReportScalar(summary.RemoteCloseCode, true) || !validReportScalar(summary.Duration, false) {
			return nil, "", finding("INVALID_AUTOBAHN_REPORT", "$.index."+caseID, "duration or close code is not a bounded integer/null scalar")
		}
		summaryCanonical, err := intake.CanonicalJSON(summary)
		if err != nil {
			return nil, "", err
		}
		detailPath := filepath.Join(clean, summary.ReportFile)
		detailBytes, err := readBoundedRegular(detailPath, autobahnReportMaximumBytes)
		if err != nil {
			return nil, "", err
		}
		var detail map[string]any
		if err := intake.DecodeStrict(detailBytes, &detail); err != nil || len(detail) == 0 || len(detail) > 256 {
			return nil, "", finding("INVALID_AUTOBAHN_REPORT", detailPath, "case detail is not one bounded strict JSON object")
		}
		if detail["id"] != caseID || detail["agent"] != expectedAgent || detail["behavior"] != summary.Behavior {
			return nil, "", finding("AUTOBAHN_RESULT_MISMATCH", detailPath, "detail case, agent, or terminal behavior differs from master report")
		}
		detailCanonical, err := intake.CanonicalJSON(detail)
		if err != nil || len(detailCanonical) > autobahnReportMaximumBytes {
			return nil, "", finding("INVALID_AUTOBAHN_REPORT", detailPath, "detail cannot be canonically normalized within bounds")
		}
		result := AutobahnResult{
			CaseID: caseID, Status: summary.Behavior, ResultDigest: intake.DigestBytes(summaryCanonical), ObservationDigest: intake.DigestBytes(detailCanonical),
		}
		result.BindingDigest, err = AutobahnResultBindingDigest(mode, result)
		if err != nil {
			return nil, "", err
		}
		results = append(results, result)
	}
	sort.Slice(results, func(left, right int) bool { return results[left].CaseID < results[right].CaseID })
	normalized, err := intake.CanonicalJSON(results)
	if err != nil {
		return nil, "", err
	}
	return results, intake.DigestBytes(normalized), nil
}

func validReportScalar(raw json.RawMessage, nullable bool) bool {
	if nullable && bytes.Equal(raw, []byte("null")) {
		return true
	}
	if len(raw) == 0 || len(raw) > 32 || strings.ContainsAny(string(raw), ".eE+-\"[]{}") {
		return false
	}
	number, err := strconv.ParseInt(string(raw), 10, 64)
	return err == nil && number >= 0
}

func autobahnReportFilename(agent, caseID string) string {
	cleanAgent := strings.Map(func(character rune) rune {
		if strings.ContainsRune("abcdefghjiklmnopqrstuvwxyz0123456789", character) {
			return character
		}
		return ' '
	}, strings.ToLower(strings.TrimSpace(agent)))
	cleanAgent = strings.ReplaceAll(strings.TrimSpace(cleanAgent), " ", "_")
	return cleanAgent + "_case_" + strings.ReplaceAll(caseID, ".", "_") + ".json"
}

func buildAutobahnExecutionPlan(endpoint AutobahnEndpointReceipt, relay AutobahnRelayReceipt, runner AutobahnRunnerReceipt, image AutobahnImageProof, network AutobahnNetworkProof, selection AutobahnSelection) (AutobahnExecutionPlan, string, error) {
	if endpoint.RuntimeCopy.Digest != JavaWebSocketRuntimeDigest || endpoint.Adapter.Digest == "" || endpoint.Support.Digest != AutobahnSLF4JAPIDigest || relay.Source.Digest != AutobahnRelaySourceDigest || relay.Binary.Digest != AutobahnRelayBinaryDigest || !exactAutobahnRunner(runner) || image.ManifestDigest != AutobahnImageManifestDigest || image.ConfigDigest != AutobahnImageConfigDigest || network.ControlTransport != "docker-attach-stdio" || network.HostPortsPublished || len(selection.SelectedCaseIDs) != AutobahnSelectedCaseCount || len(selection.ExcludedCaseIDs) != AutobahnExcludedCaseCount {
		return AutobahnExecutionPlan{}, "", finding("AUTOBAHN_PLAN_IDENTITY_MISMATCH", "$.plan", "execution plan inputs differ from the exact qualified identities")
	}
	plan := AutobahnExecutionPlan{
		SchemaVersion: "1.0.0", AcceptedRootDigest: AutobahnAcceptedRootDigest, ArchiveDigest: PinnedAutobahnSourceArchiveDigest, RegistryDigest: PinnedAutobahnRegistryDigest,
		SelectedCaseIDsDigest: digestStringSlice(selection.SelectedCaseIDs), ExcludedCaseIDsDigest: digestStringSlice(selection.ExcludedCaseIDs),
		SelectedCount: len(selection.SelectedCaseIDs), ExcludedCount: len(selection.ExcludedCaseIDs),
		SelectedFamilies: append([]string(nil), selection.SelectedFamilies...), ExcludedFamilies: append([]string(nil), selection.ExcludedFamilies...),
		RuntimeDigest: endpoint.RuntimeCopy.Digest, AdapterDigest: endpoint.Adapter.Digest, SupportDigest: endpoint.Support.Digest,
		RelaySourceDigest: relay.Source.Digest, RelayBinaryDigest: relay.Binary.Digest,
		RunnerSourceDigest: runner.Source.Digest, RunnerBinaryDigest: runner.Binary.Digest, WSTestDigest: runner.WSTestDigest, InterpreterDigest: runner.InterpreterDigest,
		ReportSourceDigest: PinnedAutobahnReportSourceDigest, ImageManifestDigest: image.ManifestDigest, ImageConfigDigest: image.ConfigDigest,
		NetworkSubnet: network.Subnet, ControlTransport: network.ControlTransport, FrameProtocol: "DATA-1-END-2-BE32-64KiB-256MiB-v1",
		ConfigMount: "read-only-bind", ReportsTransport: "bounded-tmpfs-then-hostile-copy-validation", ReportsTmpfsBytes: 256 << 20, ExpectedReportFilesPerCase: 4,
		FailurePolicy:           "attempt-client-once-and-server-once-preserve-blocked-receipt",
		ClientTransportSessions: len(selection.SelectedCaseIDs) * 2, ServerTransportSessions: len(selection.SelectedCaseIDs),
		Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", IndependentReviewClaimed: false,
	}
	canonical, err := intake.CanonicalJSON(plan)
	if err != nil {
		return AutobahnExecutionPlan{}, "", err
	}
	return plan, intake.DigestBytes(canonical), nil
}

func RunAutobahnQualification(ctx context.Context, config AutobahnControllerConfig) (AutobahnQualificationReceipt, error) {
	if ctx == nil || config.AcceptedRootDigest != AutobahnAcceptedRootDigest {
		return AutobahnQualificationReceipt{}, finding("ACCEPTED_ROOT_MISMATCH", "$.accepted_root_digest", "controller requires the exact accepted US-001 root")
	}
	archive, err := readBoundedRegular(config.ArchivePath, 16<<20)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	registry, err := ParsePinnedAutobahnRegistryArchive(archive, PinnedAutobahnSourceArchiveDigest)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	selection, err := SelectAutobahnRegistry(registry)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	if len(selection.SelectedCaseIDs) != AutobahnSelectedCaseCount || len(selection.ExcludedCaseIDs) != AutobahnExcludedCaseCount {
		return AutobahnQualificationReceipt{}, finding("AUTOBAHN_SELECTION_DRIFT", "$.selection", "exact selected or visible excluded case count changed")
	}
	members, err := readPinnedAutobahnArchive(archive, PinnedAutobahnSourceArchiveDigest)
	if err != nil || verifyPinnedAutobahnReportContract(members[pinnedAutobahnReportSourcePath]) != nil {
		return AutobahnQualificationReceipt{}, finding("AUTOBAHN_REPORT_CONTRACT_UNRESOLVED", "$.archive.fuzzing", "accepted report lifecycle could not be proved statically")
	}
	endpoint, err := BuildAutobahnEndpoint(ctx, config.Endpoint)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	relay, err := BuildAutobahnRelay(ctx, config.Relay)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	runner, err := BuildAutobahnRunner(ctx, config.Runner)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	docker, cli, err := newDockerController()
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	image, err := verifyAutobahnImage(ctx, docker, cli)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	networkName, network, cleanup, err := prepareAutobahnNetwork(ctx, docker, relay)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	defer cleanup()
	plan, planDigest, err := buildAutobahnExecutionPlan(endpoint, relay, runner, image, network, selection)
	if err != nil {
		return AutobahnQualificationReceipt{}, err
	}
	if !isDigest(config.ExpectedPlanDigest) || config.ExpectedPlanDigest != planDigest {
		return AutobahnQualificationReceipt{}, finding("AUTOBAHN_PLAN_DIGEST_MISMATCH", "$.plan_digest", "authoritative execution requires the exact preflight plan digest")
	}
	client, clientErr := runAutobahnClientMode(ctx, docker, networkName, endpoint, relay, runner, registry, selection, planDigest)
	server, serverErr := runAutobahnServerMode(ctx, docker, networkName, endpoint, relay, runner, registry, selection, planDigest)
	receipt := AutobahnQualificationReceipt{
		SchemaVersion: autobahnControllerVersion, AcceptedRootDigest: AutobahnAcceptedRootDigest, Status: "PASS",
		Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT", IndependentReviewClaimed: false, Endpoint: endpoint, Relay: relay, Runner: runner, Image: image, Network: network, Plan: plan, PlanDigest: planDigest,
		RegistryDigest: PinnedAutobahnRegistryDigest, ArchiveDigest: PinnedAutobahnSourceArchiveDigest,
		SelectedFamilies: append([]string(nil), selection.SelectedFamilies...), ExcludedFamilies: append([]string(nil), selection.ExcludedFamilies...),
		SelectedCaseIDs: append([]string(nil), selection.SelectedCaseIDs...), ExcludedCaseIDs: append([]string(nil), selection.ExcludedCaseIDs...),
		Client: client, Server: server, Blockers: []AutobahnBlockingFinding{}, Production: false, Publication: false,
	}
	for _, failure := range []struct {
		mode string
		err  error
	}{{mode: "client", err: clientErr}, {mode: "server", err: serverErr}} {
		if failure.err == nil {
			continue
		}
		receipt.Status = "BLOCKED"
		blocker := AutobahnBlockingFinding{Mode: failure.mode, Code: "AUTOBAHN_MODE_FAILED", Path: "$." + failure.mode, Detail: boundedString(failure.err.Error(), 2048)}
		if typed, ok := failure.err.(*intake.Finding); ok {
			blocker.Code, blocker.Path, blocker.Detail = typed.Code, typed.Path, boundedString(typed.Message, 2048)
		}
		receipt.Blockers = append(receipt.Blockers, blocker)
	}
	if receipt.Status == "BLOCKED" {
		return receipt, finding("AUTOBAHN_QUALIFICATION_BLOCKED", "$.blockers", "one or both authoritative modes failed; the blocked receipt and work tree preserve the exact outcome")
	}
	return receipt, nil
}

func runAutobahnClientMode(ctx context.Context, docker dockerController, network string, endpoint AutobahnEndpointReceipt, relay AutobahnRelayReceipt, runner AutobahnRunnerReceipt, registry AutobahnRegistry, selection AutobahnSelection, planDigest string) (AutobahnModeReceipt, error) {
	root := filepath.Join(filepath.Dir(endpoint.Adapter.Path), "client-mode")
	if err := makeModeDirectories(root); err != nil {
		return AutobahnModeReceipt{}, err
	}
	type configBinding struct {
		CaseID string `json:"case_id"`
		Digest string `json:"digest"`
	}
	bindings := make([]configBinding, 0, len(selection.SelectedCaseIDs))
	extractions := make([]configBinding, 0, len(selection.SelectedCaseIDs))
	results := make([]AutobahnResult, 0, len(selection.SelectedCaseIDs))
	for index, caseID := range selection.SelectedCaseIDs {
		caseRoot := filepath.Join(root, fmt.Sprintf("case-%06d", index+1))
		configDirectory := filepath.Join(caseRoot, "config")
		reportDirectory := filepath.Join(caseRoot, "reports")
		if err := makeModeDirectories(caseRoot, configDirectory, reportDirectory); err != nil {
			return AutobahnModeReceipt{}, err
		}
		configuration := map[string]any{
			"url": "ws://0.0.0.0:9001", "outdir": "/reports", "cases": []string{caseID},
			"exclude-cases": selection.ExcludedFamilies, "exclude-agent-cases": map[string]any{},
		}
		configDigest, err := writeAutobahnConfiguration(filepath.Join(configDirectory, "fuzzingserver.json"), configuration)
		if err != nil {
			return AutobahnModeReceipt{}, err
		}
		bindings = append(bindings, configBinding{CaseID: caseID, Digest: configDigest})
		container, err := startFuzzingServer(ctx, docker, network, configDirectory, configDigest, runner)
		if err != nil {
			return AutobahnModeReceipt{}, err
		}
		caseErr := runJavaAutobahnClientCase(ctx, docker, network, endpoint, relay, container.name)
		extractionDigest, collectErr := collectAndReleaseAutobahnContainer(docker, container, reportDirectory, caseID)
		if caseErr != nil {
			return AutobahnModeReceipt{}, caseErr
		}
		if collectErr != nil {
			return AutobahnModeReceipt{}, collectErr
		}
		extractions = append(extractions, configBinding{CaseID: caseID, Digest: extractionDigest})
		caseResults, _, err := readAutobahnReportSubset(reportDirectory, AutobahnEndpointAgent, []string{caseID}, "client")
		if err != nil || len(caseResults) != 1 {
			return AutobahnModeReceipt{}, finding("AUTOBAHN_CLIENT_MODE_FAILED", "$.client.results", boundedDetail(nil, err))
		}
		results = append(results, caseResults[0])
	}
	if err := ReconcileAutobahn(registry, selection, "client", results); err != nil {
		return AutobahnModeReceipt{}, err
	}
	configurationCanonical, err := intake.CanonicalJSON(bindings)
	if err != nil {
		return AutobahnModeReceipt{}, err
	}
	reportCanonical, err := intake.CanonicalJSON(results)
	if err != nil {
		return AutobahnModeReceipt{}, err
	}
	extractionCanonical, err := intake.CanonicalJSON(extractions)
	if err != nil {
		return AutobahnModeReceipt{}, err
	}
	return AutobahnModeReceipt{
		Mode: "client", PlanDigest: planDigest, Executed: true, SelectedCount: len(selection.SelectedCaseIDs), ResultCount: len(results),
		ConfigurationDigest: intake.DigestBytes(configurationCanonical), NormalizedReportDigest: intake.DigestBytes(reportCanonical),
		ExtractionManifestDigest: intake.DigestBytes(extractionCanonical), TransportSessions: len(selection.SelectedCaseIDs) * 2, Results: results,
	}, nil
}

func runJavaAutobahnClientCase(ctx context.Context, docker dockerController, network string, endpoint AutobahnEndpointReceipt, relay AutobahnRelayReceipt, fuzzingServer string) error {
	caseContext, cancel := context.WithCancel(ctx)
	defer cancel()
	listenerRaw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return finding("AUTOBAHN_CLIENT_MODE_FAILED", "$.client.loopback", "fixed client listener could not start")
	}
	listener, ok := listenerRaw.(*net.TCPListener)
	if !ok {
		_ = listenerRaw.Close()
		return finding("AUTOBAHN_CLIENT_MODE_FAILED", "$.client.loopback", "fixed client listener is not TCP")
	}
	defer listener.Close()
	sessions := make(chan error, 1)
	go func() { sessions <- runFixedClientRelaySessions(caseContext, docker, network, relay, listener, 2) }()
	port := listener.Addr().(*net.TCPAddr).Port
	environment := endpointJavaEnvironment(filepath.Dir(endpoint.Adapter.Path), filepath.Dir(endpoint.Adapter.Path))
	output, runErr := runBounded(caseContext, filepath.Dir(endpoint.Adapter.Path), environment, endpoint.Java.Path,
		"-cp", endpointClasspath(endpoint), AutobahnEndpointClass, "client",
		"--adapter", endpoint.Adapter.Path, "--adapter-digest", endpoint.Adapter.Digest,
		"--runtime", endpoint.RuntimeCopy.Path, "--support", endpoint.Support.Path,
		"--url", "ws://127.0.0.1:"+strconv.Itoa(port), "--case-count", "1")
	if runErr != nil || !bytes.Contains(output, []byte("CLIENT_COMPLETE runtime="+JavaWebSocketRuntimeDigest)) {
		cancel()
		_ = listener.Close()
		select {
		case <-sessions:
		case <-time.After(30 * time.Second):
		}
		logs, _ := docker.output(context.Background(), "logs", "--tail", "100", fuzzingServer)
		return finding("AUTOBAHN_CLIENT_MODE_FAILED", "$.client.endpoint", boundedString(boundedDetail(output, runErr)+" docker="+string(logs), 2048))
	}
	select {
	case sessionErr := <-sessions:
		if sessionErr != nil {
			return sessionErr
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func runFixedClientRelaySessions(ctx context.Context, docker dockerController, network string, relay AutobahnRelayReceipt, listener *net.TCPListener, expected int) error {
	if expected != 2 {
		return finding("AUTOBAHN_CLIENT_MODE_FAILED", "$.client.sessions", "client case requires exactly runCase and updateReports sessions")
	}
	for session := 0; session < expected; session++ {
		container, cleanup, err := startRelayContainer(ctx, docker, network, relay, "dial", "")
		if err != nil {
			return err
		}
		_ = listener.SetDeadline(time.Now().Add(180 * time.Second))
		connection, err := listener.AcceptTCP()
		if err != nil || !tcpConnectionIsLoopback(connection) {
			if connection != nil {
				_ = connection.Close()
			}
			cleanup()
			return finding("AUTOBAHN_CLIENT_MODE_FAILED", "$.client.sessions", "Java client did not use the exact loopback listener")
		}
		lifecycle, attachErr := runAttachedRelayTCP(ctx, docker, container, connection)
		exitErr := waitContainerExit(ctx, docker, container, "0")
		cleanup()
		if attachErr != nil || exitErr != nil || !exactRelayLifecycle(lifecycle, "dial", true) {
			return finding("AUTOBAHN_CLIENT_MODE_FAILED", "$.client.sessions", boundedDetail(lifecycle, attachErr))
		}
	}
	_ = listener.Close()
	return nil
}

func runAutobahnServerMode(ctx context.Context, docker dockerController, network string, endpoint AutobahnEndpointReceipt, relay AutobahnRelayReceipt, runner AutobahnRunnerReceipt, registry AutobahnRegistry, selection AutobahnSelection, planDigest string) (AutobahnModeReceipt, error) {
	root := filepath.Join(filepath.Dir(endpoint.Adapter.Path), "server-mode")
	if err := makeModeDirectories(root); err != nil {
		return AutobahnModeReceipt{}, err
	}
	server, port, err := startJavaAutobahnServer(ctx, endpoint)
	if err != nil {
		return AutobahnModeReceipt{}, err
	}
	defer server.stop()
	type configBinding struct {
		CaseID string `json:"case_id"`
		Digest string `json:"digest"`
	}
	bindings := make([]configBinding, 0, len(selection.SelectedCaseIDs))
	extractions := make([]configBinding, 0, len(selection.SelectedCaseIDs))
	results := make([]AutobahnResult, 0, len(selection.SelectedCaseIDs))
	for index, caseID := range selection.SelectedCaseIDs {
		caseContext, cancelCase := context.WithTimeout(ctx, 10*time.Minute)
		caseRoot := filepath.Join(root, fmt.Sprintf("case-%06d", index+1))
		configDirectory := filepath.Join(caseRoot, "config")
		reportDirectory := filepath.Join(caseRoot, "reports")
		if err := makeModeDirectories(caseRoot, configDirectory, reportDirectory); err != nil {
			cancelCase()
			return AutobahnModeReceipt{}, err
		}
		container, cleanup, err := startRelayContainer(caseContext, docker, network, relay, "listen", autobahnFuzzingClientAddress)
		if err != nil {
			cancelCase()
			return AutobahnModeReceipt{}, err
		}
		configuration := map[string]any{
			"options": map[string]any{"failByDrop": false}, "outdir": "/reports",
			"servers": []any{map[string]any{"agent": AutobahnEndpointAgent, "url": "ws://" + container + ":9010"}},
			"cases":   []string{caseID}, "exclude-cases": selection.ExcludedFamilies, "exclude-agent-cases": map[string]any{},
		}
		configDigest, err := writeAutobahnConfiguration(filepath.Join(configDirectory, "fuzzingclient.json"), configuration)
		if err != nil {
			cleanup()
			cancelCase()
			return AutobahnModeReceipt{}, err
		}
		bindings = append(bindings, configBinding{CaseID: caseID, Digest: configDigest})
		attached := make(chan attachedModeResult, 1)
		go func() {
			connection, dialErr := dialJavaLoopback(caseContext, port)
			if dialErr != nil {
				attached <- attachedModeResult{err: dialErr}
				return
			}
			lifecycle, attachErr := runAttachedRelayTCP(caseContext, docker, container, connection)
			attached <- attachedModeResult{lifecycle: lifecycle, err: attachErr}
		}()
		output, extractionDigest, runErr := runFuzzingClient(caseContext, docker, network, configDirectory, configDigest, reportDirectory, caseID, runner)
		if runErr != nil {
			cancelCase()
		}
		var result attachedModeResult
		select {
		case result = <-attached:
		case <-time.After(30 * time.Second):
			result.err = finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.attach", "attach cleanup did not finish within its bound")
		}
		exitContext, cancelExit := context.WithTimeout(context.Background(), 30*time.Second)
		exitErr := waitContainerExit(exitContext, docker, container, "0")
		cancelExit()
		cleanup()
		cancelCase()
		if runErr != nil || result.err != nil || exitErr != nil || !exactRelayLifecycle(result.lifecycle, "listen", true) {
			return AutobahnModeReceipt{}, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server", boundedString(boundedDetail(output, runErr)+" attach="+boundedDetail(result.lifecycle, result.err), 2048))
		}
		caseResults, _, err := readAutobahnReportSubset(reportDirectory, AutobahnEndpointAgent, []string{caseID}, "server")
		if err != nil || len(caseResults) != 1 {
			return AutobahnModeReceipt{}, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.results", boundedDetail(nil, err))
		}
		results = append(results, caseResults[0])
		extractions = append(extractions, configBinding{CaseID: caseID, Digest: extractionDigest})
	}
	if err := ReconcileAutobahn(registry, selection, "server", results); err != nil {
		return AutobahnModeReceipt{}, err
	}
	configurationCanonical, err := intake.CanonicalJSON(bindings)
	if err != nil {
		return AutobahnModeReceipt{}, err
	}
	reportCanonical, err := intake.CanonicalJSON(results)
	if err != nil {
		return AutobahnModeReceipt{}, err
	}
	extractionCanonical, err := intake.CanonicalJSON(extractions)
	if err != nil {
		return AutobahnModeReceipt{}, err
	}
	return AutobahnModeReceipt{
		Mode: "server", PlanDigest: planDigest, Executed: true, SelectedCount: len(selection.SelectedCaseIDs), ResultCount: len(results),
		ConfigurationDigest: intake.DigestBytes(configurationCanonical), NormalizedReportDigest: intake.DigestBytes(reportCanonical),
		ExtractionManifestDigest: intake.DigestBytes(extractionCanonical), TransportSessions: len(selection.SelectedCaseIDs), Results: results,
	}, nil
}

type attachedModeResult struct {
	lifecycle []byte
	err       error
}

func dialJavaLoopback(ctx context.Context, port int) (*net.TCPConn, error) {
	if port < 1 || port > 65535 {
		return nil, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.loopback", "Java server port is invalid")
	}
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.loopback", "Java server loopback is unavailable")
	}
	connection, ok := raw.(*net.TCPConn)
	if !ok || !tcpConnectionIsLoopback(connection) {
		_ = raw.Close()
		return nil, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.loopback", "Java server connection left loopback")
	}
	return connection, nil
}

func makeModeDirectories(paths ...string) error {
	for _, path := range paths {
		if strings.ContainsAny(path, ",:\r\n\t") || !filepath.IsAbs(path) {
			return finding("INVALID_PATH", path, "Docker mount path contains forbidden delimiters")
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return finding("AUTOBAHN_MODE_DIRECTORY_FAILED", path, "fresh mode directory is required")
		}
	}
	return nil
}

func writeAutobahnConfiguration(path string, value map[string]any) (string, error) {
	data, err := intake.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return "", finding("AUTOBAHN_CONFIGURATION_FAILED", path, err.Error())
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", finding("AUTOBAHN_CONFIGURATION_FAILED", path, err.Error())
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", finding("AUTOBAHN_CONFIGURATION_FAILED", path, err.Error())
	}
	if err := file.Close(); err != nil {
		return "", finding("AUTOBAHN_CONFIGURATION_FAILED", path, err.Error())
	}
	return intake.DigestBytes(data), nil
}

type autobahnRunnerContainer struct {
	name         string
	role         string
	token        string
	configDigest string
}

func autobahnDockerRunArguments(network, configDirectory, mode, name, token string, runner AutobahnRunnerReceipt) []string {
	address := autobahnFuzzingServerAddress
	if mode == "fuzzingclient" {
		address = autobahnFuzzingClientAddress
	}
	return []string{
		"run", "--detach", "--interactive", "--name", name,
		"--label", "org.verified-java-websocket.scope=us002-autobahn", "--label", "org.verified-java-websocket.role=" + mode,
		"--pull=never", "--platform", "linux/amd64", "--network", network, "--ip", address,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "1g", "--cpus", "2",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777", "--mount", "type=bind,src=" + configDirectory + ",dst=/config,readonly",
		"--tmpfs", "/reports:rw,noexec,nosuid,nodev,size=256m,mode=0700",
		"--mount", "type=bind,src=" + runner.Binary.Path + ",dst=/autobahn-runner,readonly",
		"--env", "AUTOBAHN_RUNNER_ROLE=" + mode, "--env", "AUTOBAHN_RUNNER_TOKEN=" + token,
		"--entrypoint", "/autobahn-runner", AutobahnImageReference,
	}
}

func startFuzzingServer(ctx context.Context, docker dockerController, network, configDirectory, configDigest string, runner AutobahnRunnerReceipt) (autobahnRunnerContainer, error) {
	return startAutobahnRunnerContainer(ctx, docker, network, configDirectory, configDigest, "fuzzingserver", runner)
}

func startAutobahnRunnerContainer(ctx context.Context, docker dockerController, network, configDirectory, configDigest, role string, runner AutobahnRunnerReceipt) (autobahnRunnerContainer, error) {
	if !exactAutobahnRunner(runner) || role != "fuzzingserver" && role != "fuzzingclient" || !isDigest(configDigest) {
		return autobahnRunnerContainer{}, finding("AUTOBAHN_RUNNER_IDENTITY_MISMATCH", "$.runner", "runner, role, or configuration does not equal the fixed contract")
	}
	prefix := "vjwt-fuzzserver-"
	if role == "fuzzingclient" {
		prefix = "vjwt-fuzzclient-"
	}
	name, err := randomAutobahnName(prefix)
	if err != nil {
		return autobahnRunnerContainer{}, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return autobahnRunnerContainer{}, finding("AUTOBAHN_RUNNER_TOKEN_FAILED", "$.runner", "copy-complete token generation failed")
	}
	token := hex.EncodeToString(tokenBytes)
	output, err := docker.output(ctx, autobahnDockerRunArguments(network, configDirectory, role, name, token, runner)...)
	containerID := strings.TrimSpace(string(output))
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(containerID) {
		return autobahnRunnerContainer{}, finding("AUTOBAHN_RUNNER_START_FAILED", "$.runner.container", boundedDetail(output, err))
	}
	container := autobahnRunnerContainer{name: name, role: role, token: token, configDigest: configDigest}
	if err := verifyAutobahnRunnerContainerIdentity(ctx, docker, container, network, configDirectory, runner.Binary.Path); err != nil {
		removeAutobahnContainer(docker, name)
		return autobahnRunnerContainer{}, err
	}
	if err := waitAutobahnRunnerReady(ctx, docker, container); err != nil {
		removeAutobahnContainer(docker, name)
		return autobahnRunnerContainer{}, err
	}
	return container, nil
}

func verifyAutobahnRunnerContainerIdentity(ctx context.Context, docker dockerController, container autobahnRunnerContainer, network, configDirectory, binaryPath string) error {
	output, err := docker.output(ctx, "inspect", container.name)
	if err != nil {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container", boundedDetail(output, err))
	}
	return validateAutobahnRunnerContainerInspect(output, container, network, configDirectory, binaryPath)
}

func validateAutobahnRunnerContainerInspect(output []byte, container autobahnRunnerContainer, network, configDirectory, binaryPath string) error {
	var records []map[string]json.RawMessage
	if err := intake.DecodeStrict(output, &records); err != nil || len(records) != 1 {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container", "container inspect did not return one strict record")
	}
	var actualName, image, executable string
	var arguments []string
	var config, host, networkSettings map[string]json.RawMessage
	var mounts []map[string]json.RawMessage
	record := records[0]
	if decodeDockerInspectField(record, "Name", &actualName) != nil || decodeDockerInspectField(record, "Image", &image) != nil || decodeDockerInspectField(record, "Path", &executable) != nil || decodeDockerInspectField(record, "Args", &arguments) != nil || decodeDockerInspectField(record, "Config", &config) != nil || decodeDockerInspectField(record, "HostConfig", &host) != nil || decodeDockerInspectField(record, "NetworkSettings", &networkSettings) != nil || decodeDockerInspectField(record, "Mounts", &mounts) != nil {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container", "required container identity fields are missing or malformed")
	}
	var openStdin, tty bool
	var user string
	var entrypoint, environment []string
	var labels map[string]string
	if decodeDockerInspectField(config, "OpenStdin", &openStdin) != nil || decodeDockerInspectField(config, "Tty", &tty) != nil || decodeDockerInspectField(config, "User", &user) != nil || decodeDockerInspectField(config, "Entrypoint", &entrypoint) != nil || decodeDockerInspectField(config, "Env", &environment) != nil || decodeDockerInspectField(config, "Labels", &labels) != nil {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.config", "runner configuration is missing")
	}
	var networkMode string
	var readOnly, privileged bool
	var capDrop, securityOptions []string
	var portBindings, tmpfs map[string]json.RawMessage
	var pidsLimit, memory, nanoCPUs int64
	if decodeDockerInspectField(host, "NetworkMode", &networkMode) != nil || decodeDockerInspectField(host, "ReadonlyRootfs", &readOnly) != nil || decodeDockerInspectField(host, "Privileged", &privileged) != nil || decodeDockerInspectField(host, "CapDrop", &capDrop) != nil || decodeDockerInspectField(host, "SecurityOpt", &securityOptions) != nil || decodeDockerInspectField(host, "PortBindings", &portBindings) != nil || decodeDockerInspectField(host, "Tmpfs", &tmpfs) != nil || decodeDockerInspectField(host, "PidsLimit", &pidsLimit) != nil || decodeDockerInspectField(host, "Memory", &memory) != nil || decodeDockerInspectField(host, "NanoCpus", &nanoCPUs) != nil {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.host_config", "runner isolation configuration is missing")
	}
	var ports, networks map[string]json.RawMessage
	if decodeDockerInspectField(networkSettings, "Ports", &ports) != nil || decodeDockerInspectField(networkSettings, "Networks", &networks) != nil || len(networks) != 1 {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.network", "runner network configuration is missing or ambiguous")
	}
	address := autobahnFuzzingServerAddress
	if container.role == "fuzzingclient" {
		address = autobahnFuzzingClientAddress
	}
	attachedRaw, exists := networks[network]
	var attached map[string]json.RawMessage
	var resolvedAddress string
	if !exists || intake.DecodeStrict(attachedRaw, &attached) != nil || decodeDockerInspectField(attached, "IPAddress", &resolvedAddress) != nil || resolvedAddress != address {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.network", "runner does not have its sole fixed internal address")
	}
	expectedEnvironment := []string{
		"PATH=/opt/pypy/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PYPY_VERSION=7.3.20",
		"DEBIAN_FRONTEND=noninteractive", "NODE_PATH=/usr/local/lib/node_modules/", "AUTOBAHN_RUNNER_ROLE=" + container.role, "AUTOBAHN_RUNNER_TOKEN=" + container.token,
	}
	if actualName != "/"+container.name || image != AutobahnImageManifestDigest || executable != "/autobahn-runner" || len(arguments) != 0 || !openStdin || tty || user != "" || !equalStrings(entrypoint, []string{"/autobahn-runner"}) || !equalStrings(environment, expectedEnvironment) || networkMode != network || !readOnly || privileged || !equalStrings(capDrop, []string{"ALL"}) || !equalStrings(securityOptions, []string{"no-new-privileges"}) || len(portBindings) != 0 || len(ports) != 1 || pidsLimit != 128 || memory != 1<<30 || nanoCPUs != 2_000_000_000 {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container", "runner entrypoint, image, environment, resources, privilege, or no-publication identity differs")
	}
	if labels["org.verified-java-websocket.scope"] != "us002-autobahn" || labels["org.verified-java-websocket.role"] != container.role {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.labels", "runner labels differ")
	}
	expectedTmpfs := map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777", "/reports": "rw,noexec,nosuid,nodev,size=256m,mode=0700"}
	if len(tmpfs) != len(expectedTmpfs) {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.tmpfs", "runner tmpfs set differs")
	}
	for destination, expected := range expectedTmpfs {
		var actual string
		if decodeDockerInspectField(tmpfs, destination, &actual) != nil || actual != expected {
			return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.tmpfs", "runner tmpfs options differ")
		}
	}
	expectedMounts := map[string]struct {
		kind, source string
		writable     bool
	}{
		"/config": {kind: "bind", source: configDirectory}, "/autobahn-runner": {kind: "bind", source: binaryPath},
		"/tmp": {kind: "tmpfs", writable: true}, "/reports": {kind: "tmpfs", writable: true},
	}
	if len(mounts) != len(expectedMounts) {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.mount", "runner mount set contains an undeclared or anonymous mount")
	}
	for _, mount := range mounts {
		var kind, source, destination string
		var writable bool
		if decodeDockerInspectField(mount, "Type", &kind) != nil || decodeDockerInspectField(mount, "Source", &source) != nil || decodeDockerInspectField(mount, "Destination", &destination) != nil || decodeDockerInspectField(mount, "RW", &writable) != nil {
			return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.mount", "runner mount record is malformed")
		}
		expected, ok := expectedMounts[destination]
		if !ok || kind != expected.kind || source != expected.source || writable != expected.writable {
			return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.mount", "runner mount differs from its exact binding")
		}
		delete(expectedMounts, destination)
	}
	if len(expectedMounts) != 0 {
		return finding("AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH", "$.runner.container.mount", "required runner mount is missing")
	}
	return nil
}

func waitAutobahnRunnerReady(ctx context.Context, docker dockerController, container autobahnRunnerContainer) error {
	ready := "RUNNER_READY role=" + container.role + " config=" + container.configDigest + " wstest=" + AutobahnWSTestDigest + " interpreter=" + AutobahnPyPyDigest
	deadline := time.Now().Add(30 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		logs, err := docker.output(ctx, "logs", "--tail", "200", container.name)
		last = logs
		if err == nil && bytes.Contains(logs, []byte(ready)) && !bytes.Contains(logs, []byte("RUNNER_DENIED")) {
			serverReady := bytes.Contains(logs, []byte("Fuzzing Server (Port 9001")) && bytes.Contains(logs, []byte("Ok, will run 1 test cases for any clients connecting"))
			if container.role != "fuzzingserver" || serverReady {
				state, stateErr := docker.output(ctx, "inspect", "--format", "{{.State.Running}}", container.name)
				if stateErr == nil && strings.TrimSpace(string(state)) == "true" {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return finding("AUTOBAHN_RUNNER_READINESS_FAILED", "$.runner", boundedString(string(last), 2048))
}

func waitAutobahnRunnerClientExit(ctx context.Context, docker dockerController, container autobahnRunnerContainer) ([]byte, error) {
	marker := "RUNNER_CHILD_EXIT role=fuzzingclient code=0 output=sha256:"
	deadline := time.Now().Add(180 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		logs, err := docker.output(ctx, "logs", "--tail", "500", container.name)
		last = logs
		if err == nil && bytes.Contains(logs, []byte(marker)) && !bytes.Contains(logs, []byte("RUNNER_DENIED")) {
			state, stateErr := docker.output(ctx, "inspect", "--format", "{{.State.Running}}", container.name)
			if stateErr == nil && strings.TrimSpace(string(state)) == "true" {
				return logs, nil
			}
		}
		if err == nil && bytes.Contains(logs, []byte("RUNNER_CHILD_EXIT role=fuzzingclient code=")) {
			return logs, finding("AUTOBAHN_RUNNER_CHILD_FAILED", "$.runner", boundedString(string(logs), 2048))
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return last, finding("AUTOBAHN_RUNNER_TERMINAL_FAILED", "$.runner", boundedString(string(last), 2048))
}

func waitAutobahnServerReports(ctx context.Context, docker dockerController, container autobahnRunnerContainer) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		logs, err := docker.output(ctx, "logs", "--tail", "500", container.name)
		if err == nil && bytes.Contains(logs, []byte("Report generation complete.")) && !bytes.Contains(logs, []byte("RUNNER_DENIED")) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return finding("AUTOBAHN_REPORT_NOT_FLUSHED", "$.reports", "accepted fuzzing server did not emit its exact report completion marker")
}

func runFuzzingClient(ctx context.Context, docker dockerController, network, configDirectory, configDigest, reportDirectory, caseID string, runner AutobahnRunnerReceipt) ([]byte, string, error) {
	container, err := startAutobahnRunnerContainer(ctx, docker, network, configDirectory, configDigest, "fuzzingclient", runner)
	if err != nil {
		return nil, "", err
	}
	defer removeAutobahnContainer(docker, container.name)
	output, runErr := waitAutobahnRunnerClientExit(ctx, docker, container)
	if runErr != nil {
		return output, "", runErr
	}
	extractionDigest, copyErr := copyThenReleaseAutobahnReports(
		func() (string, error) { return copyAutobahnReports(docker, container.name, reportDirectory, caseID) },
		func() error { return releaseAutobahnRunner(docker, container) },
	)
	if copyErr != nil {
		return output, "", copyErr
	}
	return output, extractionDigest, nil
}

func collectAndReleaseAutobahnContainer(docker dockerController, container autobahnRunnerContainer, reportDirectory, caseID string) (string, error) {
	defer removeAutobahnContainer(docker, container.name)
	flushContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	flushErr := waitAutobahnServerReports(flushContext, docker, container)
	cancel()
	if flushErr != nil {
		return "", flushErr
	}
	return copyThenReleaseAutobahnReports(
		func() (string, error) { return copyAutobahnReports(docker, container.name, reportDirectory, caseID) },
		func() error { return releaseAutobahnRunner(docker, container) },
	)
}

func copyThenReleaseAutobahnReports(copyReports func() (string, error), release func() error) (string, error) {
	digest, err := copyReports()
	if err != nil {
		return "", err
	}
	if err := release(); err != nil {
		return "", err
	}
	return digest, nil
}

func releaseAutobahnRunner(docker dockerController, container autobahnRunnerContainer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, docker.path, "attach", "--sig-proxy=false", container.name)
	command.Dir = "/private/tmp"
	command.Env = []string{"HOME=/private/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TZ=UTC"}
	command.Stdin = strings.NewReader(container.token + "\n")
	output := &boundedBuffer{limit: 64 << 10}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	if err != nil || bytes.Contains(output.buffer.Bytes(), []byte("RUNNER_DENIED")) || !bytes.Contains(output.buffer.Bytes(), []byte("RUNNER_COPY_COMPLETE role="+container.role)) {
		return finding("AUTOBAHN_RUNNER_RELEASE_FAILED", "$.runner", boundedDetail(output.buffer.Bytes(), err))
	}
	return waitContainerExit(ctx, docker, container.name, "0")
}

func copyAutobahnReports(docker dockerController, container, reportDirectory, caseID string) (string, error) {
	if !regexp.MustCompile(`^vjwt-fuzz(?:server|client)-[0-9a-f]{16}$`).MatchString(container) {
		return "", finding("AUTOBAHN_REPORT_COPY_FAILED", "$.reports", "report copy requires an exact fixed container identity")
	}
	clean, err := cleanAbsoluteDirectory(reportDirectory, "$.reports")
	if err != nil || clean != reportDirectory || requireRealDirectory(reportDirectory) != nil {
		return "", finding("AUTOBAHN_REPORT_COPY_FAILED", "$.reports", "report destination is not an exact real directory")
	}
	info, infoErr := os.Stat(reportDirectory)
	entries, readErr := os.ReadDir(reportDirectory)
	if infoErr != nil || readErr != nil || info.Mode().Perm() != 0o700 || len(entries) != 0 {
		return "", finding("AUTOBAHN_REPORT_COPY_FAILED", "$.reports", "report destination must be fresh, empty, and mode 0700")
	}
	copyContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := docker.output(copyContext, "cp", container+":/reports/.", reportDirectory)
	if err != nil {
		return "", finding("AUTOBAHN_REPORT_COPY_FAILED", "$.reports", boundedDetail(output, err))
	}
	return validateCopiedAutobahnReports(reportDirectory, caseID)
}

func validateCopiedAutobahnReports(reportDirectory, caseID string) (string, error) {
	jsonName := autobahnReportFilename(AutobahnEndpointAgent, caseID)
	htmlName := strings.TrimSuffix(jsonName, ".json") + ".html"
	expected := map[string]struct{}{"index.json": {}, "index.html": {}, jsonName: {}, htmlName: {}}
	entries, err := os.ReadDir(reportDirectory)
	if err != nil || len(entries) != len(expected) {
		return "", finding("AUTOBAHN_REPORT_EXTRACTION_MISMATCH", "$.reports", "copied report does not contain the exact four expected files")
	}
	type extractedArtifact struct {
		Name   string `json:"name"`
		Digest string `json:"digest"`
		Bytes  int64  `json:"bytes"`
	}
	artifacts := make([]extractedArtifact, 0, len(entries))
	var aggregate int64
	for _, entry := range entries {
		name := entry.Name()
		if _, ok := expected[name]; !ok || path.Base(name) != name || name == "." || name == ".." {
			return "", finding("AUTOBAHN_REPORT_EXTRACTION_MISMATCH", "$.reports", "copied report contains an unexpected relative path")
		}
		filePath := filepath.Join(reportDirectory, name)
		info, err := os.Lstat(filePath)
		if err != nil || !info.Mode().IsRegular() || linkCount(info) != 1 {
			return "", finding("AUTOBAHN_REPORT_EXTRACTION_MISMATCH", filePath, "copied report entry is not a singly linked regular file")
		}
		data, err := readBoundedRegular(filePath, 64<<20)
		if err != nil || int64(len(data)) != info.Size() || aggregate > 256<<20-int64(len(data)) {
			return "", finding("AUTOBAHN_REPORT_EXTRACTION_MISMATCH", filePath, "copied report exceeds per-file or aggregate tmpfs bounds")
		}
		aggregate += int64(len(data))
		artifacts = append(artifacts, extractedArtifact{Name: name, Digest: intake.DigestBytes(data), Bytes: int64(len(data))})
	}
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Name < artifacts[right].Name })
	canonical, err := intake.CanonicalJSON(artifacts)
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(canonical), nil
}

func publishedAutobahnPort(ctx context.Context, docker dockerController, container string) (int, error) {
	return publishedContainerPort(ctx, docker, container, "9001/tcp")
}

func publishedContainerPort(ctx context.Context, docker dockerController, container, containerPort string) (int, error) {
	var lastOutput []byte
	var lastErr error
	for attempt := 0; attempt < 50; attempt++ {
		output, err := docker.output(ctx, "inspect", "--format", "{{json .NetworkSettings.Ports}}", container)
		lastOutput, lastErr = output, err
		if err == nil {
			port, parseErr := parseLoopbackPortBinding(output, containerPort)
			if parseErr == nil {
				published, publishErr := docker.output(ctx, "port", container, containerPort)
				expected := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
				if publishErr != nil || strings.TrimSpace(string(published)) != expected {
					return 0, finding("AUTOBAHN_RELAY_PORT_MISMATCH", "$.relay.port", "Docker port output differs from the exact resolved loopback binding")
				}
				if err := proveLANPortDenied(port); err != nil {
					return 0, err
				}
				return port, nil
			}
			lastErr = parseErr
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return 0, finding("AUTOBAHN_RELAY_PORT_MISMATCH", "$.relay.port", boundedString("loopback-only published port was not established: "+boundedDetail(lastOutput, lastErr), 512))
}

func parseLoopbackPortBinding(output []byte, containerPort string) (int, error) {
	var ports map[string]json.RawMessage
	if err := intake.DecodeStrict(bytes.TrimSpace(output), &ports); err != nil || len(ports) != 1 {
		return 0, finding("AUTOBAHN_RELAY_PORT_MISMATCH", "$.relay.port", "resolved port map is not one strict binding")
	}
	raw, exists := ports[containerPort]
	if !exists {
		return 0, finding("AUTOBAHN_RELAY_PORT_MISMATCH", "$.relay.port", "resolved port map lacks the fixed control port")
	}
	var bindings []dockerPortBinding
	if err := intake.DecodeStrict(raw, &bindings); err != nil || len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" {
		return 0, finding("AUTOBAHN_RELAY_PORT_MISMATCH", "$.relay.port", "control port is not bound only to host IPv4 loopback")
	}
	port, err := strconv.Atoi(bindings[0].HostPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != bindings[0].HostPort {
		return 0, finding("AUTOBAHN_RELAY_PORT_MISMATCH", "$.relay.port", "resolved host port is not canonical")
	}
	return port, nil
}

func proveLANPortDenied(port int) error {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return finding("AUTOBAHN_RELAY_LAN_DENIAL_UNAVAILABLE", "$.relay.port", "host interface addresses are unavailable")
	}
	checked := 0
	for _, address := range addresses {
		ip, _, parseErr := net.ParseCIDR(address.String())
		if parseErr != nil || ip.To4() == nil || ip.IsLoopback() || !ip.IsGlobalUnicast() {
			continue
		}
		checked++
		connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)), 500*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return finding("AUTOBAHN_RELAY_LAN_EXPOSURE", "$.relay.port", "control port accepted a non-loopback host connection")
		}
	}
	if checked == 0 {
		return finding("AUTOBAHN_RELAY_LAN_DENIAL_UNAVAILABLE", "$.relay.port", "no non-loopback IPv4 interface was available for the denial canary")
	}
	return nil
}

func waitLoopbackPort(ctx context.Context, port int) error {
	for attempt := 0; attempt < 100; attempt++ {
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return finding("AUTOBAHN_CLIENT_MODE_FAILED", "$.client.readiness", "fuzzing server did not become reachable on loopback")
}

func stopAutobahnContainer(docker dockerController, container string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = docker.output(ctx, "stop", "--time", "10", container)
}

type javaServerProcess struct {
	command *exec.Cmd
	done    chan error
	output  *boundedBuffer
}

func startJavaAutobahnServer(ctx context.Context, endpoint AutobahnEndpointReceipt) (*javaServerProcess, int, error) {
	command := exec.CommandContext(ctx, endpoint.Java.Path,
		"-cp", endpointClasspath(endpoint), AutobahnEndpointClass, "server",
		"--adapter", endpoint.Adapter.Path, "--adapter-digest", endpoint.Adapter.Digest,
		"--runtime", endpoint.RuntimeCopy.Path, "--support", endpoint.Support.Path,
		"--bind", "127.0.0.1", "--port", "0", "--max-seconds", "7200")
	command.Dir = filepath.Dir(endpoint.Adapter.Path)
	command.Env = endpointJavaEnvironment(filepath.Dir(endpoint.Adapter.Path), filepath.Dir(endpoint.Adapter.Path))
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, 0, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.endpoint", err.Error())
	}
	output := &boundedBuffer{limit: autobahnDockerMaximumOutput}
	command.Stderr = output
	if err := command.Start(); err != nil {
		return nil, 0, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.endpoint", err.Error())
	}
	process := &javaServerProcess{command: command, done: make(chan error, 1), output: output}
	go func() { process.done <- command.Wait() }()
	reader := bufio.NewReader(io.LimitReader(stdout, autobahnDockerMaximumOutput))
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "SERVER_READY ") {
		process.stop()
		return nil, 0, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.endpoint", "server did not emit its exact readiness marker")
	}
	port, err := parsePositiveBounded(strings.TrimSpace(strings.TrimPrefix(line, "SERVER_READY ")), 65535)
	if err != nil {
		process.stop()
		return nil, 0, finding("AUTOBAHN_SERVER_MODE_FAILED", "$.server.endpoint", "server emitted an invalid host-only port")
	}
	go func() {
		_, _ = io.Copy(output, reader)
	}()
	return process, port, nil
}

func (p *javaServerProcess) stop() {
	if p == nil || p.command == nil || p.command.Process == nil {
		return
	}
	_ = p.command.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		_ = p.command.Process.Kill()
		<-p.done
	}
}

func endpointClasspath(endpoint AutobahnEndpointReceipt) string {
	return endpoint.Adapter.Path + string(os.PathListSeparator) + endpoint.RuntimeCopy.Path + string(os.PathListSeparator) + endpoint.Support.Path
}

func endpointJavaEnvironment(home, temporary string) []string {
	return []string{"HOME=" + home, "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin", "TZ=UTC", "TMPDIR=" + temporary}
}
