package corpora

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ClientHandshakeProjection binds the US-010 Rust tests to frozen and
// additive public evidence without changing the immutable US-005 corpus.
type ClientHandshakeProjection struct {
	Schema          string                      `json:"$schema"`
	SchemaVersion   string                      `json:"schema_version"`
	CorpusID        string                      `json:"corpus_id"`
	FrozenSource    ClientHandshakeFrozenSource `json:"frozen_source"`
	FrozenCases     []ClientHandshakeCase       `json:"frozen_cases"`
	AdditiveVectors []string                    `json:"additive_vectors"`
	Properties      ClientHandshakeProperties   `json:"properties"`
	FuzzSeeds       []ClientHandshakeFuzzSeed   `json:"fuzz_seeds"`
	Nonclaims       []string                    `json:"nonclaims"`
	Assurance       ClientHandshakeAssurance    `json:"assurance"`
}

// ClientHandshakeFrozenSource identifies the immutable input corpus.
type ClientHandshakeFrozenSource struct {
	CorpusID        string   `json:"corpus_id"`
	Artifact        string   `json:"artifact"`
	SHA256          string   `json:"sha256"`
	SelectedCaseIDs []string `json:"selected_case_ids"`
}

// ClientHandshakeCase is one exact frozen response projection.
type ClientHandshakeCase struct {
	CaseID    string `json:"case_id"`
	ClientKey string `json:"client_key"`
	NonceHex  string `json:"nonce_hex"`
	Expected  string `json:"expected"`
}

// ClientHandshakeProperties records deterministic property execution counts.
type ClientHandshakeProperties struct {
	ValidCasesSplitAtEveryByte int      `json:"valid_cases_split_at_every_byte"`
	SplitPointExecutions       int      `json:"split_point_executions"`
	CasePermutationProperties  []string `json:"case_permutation_properties"`
	FixedSeed                  string   `json:"fixed_seed"`
}

// ClientHandshakeFuzzSeed binds an inert seed to its expected typed result.
type ClientHandshakeFuzzSeed struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Expected string `json:"expected"`
}

// ClientHandshakeAssurance prevents the projection from implying deployment.
type ClientHandshakeAssurance struct {
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	AutobahnExecutions       int    `json:"autobahn_executions"`
	Production               bool   `json:"production"`
	Publication              bool   `json:"publication"`
}

// LoadAndVerifyClientHandshakeProjection checks all referenced immutable
// bytes, source case identities, nonces, and assurance bounds.
func LoadAndVerifyClientHandshakeProjection(root string) (ClientHandshakeProjection, error) {
	path := filepath.Join(root, "corpora/handshake/client.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return ClientHandshakeProjection{}, err
	}
	var projection ClientHandshakeProjection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil {
		return ClientHandshakeProjection{}, fmt.Errorf("decode client projection: %w", err)
	}
	if projection.SchemaVersion != "1.0.0" || projection.CorpusID != "us010-client-handshake" {
		return ClientHandshakeProjection{}, fmt.Errorf("unexpected client projection identity")
	}
	if len(projection.FrozenCases) != 10 || len(projection.FuzzSeeds) != 11 {
		return ClientHandshakeProjection{}, fmt.Errorf("projection requires 10 frozen cases and 11 fuzz seeds")
	}
	if projection.Properties.ValidCasesSplitAtEveryByte != 4 || projection.Properties.SplitPointExecutions != 548 {
		return ClientHandshakeProjection{}, fmt.Errorf("property execution counts do not match committed tests")
	}
	if projection.Assurance.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		projection.Assurance.IndependentReviewClaimed || projection.Assurance.AutobahnExecutions != 0 ||
		projection.Assurance.Production || projection.Assurance.Publication {
		return ClientHandshakeProjection{}, fmt.Errorf("client projection overstates assurance")
	}

	sourcePath := filepath.Join(root, projection.FrozenSource.Artifact)
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return ClientHandshakeProjection{}, err
	}
	if DigestSHA256(source) != projection.FrozenSource.SHA256 {
		return ClientHandshakeProjection{}, fmt.Errorf("frozen source digest mismatch")
	}
	sourceCases, err := serverResponseCases(source)
	if err != nil {
		return ClientHandshakeProjection{}, err
	}
	seen := make(map[string]bool, len(projection.FrozenCases))
	for _, projected := range projection.FrozenCases {
		if seen[projected.CaseID] {
			return ClientHandshakeProjection{}, fmt.Errorf("duplicate projected case %s", projected.CaseID)
		}
		seen[projected.CaseID] = true
		sourceCase, ok := sourceCases[projected.CaseID]
		if !ok || sourceCase.Context.ClientKey != projected.ClientKey {
			return ClientHandshakeProjection{}, fmt.Errorf("case %s does not match frozen source", projected.CaseID)
		}
		nonce, err := hex.DecodeString(projected.NonceHex)
		if err != nil || len(nonce) != 16 || base64.StdEncoding.EncodeToString(nonce) != projected.ClientKey {
			return ClientHandshakeProjection{}, fmt.Errorf("case %s nonce does not derive its client key", projected.CaseID)
		}
	}
	if len(seen) != len(projection.FrozenSource.SelectedCaseIDs) {
		return ClientHandshakeProjection{}, fmt.Errorf("selected case inventory length mismatch")
	}
	for _, id := range projection.FrozenSource.SelectedCaseIDs {
		if !seen[id] {
			return ClientHandshakeProjection{}, fmt.Errorf("selected case %s is not projected", id)
		}
	}

	seedSeen := make(map[string]bool, len(projection.FuzzSeeds))
	for _, seed := range projection.FuzzSeeds {
		if seedSeen[seed.Path] || !strings.HasPrefix(seed.Path, "rust/connection-core/fuzz-seeds/us010/") || filepath.Clean(seed.Path) != seed.Path {
			return ClientHandshakeProjection{}, fmt.Errorf("invalid or duplicate seed path %q", seed.Path)
		}
		seedSeen[seed.Path] = true
		seedBytes, err := os.ReadFile(filepath.Join(root, seed.Path))
		if err != nil {
			return ClientHandshakeProjection{}, err
		}
		if DigestSHA256(seedBytes) != seed.SHA256 {
			return ClientHandshakeProjection{}, fmt.Errorf("seed digest mismatch: %s", seed.Path)
		}
		compact := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
				return -1
			}
			return r
		}, string(seedBytes))
		if _, err := hex.DecodeString(compact); err != nil {
			return ClientHandshakeProjection{}, fmt.Errorf("seed is not canonical hex: %s", seed.Path)
		}
	}
	return projection, nil
}

func serverResponseCases(raw []byte) (map[string]HandshakeCase, error) {
	cases := make(map[string]HandshakeCase)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		var item HandshakeCase
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return nil, err
		}
		if item.Direction == "server_response" {
			cases[item.CaseID] = item
		}
	}
	return cases, scanner.Err()
}
