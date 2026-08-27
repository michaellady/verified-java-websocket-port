package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyGoodFixture(t *testing.T) {
	root := goodFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "--root", root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitOK, stdout.String(), stderr.String())
	}
	var report struct {
		OK       bool  `json:"ok"`
		Findings []any `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !report.OK || len(report.Findings) != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestVerifyRejectsHostileScaffolds(t *testing.T) {
	tests := []struct {
		name   string
		code   string
		mutate func(*testing.T, string)
	}{
		{"missing source safety", "SOURCE_UNSAFE_ATTRIBUTE_MISSING", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/src/lib.rs", "#![forbid(unsafe_code)]", "")
		}},
		{"missing workspace safety", "WORKSPACE_UNSAFE_LINT_MISSING", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/Cargo.toml", "unsafe_code = \"forbid\"", "unsafe_code = \"warn\"")
		}},
		{"missing package lint opt in", "PACKAGE_LINT_OPT_IN_MISSING", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "[lints]\nworkspace = true", "[lints]\nworkspace = false")
		}},
		{"unlisted manifest", "WORKSPACE_MEMBER_MISMATCH", func(t *testing.T, root string) {
			writeFixture(t, root, "rust/hidden/Cargo.toml", "[package]\nname = \"hidden\"\nversion = \"0.0.0\"\n")
		}},
		{"dependency", "DEPENDENCY_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "[dependencies]\n", "[dependencies]\nserde = \"1.0.0\"\n")
		}},
		{"build dependency", "BUILD_DEPENDENCY_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "[build-dependencies]\n", "[build-dependencies]\ncc = \"1.0.0\"\n")
		}},
		{"build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			writeFixture(t, root, "rust/connection-core/build.rs", "fn main() {}\n")
		}},
		{"proc macro", "PROC_MACRO_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "path = \"src/lib.rs\"", "path = \"src/lib.rs\"\nproc-macro = true")
		}},
		{"forbidden io", "FORBIDDEN_CORE_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub fn bad() { let _ = std::net::TcpStream::connect(\"ignored\"); }\n")
		}},
		{"callback", "CALLBACK_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub fn bad<F: FnMut()>(_callback: F) {}\n")
		}},
		{"stale lock", "LOCKFILE_DIGEST_MISMATCH", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/Cargo.lock", "# drift\n")
		}},
		{"stale license", "LICENSE_DIGEST_MISMATCH", func(t *testing.T, root string) {
			appendFixture(t, root, "LICENSE", "drift\n")
		}},
		{"stale toolchain", "TOOLCHAIN_MISMATCH", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/rust-toolchain.toml", "1.95.0", "stable")
		}},
		{"protocol stub", "PROTOCOL_STUB", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub fn bad() { todo!() }\n")
		}},
		{"invalid policy JSON", "POLICY_INVALID", func(t *testing.T, root string) {
			writeFixture(t, root, "security/rust-scaffold-policy.json", "{} trailing")
		}},
		{"offline command drift", "OFFLINE_REPRODUCIBILITY_METADATA_INVALID", func(t *testing.T, root string) {
			replaceFixture(t, root, "security/rust-scaffold-policy.json", "cargo metadata --locked --offline --format-version 1", "cargo metadata")
		}},
		{"unsafe policy path", "UNSAFE_PATH", func(t *testing.T, root string) {
			replaceFixture(t, root, "security/rust-scaffold-policy.json", `"workspace_root": "rust"`, `"workspace_root": "../rust"`)
		}},
		{"invalid manifest", "TOML_INVALID", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/Cargo.toml", "not valid toml\n")
		}},
		{"invalid workspace member", "WORKSPACE_MEMBER_INVALID", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/Cargo.toml", `members = ["connection-core"]`, `members = ["../escape"]`)
		}},
		{"lock package drift", "LOCKFILE_PACKAGE_MISMATCH", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/Cargo.lock", "\n[[package]]\nname = \"external\"\nversion = \"1.0.0\"\n")
		}},
		{"nonempty unsafe inventory", "DEPENDENCY_UNSAFE_INVENTORY_NOT_EMPTY", func(t *testing.T, root string) {
			replaceFixture(t, root, "security/rust-dependency-unsafe-inventory.json", `"proc_macro_crates": []`, `"proc_macro_crates": ["evil-macro"]`)
		}},
		{"qualified toolchain drift", "TOOLCHAIN_PIN_MISMATCH", func(t *testing.T, root string) {
			replaceFixture(t, root, "evidence/intake/toolchain-pins.json", `"version":"1.95.0"`, `"version":"1.94.0"`)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := goodFixture(t)
			test.mutate(t, root)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"verify", "--root", root}, &stdout, &stderr); code != exitFindings {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitFindings, stdout.String(), stderr.String())
			}
			var report struct {
				Findings []struct{ Code string } `json:"findings"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("decode report: %v", err)
			}
			for _, finding := range report.Findings {
				if finding.Code == test.code {
					return
				}
			}
			t.Fatalf("missing typed finding %s in %s", test.code, stdout.String())
		})
	}
}

func TestUsageIsTypedByExitStatus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if code := run([]string{"scan"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("unknown command exit = %d, want %d", code, exitUsage)
	}
	if code := run([]string{"verify", "--unknown"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("bad flag exit = %d, want %d", code, exitUsage)
	}
}

func goodFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "LICENSE", "fixture Apache license\n")
	writeFixture(t, root, "rust/Cargo.toml", `[workspace]
resolver = "3"
members = ["connection-core"]

[workspace.package]
version = "0.0.0"
edition = "2024"
rust-version = "1.95.0"
license = "Apache-2.0"
publish = false

[workspace.lints.rust]
unsafe_code = "forbid"
`)
	writeFixture(t, root, "rust/connection-core/Cargo.toml", `[package]
name = "websocket-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lib]
name = "websocket_core"
path = "src/lib.rs"

[lints]
workspace = true

[dependencies]

[dev-dependencies]

[build-dependencies]
`)
	writeFixture(t, root, "rust/connection-core/src/lib.rs", `#![forbid(unsafe_code)]
// std::net::TcpStream FnMut todo!() are inert fixture comments.
/* nested /* std::process::Command */ unimplemented!() */
pub const TEXT: &str = "std::time::Instant and unimplemented!() are inert strings";
pub const RAW: &str = r###"std::fs::File panic!()"###;
pub const BYTE: u8 = b'x';
pub struct ConnectionCore;
`)
	writeFixture(t, root, "rust/connection-core/tests/contract.rs", `#![forbid(unsafe_code)]
#[test]
fn contract_fixture_is_live() { assert!(true); }
`)
	writeFixture(t, root, "rust/rust-toolchain.toml", `[toolchain]
channel = "1.95.0"
components = ["rustfmt", "clippy"]
`)
	lock := `# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "websocket-core"
version = "0.0.0"
`
	writeFixture(t, root, "rust/Cargo.lock", lock)
	writeFixture(t, root, "evidence/intake/toolchain-pins.json", `{"artifacts":[{"artifact_id":"rustc-1.95.0-aarch64-apple-darwin","version":"1.95.0"}]}`)
	licenseDigest := fixtureDigest([]byte("fixture Apache license\n"))
	lockDigest := fixtureDigest([]byte(lock))
	writeFixture(t, root, "security/rust-scaffold-policy.json", `{
  "schema_version": 1,
  "workspace_root": "rust",
  "license_path": "LICENSE",
  "license_spdx": "Apache-2.0",
  "license_sha256": "sha256:`+licenseDigest+`",
  "toolchain_pin_path": "evidence/intake/toolchain-pins.json",
  "toolchain_artifact_id": "rustc-1.95.0-aarch64-apple-darwin",
  "toolchain_version": "1.95.0",
  "dependency_unsafe_inventory": "security/rust-dependency-unsafe-inventory.json",
  "offline_commands": [
    "cargo metadata --locked --offline --format-version 1",
    "cargo test --workspace --all-targets --all-features --locked --offline",
    "cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings"
  ]
}`)
	writeFixture(t, root, "security/rust-dependency-unsafe-inventory.json", `{
  "schema_version": 1,
  "cargo_lock_path": "rust/Cargo.lock",
  "cargo_lock_sha256": "sha256:`+lockDigest+`",
  "external_packages": [],
  "build_scripts": [],
  "proc_macro_crates": [],
  "build_dependencies": []
}`)
	return root
}

func writeFixture(t *testing.T, root, relative, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", relative, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

func replaceFixture(t *testing.T, root, relative, old, replacement string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	if !strings.Contains(string(body), old) {
		t.Fatalf("fixture %s lacks mutation target %q", relative, old)
	}
	writeFixture(t, root, relative, strings.Replace(string(body), old, replacement, 1))
}

func appendFixture(t *testing.T, root, relative, suffix string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	writeFixture(t, root, relative, string(body)+suffix)
}

func fixtureDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
