package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyGoodFixture(t *testing.T) {
	root := goodFixture(t)
	var stdout, stderr bytes.Buffer
	if code := run(verificationArguments(root), &stdout, &stderr); code != exitOK {
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
		{"driver registry dependency", "DEPENDENCY_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/websocket-driver/Cargo.toml", `websocket-core = { path = "../connection-core" }`, `websocket-core = "0.0.0"`)
		}},
		{"driver wrong local path", "DEPENDENCY_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/websocket-driver/Cargo.toml", `websocket-core = { path = "../connection-core" }`, `websocket-core = { path = "../other" }`)
		}},
		{"driver extra dependency", "DEPENDENCY_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/websocket-driver/Cargo.toml", `websocket-core = { path = "../connection-core" }`, "websocket-core = { path = \"../connection-core\" }\nserde = \"1\"")
		}},
		{"build dependency", "BUILD_DEPENDENCY_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "[build-dependencies]\n", "[build-dependencies]\ncc = \"1.0.0\"\n")
		}},
		{"build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			writeFixture(t, root, "rust/connection-core/build.rs", "fn main() {}\n")
		}},
		{"repository root build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			writeFixture(t, root, "build.rs", "fn main() {}\n")
		}},
		{"custom package build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "publish.workspace = true", "publish.workspace = true\nbuild = \"codegen.rs\"")
		}},
		{"quoted custom package build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "publish.workspace = true", "publish.workspace = true\n\"build\" = \"codegen.rs\"")
		}},
		{"literal quoted custom package build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "publish.workspace = true", "publish.workspace = true\n'build' = \"codegen.rs\"")
		}},
		{"quoted package table custom build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "[package]", "[\"package\"]")
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "publish.workspace = true", "publish.workspace = true\n\"build\" = \"codegen.rs\"")
		}},
		{"dotted custom package build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			prependFixture(t, root, "rust/connection-core/Cargo.toml", "package.build = \"codegen.rs\"\n")
		}},
		{"quoted dotted custom package build script", "BUILD_SCRIPT_NOT_ALLOWED", func(t *testing.T, root string) {
			prependFixture(t, root, "rust/connection-core/Cargo.toml", "\"package\".\"build\" = \"codegen.rs\"\n")
		}},
		{"repository cargo config", "CARGO_CONFIG_NOT_ALLOWED", func(t *testing.T, root string) {
			writeFixture(t, root, ".cargo/config.toml", "[build]\nrustc-wrapper = \"./wrapper\"\n")
		}},
		{"proc macro", "PROC_MACRO_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "path = \"src/lib.rs\"", "path = \"src/lib.rs\"\nproc-macro = true")
		}},
		{"forbidden io", "FORBIDDEN_CORE_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub fn bad() { let _ = std::net::TcpStream::connect(\"ignored\"); }\n")
		}},
		{"driver forbidden socket", "FORBIDDEN_CORE_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/websocket-driver/src/lib.rs", "\nuse std::net::TcpStream;\n")
		}},
		{"std alias", "FORBIDDEN_CORE_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\nuse std as ambient;\n")
		}},
		{"absolute std path", "FORBIDDEN_CORE_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\nuse ::std::env;\n")
		}},
		{"std group import", "FORBIDDEN_CORE_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\nuse std::{sync::mpsc};\n")
		}},
		{"unix socket", "FORBIDDEN_CORE_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\nuse std::os::unix::net::UnixStream;\n")
		}},
		{"ambient environment", "FORBIDDEN_CORE_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\nuse std::env;\n")
		}},
		{"callback", "CALLBACK_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub fn bad<F: FnMut()>(_callback: F) {}\n")
		}},
		{"function pointer", "CALLBACK_SURFACE", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub type Callback = fn();\n")
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
			replaceFixture(t, root, "rust/Cargo.toml", `members = ["connection-core", "websocket-driver"]`, `members = ["../escape"]`)
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
		{"expired toolchain receipt", "TOOLCHAIN_PIN_EXPIRED", func(t *testing.T, root string) {
			replaceFixture(t, root, "evidence/intake/toolchain-pins.json", `"expires_at":"2026-09-23T12:26:43Z"`, `"expires_at":"2026-08-25T00:00:00Z"`)
		}},
		{"substituted installed cargo", "TOOLCHAIN_BINARY_MISMATCH", func(t *testing.T, root string) {
			appendFixture(t, root, "toolchain/bin/cargo", "substitution\n")
		}},
		{"synthetic toolchain shape", "TOOLCHAIN_PIN_INVALID", func(t *testing.T, root string) {
			writeFixture(t, root, "evidence/intake/toolchain-pins.json", `{"artifacts":[]}`)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := goodFixture(t)
			test.mutate(t, root)
			var stdout, stderr bytes.Buffer
			if code := run(verificationArguments(root), &stdout, &stderr); code != exitFindings {
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

func TestVerifyRejectsAmbientCompiledSourceInputs(t *testing.T) {
	tests := []struct {
		name   string
		code   string
		mutate func(*testing.T, string)
	}{
		{"include macro", "AMBIENT_MACRO", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\ninclude!(\"generated.rs\");\n")
		}},
		{"include bytes macro", "AMBIENT_MACRO", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub const BYTES: &[u8] = include_bytes!(\"data.bin\");\n")
		}},
		{"include string macro", "AMBIENT_MACRO", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub const TEXT: &str = include_str!(\"data.txt\");\n")
		}},
		{"environment macro", "AMBIENT_MACRO", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub const VALUE: &str = env!(\"VALUE\");\n")
		}},
		{"optional environment macro", "AMBIENT_MACRO", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\npub const VALUE: Option<&str> = option_env!(\"VALUE\");\n")
		}},
		{"manifest root outside crate", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", `path = "src/lib.rs"`, `path = "../outside.rs"`)
			writeFixture(t, root, "rust/outside.rs", "#![forbid(unsafe_code)]\npub struct Outside;\n")
		}},
		{"literal manifest root outside crate", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", `path = "src/lib.rs"`, `path = '../outside.rs'`)
			writeFixture(t, root, "rust/outside.rs", "#![forbid(unsafe_code)]\npub struct Outside;\n")
		}},
		{"dotted manifest root outside crate", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "[lib]\nname = \"websocket_core\"\npath = \"src/lib.rs\"\n\n", "")
			prependFixture(t, root, "rust/connection-core/Cargo.toml", "lib.name = \"websocket_core\"\nlib.path = \"../outside.rs\"\n")
			writeFixture(t, root, "rust/outside.rs", "#![forbid(unsafe_code)]\npub struct Outside;\n")
		}},
		{"dotted literal manifest root outside crate", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "[lib]\nname = \"websocket_core\"\npath = \"src/lib.rs\"\n\n", "")
			prependFixture(t, root, "rust/connection-core/Cargo.toml", "lib.name = \"websocket_core\"\nlib.path = '../outside.rs'\n")
			writeFixture(t, root, "rust/outside.rs", "#![forbid(unsafe_code)]\npub struct Outside;\n")
		}},
		{"multiline basic manifest root is rejected", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", `path = "src/lib.rs"`, `path = """src/lib.rs"""`)
		}},
		{"multiline literal manifest root is rejected", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", `path = "src/lib.rs"`, `path = '''src/lib.rs'''`)
		}},
		{"literal binary root outside crate", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/Cargo.toml", "\n[[bin]]\nname = 'outside'\npath = '../outside.rs'\n")
			writeFixture(t, root, "rust/outside.rs", "#![forbid(unsafe_code)]\nfn main() {}\n")
		}},
		{"multiline binary root is rejected", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/Cargo.toml", "\n[[bin]]\nname = 'inside'\npath = '''generated/main.rs'''\n")
			writeFixture(t, root, "rust/connection-core/generated/main.rs", "#![forbid(unsafe_code)]\nfn main() {}\n")
		}},
		{"custom manifest root is scanned", "AMBIENT_MACRO", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", `path = "src/lib.rs"`, `path = "generated/lib.rs"`)
			writeFixture(t, root, "rust/connection-core/generated/lib.rs", "#![forbid(unsafe_code)]\npub const VALUE: &str = env!(\"VALUE\");\n")
		}},
		{"path attribute source override", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\n#[path = \"../outside.rs\"] mod outside;\n")
			writeFixture(t, root, "rust/connection-core/outside.rs", "pub struct Outside;\n")
		}},
		{"conditional path attribute source override", "SOURCE_PATH_NOT_ALLOWED", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\n#[cfg_attr(all(), path = \"../outside.rs\")] mod outside;\n")
			writeFixture(t, root, "rust/connection-core/outside.rs", "pub struct Outside;\n")
		}},
		{"automatic binary target is scanned", "AMBIENT_MACRO", func(t *testing.T, root string) {
			writeFixture(t, root, "rust/connection-core/src/bin/ambient.rs", "#![forbid(unsafe_code)]\npub const VALUE: &str = env!(\"VALUE\");\n")
		}},
		{"reviewer macro indirection", "DECLARATIVE_MACRO_NOT_ALLOWED", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", `
macro_rules! indirect {
    ($macro_name:ident) => { pub const VALUE: &str = $macro_name!("data.txt"); };
}
indirect!(include_str);
`)
		}},
		{"benign declarative macro definition", "DECLARATIVE_MACRO_NOT_ALLOWED", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/src/lib.rs", "\nmacro_rules! local { () => {}; }\n")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := goodFixture(t)
			test.mutate(t, root)
			var stdout, stderr bytes.Buffer
			if code := run(verificationArguments(root), &stdout, &stderr); code != exitFindings {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitFindings, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), `"code": "`+test.code+`"`) {
				t.Fatalf("missing typed finding %s in %s", test.code, stdout.String())
			}
		})
	}
}

func TestVerifyAllowsRootConfinedLiteralSourcePaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"lib table", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", `path = "src/lib.rs"`, `path = 'generated/lib.rs'`)
			writeFixture(t, root, "rust/connection-core/generated/lib.rs", "#![forbid(unsafe_code)]\npub struct ConnectionCore;\n")
			removeFixture(t, root, "rust/connection-core/src/lib.rs")
		}},
		{"dotted lib key", func(t *testing.T, root string) {
			replaceFixture(t, root, "rust/connection-core/Cargo.toml", "[lib]\nname = \"websocket_core\"\npath = \"src/lib.rs\"\n\n", "")
			prependFixture(t, root, "rust/connection-core/Cargo.toml", "lib.name = 'websocket_core'\nlib.path = 'generated/lib.rs'\n")
			writeFixture(t, root, "rust/connection-core/generated/lib.rs", "#![forbid(unsafe_code)]\npub struct ConnectionCore;\n")
			removeFixture(t, root, "rust/connection-core/src/lib.rs")
		}},
		{"binary table", func(t *testing.T, root string) {
			appendFixture(t, root, "rust/connection-core/Cargo.toml", "\n[[bin]]\nname = 'inside'\npath = 'generated/main.rs'\n")
			writeFixture(t, root, "rust/connection-core/generated/main.rs", "#![forbid(unsafe_code)]\nfn main() {}\n")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := goodFixture(t)
			test.mutate(t, root)
			var stdout, stderr bytes.Buffer
			if code := run(verificationArguments(root), &stdout, &stderr); code != exitOK {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitOK, stdout.String(), stderr.String())
			}
		})
	}
}

func TestVerifyAllowsOnlyTheBoundedMPSCStdImport(t *testing.T) {
	root := goodFixture(t)
	writeFixture(t, root, "rust/connection-core/src/channel.rs", "use std::sync::mpsc;\n")

	var stdout, stderr bytes.Buffer
	if code := run(verificationArguments(root), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitOK, stdout.String(), stderr.String())
	}
}

func TestVerifyRejectsAncestorSymlinkEscapes(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"policy", "security"},
		{"toolchain receipt", "evidence"},
		{"workspace", "rust"},
		{"production source", "rust/connection-core/src"},
		{"installed toolchain", "toolchain/bin"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := goodFixture(t)
			original := filepath.Join(root, filepath.FromSlash(test.path))
			real := original + "-real"
			if err := os.Rename(original, real); err != nil {
				t.Fatalf("rename ancestor: %v", err)
			}
			if err := os.Symlink(real, original); err != nil {
				t.Fatalf("symlink ancestor: %v", err)
			}

			var stdout, stderr bytes.Buffer
			if code := run(verificationArguments(root), &stdout, &stderr); code != exitFindings {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitFindings, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), `"code": "UNSAFE_PATH"`) {
				t.Fatalf("missing UNSAFE_PATH finding: %s", stdout.String())
			}
		})
	}
}

func TestCargoCommandFailsClosedAndNeutralizesAmbientOverrides(t *testing.T) {
	t.Run("sanitized execution", func(t *testing.T) {
		root := goodFixture(t)
		t.Setenv("RUSTC", "/malicious/rustc")
		t.Setenv("RUSTC_WRAPPER", "/malicious/wrapper")
		t.Setenv("RUSTC_WORKSPACE_WRAPPER", "/malicious/workspace-wrapper")
		t.Setenv("RUSTFLAGS", "--malicious")
		t.Setenv("CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER", "/malicious/runner")

		arguments := cargoArguments(root, "metadata", "--offline")
		var stdout, stderr bytes.Buffer
		if code := run(arguments, &stdout, &stderr); code != exitOK {
			t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitOK, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "/malicious/") {
			t.Fatalf("ambient executable override reached Cargo: %s", stdout.String())
		}
		if !strings.Contains(stdout.String(), "CARGO_EXECUTED") ||
			!strings.Contains(stdout.String(), "RUSTC="+filepath.Join(root, "toolchain/bin/rustc")) {
			t.Fatalf("selected pinned toolchain was not executed: %s", stdout.String())
		}
	})

	t.Run("gate failure prevents execution", func(t *testing.T) {
		root := goodFixture(t)
		appendFixture(t, root, "rust/connection-core/src/lib.rs", "\nuse std::process;\n")

		var stdout, stderr bytes.Buffer
		if code := run(cargoArguments(root, "metadata", "--offline"), &stdout, &stderr); code != exitFindings {
			t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, exitFindings, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "CARGO_EXECUTED") {
			t.Fatalf("Cargo executed after a gate finding: %s", stdout.String())
		}
	})
}

func TestRustMakeGatesRouteCargoThroughRepositoryRustgate(t *testing.T) {
	command := exec.Command("make", "-n", "gates")
	command.Dir = filepath.Join("..", "..", "rust")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n gates: %v\n%s", err, output)
	}
	text := string(output)
	if count := strings.Count(text, "go run ./cmd/rustgate cargo"); count != 5 {
		t.Fatalf("rustgate cargo launcher count = %d, want 5:\n%s", count, text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "cargo ") {
			t.Fatalf("direct Cargo command bypasses rustgate: %s", line)
		}
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
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("canonicalize fixture root: %v", err)
	}
	root = canonicalRoot
	writeFixture(t, root, "LICENSE", "fixture Apache license\n")
	writeFixture(t, root, "rust/Cargo.toml", `[workspace]
resolver = "3"
members = ["connection-core", "websocket-driver"]

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
	writeFixture(t, root, "rust/websocket-driver/Cargo.toml", `[package]
name = "websocket-driver"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lib]
name = "websocket_driver"
path = "src/lib.rs"

[lints]
workspace = true

[dependencies]
websocket-core = { path = "../connection-core" }

[dev-dependencies]

[build-dependencies]
`)
	writeFixture(t, root, "rust/websocket-driver/src/lib.rs", `#![forbid(unsafe_code)]
pub struct ConnectionOwner;
`)
	writeFixture(t, root, "rust/connection-core/src/lib.rs", `#![forbid(unsafe_code)]
// std::net::TcpStream FnMut todo!() include!() env!() are inert fixture comments.
/* nested /* std::process::Command */ unimplemented!() include_bytes!() */
pub const TEXT: &str = "std::time::Instant, unimplemented!(), include_str!(), and option_env!() are inert strings";
pub const RAW: &str = r###"std::fs::File panic!() include!() env!()"###;
pub const BYTE: u8 = b'x';
pub struct ConnectionCore;
pub fn ordinary_local_path() { let path = 1; let _ = path; }
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

[[package]]
name = "websocket-driver"
version = "0.0.0"
dependencies = ["websocket-core"]
`
	writeFixture(t, root, "rust/Cargo.lock", lock)
	rustc := "#!/bin/sh\nexit 0\n"
	rustdoc := "#!/bin/sh\nexit 0\n# rustdoc\n"
	cargo := "#!/bin/sh\nprintf 'CARGO_EXECUTED\\nRUSTC=%s\\nRUSTDOC=%s\\nRUSTC_WRAPPER=%s\\nRUSTC_WORKSPACE_WRAPPER=%s\\nRUSTFLAGS=%s\\nCARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER=%s\\n' \"$RUSTC\" \"$RUSTDOC\" \"$RUSTC_WRAPPER\" \"$RUSTC_WORKSPACE_WRAPPER\" \"$RUSTFLAGS\" \"$CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER\"\n"
	writeExecutableFixture(t, root, "toolchain/bin/rustc", rustc)
	writeExecutableFixture(t, root, "toolchain/bin/rustdoc", rustdoc)
	writeExecutableFixture(t, root, "toolchain/bin/cargo", cargo)
	writeFixture(t, root, "evidence/intake/toolchain-pins.json", `{
  "schema_version":"1.0.0",
  "company":"fixture-company",
  "project":"fixture-project",
  "laboratory_id":"fixture-lab",
  "generated_at":"2026-08-24T12:26:43Z",
  "execution_state":"STATIC_INTAKE_ONLY",
  "qualification_sandbox":{"required_role":"port-implementer","requested_access":[],"forbidden_access":[],"disposable":true,"secrets":"none","publication":false},
  "executables":[{
    "artifact_id":"rustc-1.95.0-aarch64-apple-darwin",
    "platform":"aarch64-apple-darwin",
    "version":"1.95.0",
	"binary_digests":{"rustc/bin/rustc":"sha256:`+fixtureDigest([]byte(rustc))+`","rustc/bin/rustdoc":"sha256:`+fixtureDigest([]byte(rustdoc))+`","cargo/bin/cargo":"sha256:`+fixtureDigest([]byte(cargo))+`"},
    "lock_graph":["fixture@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],
    "sbom_component_id":"component-rust-fixture",
    "vulnerability_observation_id":"vuln-rust-fixture",
    "license":"Apache-2.0 OR MIT",
    "provenance":"fixture static qualification",
    "mirror_or_replay":"fixture replay",
    "expires_at":"2026-09-23T12:26:43Z",
    "rotation":"requalify",
    "revocation":"ACTIVE_AT_SNAPSHOT"
  }],
  "container":{"reference":"fixture","platform":"linux/amd64","manifest_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","config_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","compressed_layer_bytes":1,"floating_tag_satisfies_gate":false,"executed":false}
}`)
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

func verificationArguments(root string) []string {
	return []string{
		"verify",
		"--root", root,
		"--toolchain-bin-dir", filepath.Join(root, "toolchain/bin"),
		"--validation-time", "2026-08-26T00:00:00Z",
	}
}

func cargoArguments(root string, arguments ...string) []string {
	result := []string{
		"cargo",
		"--root", root,
		"--toolchain-bin-dir", filepath.Join(root, "toolchain/bin"),
		"--validation-time", "2026-08-26T00:00:00Z",
		"--",
	}
	return append(result, arguments...)
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

func writeExecutableFixture(t *testing.T, root, relative, body string) {
	t.Helper()
	writeFixture(t, root, relative, body)
	if err := os.Chmod(filepath.Join(root, filepath.FromSlash(relative)), 0o755); err != nil {
		t.Fatalf("chmod %s: %v", relative, err)
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

func prependFixture(t *testing.T, root, relative, prefix string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	writeFixture(t, root, relative, prefix+string(body))
}

func removeFixture(t *testing.T, root, relative string) {
	t.Helper()
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
		t.Fatalf("remove %s: %v", relative, err)
	}
}

func fixtureDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
