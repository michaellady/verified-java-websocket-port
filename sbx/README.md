# Docker SBX agent lanes

Status: **reviewable configuration only; every launch profile is blocked**.
Nothing in this directory authorizes creation or execution of a sandbox.

## Current host state

The installed CLI and daemon are Docker SBX `v0.39.0`. Homebrew also reports
`0.39.0` as the current stable cask, so there is no stable update to install.
The `0.42.0-rc4` preview is not installed because it is a release candidate and
changes TCP behavior. This project requires a stable release containing the
0.42 isolation fixes before it will run untrusted agent work.

The existing `claude-mikelady` sandbox is stopped. It uses the older
`claude-code-docker@sha256:ae8a46a105752b6d8937d4000f2058e8379af51aebffc2881618ceef7914f639`
image, mounts all of `/Users/mikelady`, exposes the proxy/MCP integration and an
imported secret marker, and lacks Maven, Rust, Cargo, Kani, CBMC, and Charon. It
is not an acceptable Java-to-Rust lane. There is no existing native Codex SBX
sandbox. The stopped generic shell sandboxes also lack the complete pinned
toolchain. Existing sandboxes must remain stopped and must not be repurposed.

The host has a registered local stdio `node_repl` MCP server. Docker runs local
stdio MCP servers on the host side of the microVM boundary. The Codex and Claude
profiles therefore retain `HOST_STDIO_MCP_DENY_UNVERIFIED` until either an
organization MCP policy forbids `resource.type == "local-stdio"` at use time or
Docker provides and we probe an explicit empty-static-gateway mode. Merely
omitting `--static-mcp` is not sufficient because omission selects dynamic MCP
mode.

## Repository-owned design

- `PORTING_CONTRACT.md` is the common work and claim contract.
- `kits/port-contract` is one schema-v2 mixin shared by Muse Code, Codex, and
  Claude. It supplies the contract reminder and only the dependency hosts used
  by the repository bootstrap.
- `kits/muse-code` is the missing third-agent integration. It pins Meta Muse
  Code `1.0.2-R2040.1` by URL, byte count, and SHA-256 on Linux arm64 and amd64.
  It keeps Muse's inner approvals and contained-execution sandbox enabled.
- `profiles.json` binds all six agent/lane combinations to exact image-index and
  platform-manifest digests observed from Docker Hub on 2026-09-03. Sandbox and
  cache names are unique; clone mode, no shared skills, no host stdio MCP, no
  static MCP servers, and no published ports are closed invariants. The catalog
  also binds the complete file closure of both composed kits by SHA-256 and
  rejects unlisted files and symlinks.
- `cmd/sbxprofilectl` validates those invariants and prints candidate launch
  commands. It has no code path that calls `sbx` or mutates sandbox state.

The Muse kit adapts the independently reviewed staging helper as source. It
tests and builds that helper inside the exact pinned base image, then the helper
performs bounded download, exact size and SHA-256 verification, fsync, and
atomic publication. The unsigned staging binaries are deliberately not copied
into the repository.

The kit-v2 network policy is not phase-scoped. Consequently the Meta download
host remains allowed after installation. A production profile must instead use
a controlled Linux build to bake Muse into a signed, SBOM-attached,
digest-pinned image with no runtime download-host permission.

## Architecture split

Linux arm64 is development-only. The current repository bootstrap intentionally
rejects it because the accepted Temurin JDK, CBMC package, and Kani closure are
Linux amd64. Arm64 work may edit and run locally proven checks, but it cannot
satisfy Java-oracle or formal acceptance.

Linux amd64 is the authoritative verification lane. All three agents use the
same existing bootstrap rather than embedding a second toolchain installer:

```sh
GOTOOLCHAIN=auto go run ./cmd/cloudsetup setup --root "$PWD" --home "$HOME"
```

The bootstrap pins Go 1.25.5, JDK 17.0.19, Maven 3.9.11, Rust 1.95.0, the Kani
nightly and Kani 0.67.0 source identity, and CBMC 6.11.0. The agent must then run
the canonical repository gates in `AGENTS.md` and obey the no-Autobahn and
claim-ceiling rules in `PORTING_CONTRACT.md`.

## Future launch commands

Run only from the repository's main checkout because Docker clone mode rejects
a linked Git worktree. The main checkout must first be on the exact branch or
commit the agent should clone. These commands remain blocked until every
profile's recorded blockers are resolved and revalidated.

```sh
sbx run --clone --no-share-skills --kit sbx/kits/port-contract --name vjwp-codex-arm64-dev --template docker.io/docker/sandbox-templates:codex-docker@sha256:f2fa53ce37ddcc8693921eb972040a28f8e30e12cefa7e3c6c3bb0eef70e95da codex .
```

```sh
sbx run --clone --no-share-skills --kit sbx/kits/port-contract --name vjwp-claude-arm64-dev --template docker.io/docker/sandbox-templates:claude-code-docker@sha256:3b0287cd3d831cda197fc903afe731cf616e3614214dc0c0938d52ba46db41fb claude .
```

```sh
sbx run --clone --no-share-skills --kit sbx/kits/muse-code --kit sbx/kits/port-contract --name vjwp-muse-arm64-dev muse-code .
```

The corresponding authoritative commands use a Linux amd64 host:

```sh
sbx run --clone --no-share-skills --kit sbx/kits/port-contract --name vjwp-codex-amd64-formal --template docker.io/docker/sandbox-templates:codex-docker@sha256:4478aac4b542421404a5a5c860164f88c42c201e8730c1f3174c8d749f781703 codex .
```

```sh
sbx run --clone --no-share-skills --kit sbx/kits/port-contract --name vjwp-claude-amd64-formal --template docker.io/docker/sandbox-templates:claude-code-docker@sha256:2ce248aa988a9c6bf1464eb517559ef946a17a1a102d584eddc24246bd7d301c claude .
```

```sh
sbx run --clone --no-share-skills --kit sbx/kits/muse-code --kit sbx/kits/port-contract --name vjwp-muse-amd64-formal muse-code .
```

The Codex and Claude commands deliberately preserve Docker's built-in
outer-sandbox execution semantics rather than replacing their entrypoints.
Their model credentials stay behind Docker's host proxy. Muse is different: its
inner approval and sandbox remain enabled, and no credential or inference host
is configured until a real authenticated probe establishes the service name,
environment variable, HTTP host, header shape, and account-retention policy.

## Static validation

These commands are safe on SBX 0.39 because they do not create a sandbox:

```sh
go run ./cmd/sbxprofilectl verify --root .
sbx kit validate sbx/kits/port-contract
sbx kit validate sbx/kits/muse-code
go test ./cmd/sbxprofilectl -count=1
go test -C sbx/kits/muse-code/files/home/.local/src/muse-fetch ./... -count=1
```

On 2026-09-03, a bounded Docker probe of the exact pinned shell-image index
resolved to Linux arm64 with Go 1.26.0 at `/usr/bin/go`; `/home/agent`, `/tmp`,
and `/usr/local/bin` were on a writable overlay with more than 900 GB free. The
bundled Muse downloader both tested and built inside that image. A second probe
of the recorded Linux amd64 manifest ran the repository's `internal/portplan`
tests with the cached, digest-pinned Temurin 17.0.19 distribution. These probes
validate the build assumptions only. They are not SBX agent launches and do not
clear any launch blocker.

Render any exact candidate command without executing it:

```sh
go run ./cmd/sbxprofilectl show-command --root . --id muse-amd64-formal
```
