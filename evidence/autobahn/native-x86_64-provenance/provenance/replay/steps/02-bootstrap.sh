#!/bin/bash
# US-019 provenance re-run: host bootstrap. Fail loudly on the first real error.
set -euo pipefail

ATTEMPT="us019-prov-20260828T183623Z"
BUCKET="vjwp-us019-prov-539402214167"
PAYLOAD_SHA="967caaefdc6fe655057dfebe799f085f50a04c94b6b54b428eb54eccc2736aac"
HOSTFACTS_SHA="df2e174671ba70a8acc4fcab7a3df3b8d767535a4716e0feadc69d625e0dc166"
PROVCAP_SHA="7e5d1a4ed7d23a9085e2b75aba1cf5174cb9788e22493948b8312492219c1744"
AUTOBAHN_IMAGE="crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074"

echo "=== ARCH SELF-REPORT (read off this machine) ==="
uname -m
uname -a

echo "=== PACKAGES ==="
# gcc is installed here rather than at build time: cargo needs a linker and
# discovering that mid-build costs a round trip.
dnf install -y docker git tar gzip which gcc python3 java-17-amazon-corretto-devel >/dev/null
systemctl enable --now docker
docker version --format '{{.Server.Version}}'
gcc --version | head -1
java -version 2>&1 | head -1

echo "=== GO 1.25.5 ==="
curl -fsSL -o /tmp/go.tgz https://go.dev/dl/go1.25.5.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tgz
/usr/local/go/bin/go version

echo "=== RUST (rust-toolchain.toml pins 1.95.0) ==="
export RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo
curl -fsSL --proto '=https' --tlsv1.2 https://sh.rustup.rs -o /tmp/rustup.sh
sh /tmp/rustup.sh -y --no-modify-path --default-toolchain 1.95.0 --profile minimal >/dev/null
/opt/cargo/bin/rustc --version
/opt/cargo/bin/cargo --version

echo "=== PAYLOAD TRANSFER (digest verified inbound) ==="
mkdir -p /opt/vjwp "/opt/vjwp/capture/$ATTEMPT"
aws s3 cp "s3://$BUCKET/in/vjwp-payload.tgz" /tmp/vjwp-payload.tgz
echo "$PAYLOAD_SHA  /tmp/vjwp-payload.tgz" | sha256sum -c -
tar -C /opt/vjwp -xzf /tmp/vjwp-payload.tgz

echo "=== CAPTURE TOOLING (digest verified inbound) ==="
aws s3 cp "s3://$BUCKET/in/hostfacts-linux-amd64" /usr/local/bin/hostfacts
echo "$HOSTFACTS_SHA  /usr/local/bin/hostfacts" | sha256sum -c -
chmod +x /usr/local/bin/hostfacts
aws s3 cp "s3://$BUCKET/in/provcap-linux-amd64" /usr/local/bin/provcap
echo "$PROVCAP_SHA  /usr/local/bin/provcap" | sha256sum -c -
chmod +x /usr/local/bin/provcap

echo "=== RUN STEPS (the replay bundle; digest of what actually arrived) ==="
aws s3 cp "s3://$BUCKET/in/run-steps.tgz" /tmp/run-steps.tgz
sha256sum /tmp/run-steps.tgz
rm -rf /opt/vjwp/run-steps && mkdir -p /opt/vjwp/run-steps
tar -C /opt/vjwp/run-steps -xzf /tmp/run-steps.tgz
sha256sum /opt/vjwp/run-steps/*.sh

echo "=== MANIFEST DIGEST ON HOST ==="
sha256sum /opt/vjwp/autobahn/case-manifest.json

echo "=== AUTOBAHN IMAGE, PULLED BY MANIFEST DIGEST ==="
docker pull "$AUTOBAHN_IMAGE"
docker image inspect "$AUTOBAHN_IMAGE" \
  --format 'id={{.Id}} arch={{.Architecture}} os={{.Os}} layers={{len .RootFS.Layers}}'
docker image inspect "$AUTOBAHN_IMAGE" --format 'repo_digests={{.RepoDigests}}'

echo "BOOTSTRAP_OK"
