#!/bin/bash
# Literal replay of the US-019 provenance run, us019-prov-20260828T183623Z.
#
# Paste this on a workstation with the dev AWS profile. It reproduces the host,
# the image, the tree, and the four sweeps in the order they were executed.
# Every digest below was read off the run it describes, not copied from a plan.
set -euo pipefail
export AWS_PROFILE=dev-sso AWS_REGION=us-east-1

COMMIT=518b77aa3ecdc180c832a0d988adf498d687e1b8                       # tree under test
IMAGE=crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074
AMI=ami-02b3d83d84b07786d              # al2023 x86_64, the AMI this run booted
INSTANCE_TYPE=c7i.xlarge
ADAPTER_DIGEST=sha256:98ca1c7fdb5584386ff87bf993d962f9d4aa68ed1fbb5340558a5b0e93a3c95a       # built here from AutobahnEndpoint.java
WS_TESTEE_SHA256=4f0d1c37badee36d1d3862ff533b01a9a703d44b8af9958f4134048cb2065342         # built here from $COMMIT

git -C <worktree> checkout $COMMIT
# 1. Launch: see steps/00-launch.sh in this replay bundle for the exact
#    run-instances call, IAM, egress-only SG and S3 transfer bucket.
# 2. Deliver the tree as a tarball and run these, in order, over SSM
#    RunShellScript, each one's host exit status read from
#    GetCommandInvocation.ResponseCode:
       00-launch.sh
       01-deadman.sh
       02-bootstrap.sh
       03-build.sh
       04-provenance-pre.sh
       05-leg-rust-fuzzingclient.sh
       06-leg-rust-fuzzingserver.sh
       07-leg-java-fuzzingclient.sh
       08-leg-java-fuzzingserver.sh
       09-finalize.sh
       10-teardown.sh
# 3. Pull s3://vjwp-us019-prov-539402214167/out/us019-prov-20260828T183623Z-evidence.tgz and verify it against the
#    published .sha256 before unpacking.
# 4. Terminate the instance and delete the IAM role, instance profile, security
#    group and bucket.
