#!/bin/bash
# US-019 provenance re-run: provision the single host both jobs run on.
#
# Every resource is tagged before it can be orphaned, and every id is appended
# to the resource ledger the moment AWS returns it, so teardown has a complete
# list even if this script dies partway through.
set -euo pipefail

export AWS_PROFILE=dev-sso
export AWS_REGION=us-east-1

W=/Users/mikelady/hq/workspace/worktrees/vjwp-claude-native-run/.runlog/us019-rerun
ATTEMPT="us019-prov-20260828T183623Z"
BUCKET="vjwp-us019-prov-539402214167"
ROLE="vjwp-us019-prov-host"
SGNAME="vjwp-us019-prov"
VPC="vpc-0ce04bd8c69528db1"
SUBNET="subnet-08c6289c316afcf96"
AMI="ami-02b3d83d84b07786d"
ITYPE="c7i.xlarge"
LEDGER="$W/out/resources.env"

TAGS_CLI="Key=Project,Value=vjwp Key=Purpose,Value=us019-ac1-ac5-provenance Key=Plane,Value=claude Key=ManagedBy,Value=agent Key=AttemptId,Value=$ATTEMPT Key=Workspace,Value=vjwp"
TAGS_SPEC="{Key=Project,Value=vjwp},{Key=Purpose,Value=us019-ac1-ac5-provenance},{Key=Plane,Value=claude},{Key=ManagedBy,Value=agent},{Key=AttemptId,Value=$ATTEMPT},{Key=Workspace,Value=vjwp},{Key=Name,Value=vjwp-us019-prov}"

note() { echo "$1" >> "$LEDGER"; echo "LEDGER += $1"; }

mkdir -p "$W/out"
: > "$LEDGER"
note "ATTEMPT=$ATTEMPT"
note "REGION=$AWS_REGION"
echo "LAUNCH_SEQUENCE_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "=== IAM ROLE + INSTANCE PROFILE (SSM only; no SSH key is ever created) ==="
cat > "$W/out/trust.json" <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
aws iam create-role --role-name "$ROLE" \
  --assume-role-policy-document "file://$W/out/trust.json" \
  --tags $TAGS_CLI >/dev/null
note "ROLE=$ROLE"
aws iam attach-role-policy --role-name "$ROLE" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
note "ROLE_MANAGED_POLICY=arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
aws iam create-instance-profile --instance-profile-name "$ROLE" --tags $TAGS_CLI >/dev/null
note "INSTANCE_PROFILE=$ROLE"
aws iam add-role-to-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE"

echo "=== S3 TRANSFER BUCKET ==="
aws s3api create-bucket --bucket "$BUCKET" --region "$AWS_REGION" >/dev/null
note "BUCKET=$BUCKET"
aws s3api put-bucket-tagging --bucket "$BUCKET" \
  --tagging "TagSet=[{Key=Project,Value=vjwp},{Key=Purpose,Value=us019-ac1-ac5-provenance},{Key=Plane,Value=claude},{Key=ManagedBy,Value=agent},{Key=AttemptId,Value=$ATTEMPT}]"
cat > "$W/out/s3policy.json" <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:ListBucket","s3:DeleteObject"],"Resource":["arn:aws:s3:::$BUCKET","arn:aws:s3:::$BUCKET/*"]}]}
EOF
aws iam put-role-policy --role-name "$ROLE" --policy-name transfer-bucket \
  --policy-document "file://$W/out/s3policy.json"
note "ROLE_INLINE_POLICY=transfer-bucket"

echo "=== UPLOAD INPUTS ==="
aws s3 cp "$W/out/vjwp-payload.tgz"       "s3://$BUCKET/in/vjwp-payload.tgz" --quiet
aws s3 cp "$W/bin/hostfacts-linux-amd64"  "s3://$BUCKET/in/hostfacts-linux-amd64" --quiet
aws s3 cp "$W/bin/provcap-linux-amd64"    "s3://$BUCKET/in/provcap-linux-amd64" --quiet
aws s3 cp "$W/out/run-steps.tgz"          "s3://$BUCKET/in/run-steps.tgz" --quiet
aws s3 ls "s3://$BUCKET/in/"

echo "=== EGRESS-ONLY SECURITY GROUP (no ingress rule is ever authorized) ==="
SGID=$(aws ec2 create-security-group --group-name "$SGNAME" \
  --description "US-019 provenance conformance host, egress only" --vpc-id "$VPC" \
  --tag-specifications "ResourceType=security-group,Tags=[$TAGS_SPEC]" \
  --query GroupId --output text)
note "SGID=$SGID"
aws ec2 revoke-security-group-egress --group-id "$SGID" \
  --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' >/dev/null
aws ec2 authorize-security-group-egress --group-id "$SGID" --ip-permissions \
  '[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"SSM, S3, image and package pulls"}]},{"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"dnf repos"}]}]' >/dev/null
aws ec2 describe-security-groups --group-ids "$SGID" \
  --query 'SecurityGroups[].{Ingress:IpPermissions,Egress:IpPermissionsEgress}' --output json

echo "=== LAUNCH ==="
echo "LAUNCH_REQUESTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# The instance profile is eventually consistent after creation; a launch that
# races it fails with an invalid-profile error rather than anything subtle.
sleep 12
aws ec2 run-instances \
  --image-id "$AMI" \
  --instance-type "$ITYPE" \
  --subnet-id "$SUBNET" \
  --security-group-ids "$SGID" \
  --iam-instance-profile "Name=$ROLE" \
  --associate-public-ip-address \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":40,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --tag-specifications "ResourceType=instance,Tags=[$TAGS_SPEC]" \
    "ResourceType=volume,Tags=[$TAGS_SPEC]" "ResourceType=network-interface,Tags=[$TAGS_SPEC]" \
  --count 1 --output json > "$W/out/run-instances.json"

IID=$(python3 -c "import json;print(json.load(open('$W/out/run-instances.json'))['Instances'][0]['InstanceId'])")
note "INSTANCE_ID=$IID"
LAUNCH_TIME=$(python3 -c "import json;print(json.load(open('$W/out/run-instances.json'))['Instances'][0]['LaunchTime'])")
note "LAUNCH_TIME=$LAUNCH_TIME"

echo "=== DEAD-MAN SWITCH (shutdown terminates rather than stopping) ==="
aws ec2 modify-instance-attribute --instance-id "$IID" \
  --instance-initiated-shutdown-behavior Value=terminate
aws ec2 describe-instance-attribute --instance-id "$IID" \
  --attribute instanceInitiatedShutdownBehavior --output json

echo "=== WAIT RUNNING ==="
aws ec2 wait instance-running --instance-ids "$IID"
aws ec2 describe-instances --instance-ids "$IID" \
  --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,AZ:Placement.AvailabilityZone,Ami:ImageId,Arch:Architecture,Vol:BlockDeviceMappings[0].Ebs.VolumeId,Eni:NetworkInterfaces[0].NetworkInterfaceId}' \
  --output json > "$W/out/provision-record.json"
cat "$W/out/provision-record.json"

VOL=$(python3 -c "import json;print(json.load(open('$W/out/provision-record.json'))[0]['Vol'])")
ENI=$(python3 -c "import json;print(json.load(open('$W/out/provision-record.json'))[0]['Eni'])")
note "VOLUME_ID=$VOL"
note "ENI_ID=$ENI"

echo "LAUNCH_OK instance=$IID"
