#!/bin/bash
# Boots the kryptkeeper Hub on first launch. Runs as root via cloud-init.
#
# Assumes Amazon Linux 2023 (the AMI this module's data.aws_ami filter
# selects): dnf as the package manager, AWS CLI v2 preinstalled. Adapt this
# script if you point compute/main.tf at a different AMI.
#
# Both secret-fetch waits below are real, not defensive theater: the two
# Secrets Manager reads and this instance's IAM role policies are separate
# resources from the instance itself, so Terraform can start user_data
# running before either is actually attached/propagated. The app secret's
# VALUE is additionally written by the operator out of band (never by
# Terraform, which would put it in state: IAC-002), so that wait is long.
#
# The container itself runs under a real systemd unit (kryptkeeper.service,
# written below), not a bare `docker run -d --restart unless-stopped`. That
# unit's RequiresMountsFor=/var/kryptkeeper blocks it from starting -- on
# this boot or any later one -- until the dedicated data volume is actually
# mounted, so a slow EBS reattach after a host reboot fails the unit instead
# of silently launching the container against an empty directory and
# minting a fresh keystore/CA state (D-092: disk loss must not be silent).
set -euo pipefail

DATA_DIR=/var/kryptkeeper
BY_ID="/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${data_volume_id}"

DATA_DEV=""
for _ in $(seq 1 60); do
  if [ -e "$BY_ID" ]; then
    DATA_DEV=$(readlink -f "$BY_ID")
    break
  fi
  # Fallback for non-Nitro instance types, where EBS attaches as the
  # requested /dev/sdf name (surfaced to the guest kernel as xvdf).
  if [ -b /dev/xvdf ]; then
    DATA_DEV=/dev/xvdf
    break
  fi
  sleep 5
done
if [ -z "$DATA_DEV" ]; then
  echo "kryptkeeper user_data: data volume never appeared, giving up" >&2
  exit 1
fi

if ! blkid "$DATA_DEV" >/dev/null 2>&1; then
  mkfs.ext4 "$DATA_DEV"
fi
mkdir -p "$DATA_DIR"
mount "$DATA_DEV" "$DATA_DIR"
# Keyed by filesystem UUID, not the kernel device name: NVMe device
# enumeration order on Nitro instance types is not guaranteed stable across
# reboots (the very reason this script looks the volume up via
# /dev/disk/by-id/ above), so /dev/nvme1n1 today could be /dev/nvme2n1 next
# boot and silently mismatch a device-keyed fstab entry.
#
# Deliberately no `nofail`: that flag drops this mount from local-fs.target's
# hard Requires=, so on a later boot there would be no ordering guarantee
# that it completes before docker.service (and this instance's
# kryptkeeper.service) start. Without nofail, a not-yet-attached volume
# fails the boot loudly instead of the container silently running against
# an empty /var/kryptkeeper.
DATA_UUID=$(blkid -s UUID -o value "$DATA_DEV")
grep -q " $DATA_DIR " /etc/fstab || echo "UUID=$DATA_UUID $DATA_DIR ext4 defaults 0 2" >> /etc/fstab
mkdir -p "$DATA_DIR/keys" "$DATA_DIR/data"
# The image runs as distroless nonroot (uid/gid 65532); a root-owned mount
# would not be writable by it.
chown 65532:65532 "$DATA_DIR/keys" "$DATA_DIR/data"
chmod 0700 "$DATA_DIR/keys"

dnf install -y docker jq
systemctl enable --now docker

DB_SECRET_JSON=""
for _ in $(seq 1 30); do
  if DB_SECRET_JSON=$(aws secretsmanager get-secret-value \
    --secret-id '${db_secret_arn}' \
    --region '${region}' \
    --query SecretString --output text 2>/dev/null); then
    break
  fi
  sleep 10
done
if [ -z "$DB_SECRET_JSON" ]; then
  echo "kryptkeeper user_data: could not read the database secret after retrying, giving up" >&2
  exit 1
fi
# URL-encoded: the RDS-generated password may contain URL-reserved characters.
DB_PASSWORD=$(echo "$DB_SECRET_JSON" | jq -r '.password | @uri')

APP_SECRET_JSON=""
for _ in $(seq 1 180); do
  if APP_SECRET_JSON=$(aws secretsmanager get-secret-value \
    --secret-id '${app_secret_arn}' \
    --region '${region}' \
    --query SecretString --output text 2>/dev/null); then
    break
  fi
  sleep 10
done
if [ -z "$APP_SECRET_JSON" ]; then
  echo "kryptkeeper user_data: could not read the app secret after retrying (has 'aws secretsmanager put-secret-value' been run for ${app_secret_arn}?), giving up" >&2
  exit 1
fi
APP_BOOTSTRAP_TOKEN=$(echo "$APP_SECRET_JSON" | jq -r '.app_bootstrap_token // empty')
KEYSTORE_PASSPHRASE=$(echo "$APP_SECRET_JSON" | jq -r '.keystore_passphrase // empty')
# The bootstrap token is a network credential; the passphrase is the at-rest
# key for CA private keys. They must be independent values (IAC-003).
if [ -z "$APP_BOOTSTRAP_TOKEN" ] || [ -z "$KEYSTORE_PASSPHRASE" ]; then
  echo "kryptkeeper user_data: app secret must contain non-empty app_bootstrap_token and keystore_passphrase, giving up" >&2
  exit 1
fi
if [ "$APP_BOOTSTRAP_TOKEN" = "$KEYSTORE_PASSPHRASE" ]; then
  echo "kryptkeeper user_data: keystore_passphrase must differ from app_bootstrap_token, giving up" >&2
  exit 1
fi

%{ if tls_secret_arn != "" ~}
# Operator-supplied listener certificate (tls_cert_secret_arn). Group 65532
# so the nonroot container can read the key; nothing else can.
TLS_SECRET_JSON=""
for _ in $(seq 1 30); do
  if TLS_SECRET_JSON=$(aws secretsmanager get-secret-value \
    --secret-id '${tls_secret_arn}' \
    --region '${region}' \
    --query SecretString --output text 2>/dev/null); then
    break
  fi
  sleep 10
done
if [ -z "$TLS_SECRET_JSON" ]; then
  echo "kryptkeeper user_data: could not read the TLS certificate secret after retrying, giving up" >&2
  exit 1
fi
install -d -m 0750 -g 65532 /etc/kryptkeeper/tls
echo "$TLS_SECRET_JSON" | jq -er .certificate_pem > /etc/kryptkeeper/tls/tls.crt
echo "$TLS_SECRET_JSON" | jq -er .private_key_pem > /etc/kryptkeeper/tls/tls.key
chgrp 65532 /etc/kryptkeeper/tls/tls.crt /etc/kryptkeeper/tls/tls.key
chmod 0640 /etc/kryptkeeper/tls/tls.crt /etc/kryptkeeper/tls/tls.key
%{ endif ~}

# Written once, root-only (0600): kryptkeeper.service reads this as an
# EnvironmentFile so neither secret ever appears in this script (which EC2
# user data exposes in plaintext to any IAM principal with
# ec2:DescribeInstanceAttribute on the instance) or in `docker run`'s argv
# (visible to anything reading `ps`).
install -d -m 0755 /etc/kryptkeeper
cat > /etc/kryptkeeper/kryptkeeper.env <<ENVEOF
DATABASE_URL=postgres://${db_username}:$DB_PASSWORD@${db_endpoint}/${db_name}?sslmode=require
APP_BOOTSTRAP_TOKEN=$APP_BOOTSTRAP_TOKEN
KRYPTKEEPER_KEYSTORE_PASSPHRASE=$KEYSTORE_PASSPHRASE
ENVEOF
chmod 0600 /etc/kryptkeeper/kryptkeeper.env

cat > /etc/systemd/system/kryptkeeper.service <<UNITEOF
[Unit]
Description=kryptkeeper Hub container
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target
RequiresMountsFor=$DATA_DIR

[Service]
Type=simple
EnvironmentFile=/etc/kryptkeeper/kryptkeeper.env
Environment=AUTH_MODE=bootstrap APP_BIND_ADDR=0.0.0.0 PORT=${app_port} KRYPTKEEPER_DB_MODE=postgres KRYPTKEEPER_KEYSTORE_DIR=/var/kryptkeeper/keys KRYPTKEEPER_DATA_DIR=/var/kryptkeeper/data APP_TEMPLATE_FILE=/var/kryptkeeper/data/templates.json
# TLS (IAC-001): the CA engine must be on for the Hub to serve TLS without an
# operator-supplied pair. KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT only acts when no
# CA exists yet, so it is safe to leave set. Clients must trust the Hub CA
# (ca.pem under the data volume's tls/ directory) or the operator cert's CA.
Environment=APP_CERTIFICATE_PROVIDER=ca KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT=true KRYPTKEEPER_BASE_URL=${base_url} KRYPTKEEPER_TLS_SANS=${tls_sans}
%{ if tls_secret_arn != "" ~}
Environment=KRYPTKEEPER_TLS_CERT_FILE=/etc/kryptkeeper/tls/tls.crt KRYPTKEEPER_TLS_KEY_FILE=/etc/kryptkeeper/tls/tls.key
%{ else ~}
Environment=KRYPTKEEPER_TLS_SELF_ISSUE=true
%{ endif ~}
ExecStartPre=-/usr/bin/docker rm -f kryptkeeper
ExecStart=/usr/bin/docker run --rm --name kryptkeeper \\
  --read-only \\
  --tmpfs /tmp \\
  --cap-drop ALL \\
  --security-opt no-new-privileges:true \\
  -p ${app_port}:${app_port} \\
  -e AUTH_MODE \\
  -e APP_BOOTSTRAP_TOKEN \\
  -e APP_BIND_ADDR \\
  -e PORT \\
  -e KRYPTKEEPER_DB_MODE \\
  -e DATABASE_URL \\
  -e KRYPTKEEPER_KEYSTORE_PASSPHRASE \\
  -e KRYPTKEEPER_KEYSTORE_DIR \\
  -e KRYPTKEEPER_DATA_DIR \\
  -e APP_TEMPLATE_FILE \\
  -e APP_CERTIFICATE_PROVIDER \\
  -e KRYPTKEEPER_BOOTSTRAP_CREATE_ROOT \\
  -e KRYPTKEEPER_BASE_URL \\
  -e KRYPTKEEPER_TLS_SANS \\
%{ if tls_secret_arn != "" ~}
  -e KRYPTKEEPER_TLS_CERT_FILE \\
  -e KRYPTKEEPER_TLS_KEY_FILE \\
  -v /etc/kryptkeeper/tls:/etc/kryptkeeper/tls:ro \\
%{ else ~}
  -e KRYPTKEEPER_TLS_SELF_ISSUE \\
%{ endif ~}
  -v $DATA_DIR/keys:/var/kryptkeeper/keys \\
  -v $DATA_DIR/data:/var/kryptkeeper/data \\
  '${image_repository}@${image_digest}'
ExecStop=/usr/bin/docker stop kryptkeeper
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable --now kryptkeeper.service
