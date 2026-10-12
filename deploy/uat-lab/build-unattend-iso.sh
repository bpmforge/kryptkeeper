#!/bin/bash
# Build a per-VM unattend ISO on macOS from the templates, filling secrets from
# ~/.config/kryptkeeper-lab/secrets.env. Output stays in ~/.config/kryptkeeper-lab (0700).
# usage: build-unattend-iso.sh <role: dc01|win11> <computer-name> <image-name> <product-key> <autologon-user>
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); role=$1
set -a; . ~/.config/kryptkeeper-lab/secrets.env; set +a
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/kk"
fill() { python3 - "$@" <<'PY'
import os,sys
s=open(sys.argv[1]).read()
for k,v in {"__IMAGE_NAME__":sys.argv[3],"__PRODUCT_KEY__":sys.argv[4],"__COMPUTER_NAME__":sys.argv[5],
            "__AUTOLOGON_USER__":sys.argv[6],"__ADMIN_PW__":os.environ["KK_LAB_ADMIN_PW"],
            "__DSRM_PW__":os.environ["KK_LAB_DSRM_PW"],"__USER_PW__":os.environ["KK_LAB_USER_PW"],
            "__DC_IP__":os.environ.get("KK_LAB_DC_IP","")}.items():
    s=s.replace(k,v)
open(sys.argv[2],"w").write(s)
PY
}
fill "$here/autounattend.xml.tmpl" "$work/autounattend.xml" "$3" "$4" "$2" "$5"
cat "$here/firstlogon.ps1" "$here/$role-tail.ps1" > "$work/kk/firstlogon.tmpl"
fill "$work/kk/firstlogon.tmpl" "$work/kk/firstlogon.ps1" "$3" "$4" "$2" "$5"; rm "$work/kk/firstlogon.tmpl"
out=~/.config/kryptkeeper-lab/kk-$role-unattend.iso; rm -f "$out"
hdiutil makehybrid -quiet -iso -joliet -default-volume-name KKUNATTEND -o "$out" "$work"
chmod 600 "$out"; echo "$out"
