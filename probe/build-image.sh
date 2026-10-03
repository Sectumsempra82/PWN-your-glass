#!/bin/bash
# Prepare an image file only; flashing is a separate, explicitly targeted step.
set -euo pipefail
source_dir=$(realpath "$1")
metadata=$(realpath "$2")
config=$(realpath "$3")
build_dir=$(realpath -m "$4")
[[ $EUID -eq 0 ]] || { echo 'Run as root in Linux/WSL'; exit 1; }
[[ "$build_dir" != /dev && "$build_dir" != /dev/* ]] || exit 1
mkdir -p "$build_dir"
mkdir -p "$source_dir/private/probe"
image="$build_dir/glass-probe.img"
[[ ! -e "$image" && ! -e "$image.xz" ]] || { echo 'Choose a fresh build directory'; exit 1; }
mapfile -t fields < <(python3 - "$metadata" <<'PY'
import json, sys
from urllib.parse import urlsplit
data = json.load(open(sys.argv[1]))
url = urlsplit(data['url'])
assert url.scheme == 'https' and url.hostname == 'downloads.raspberrypi.com'
assert '/raspios_lite_arm64/' in url.path
assert len(data['extract_sha256']) == 64
print(data['url'])
print(data['extract_sha256'])
PY
)
[[ ${#fields[@]} == 2 ]] || exit 1
curl --fail --location --retry 3 --output "$image.xz" "${fields[0]}"
xz --decompress --keep "$image.xz"
printf '%s  %s\n' "${fields[1]}" "$image" | sha256sum --check
start=$(python3 - "$image" <<'PY'
import struct, sys
with open(sys.argv[1], 'rb') as f:
    mbr = f.read(512)
assert mbr[510:] == b'\x55\xaa'
partition = mbr[462:478]
assert partition[4] == 0x83
print(struct.unpack_from('<I', partition, 8)[0])
PY
)
truncate -s 8G "$image"
printf '%s,+,83\n' "$start" | sfdisk --no-reread -N 2 "$image"
loop=$(losetup --find --show --partscan "$image")
trap 'losetup -d "$loop"' EXIT
e2fsck -pf "${loop}p2" || [[ $? == 1 ]]
resize2fs "${loop}p2"
losetup -d "$loop"
trap - EXIT
bash "$source_dir/probe/install-image.sh" "$image" "$source_dir" "$config"
bash "$source_dir/probe/validate-image.sh" "$image" "$source_dir"
sha256sum "$image" > "$image.sha256"
echo "Built and validated: $image"
