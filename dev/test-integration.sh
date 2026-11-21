#!/usr/bin/env bash
set -euo pipefail

case "${PDNS_VERSION:-5.1}" in
  5.0) image=powerdns/pdns-auth-50@sha256:400bbb64be946974c174a07fb439f234cc12ff65c5d807f2f1c2884d89436a8c ;;
  5.1) image=powerdns/pdns-auth-51@sha256:c0de11726bc54014f8df855ec4cadc988443280804ddd733f982b9c0eb9884dc ;;
  *) echo 'PDNS_VERSION must be 5.0 or 5.1' >&2; exit 2 ;;
esac

export IZENA_PDNS_IMAGE="$image"
export IZENA_PDNS_API_KEY="$(openssl rand -hex 24)"
export IZENA_PDNS_PRIMARY_IP="${IZENA_PDNS_PRIMARY_IP:-10.253.57.10}"
compose=(docker compose -f dev/docker-compose.yaml -p "izena-pdns-test-$(openssl rand -hex 8)")

cleanup() {
  "${compose[@]}" down --volumes
}
trap cleanup EXIT

"${compose[@]}" up -d --wait
export IZENA_PDNS_BIND_URL="http://$("${compose[@]}" port bind 8081)"
export IZENA_PDNS_URL="http://$("${compose[@]}" port pdns 8081)"
export IZENA_PDNS_PRIMARY_URL="http://$("${compose[@]}" port primary 8081)"
export IZENA_PDNS_SECONDARY_URL="http://$("${compose[@]}" port secondary 8081)"
"$@"
