#!/usr/bin/env sh
# Download the offline ip2asn IPv4 database used for passive IP geo labels.
#
#   ./scripts/fetch_geoip.sh [data-dir]
#
# The file lands in <data-dir>/ip2asn-v4.tsv.gz (default ./data), which the
# server picks up automatically at boot. Nothing is queried online at runtime;
# this script is the only network step and is meant to be run by an operator.
set -eu

dir="${1:-./data}"
mkdir -p "$dir"
url="https://iptoasn.com/data/ip2asn-v4.tsv.gz"
out="$dir/ip2asn-v4.tsv.gz"

echo "downloading $url"
curl -fL --retry 3 -o "$out" "$url"
gzip -t "$out"
echo "saved $out ($(wc -c < "$out") bytes)"
echo "ranges: $(gzip -dc "$out" | wc -l)"
echo "restart the server to load it (or pass -geoip-db / PHISH_GEOIP_DB)"
