#!/bin/sh
set -eu
DIR="/etc/mihomo/rules"
URL="https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/ru-blocked.txt"
CURRENT="$DIR/ru-blocked-source.txt"
RAW="$DIR/.ru-blocked-raw-download-$$"
TMP="$DIR/.ru-blocked-filtered-download-$$"
FILTER_FILE="$DIR/ru-blocked-filters.txt"
trap 'rm -f "$RAW" "$TMP"' EXIT HUP INT TERM

echo "Downloading source..."
if ! wget -q -O "$RAW" "$URL"; then echo "ERROR: download failed; current source preserved" >&2; exit 1; fi
COUNT=$(awk -F: '$1=="domain" && NF==2 {n++} END {print n+0}' "$RAW")
BAD=$(awk -F: '$1!="domain" || NF!=2 {n++} END {print n+0}' "$RAW")
BYTES=$(wc -c < "$RAW" | tr -d ' ')
echo "Downloaded bytes: $BYTES"
echo "Domain entries: $COUNT"
echo "Unexpected entries: $BAD"
if [ ! -s "$RAW" ] || [ "$BAD" -ne 0 ] || [ "$COUNT" -lt 1000 ] || [ "$BYTES" -lt 10000 ]; then
    echo "ERROR: source validation failed; current source preserved" >&2; exit 1
fi
python3 "$DIR/domain_filter.py" "$RAW" "$TMP" "$FILTER_FILE"
FILTERED=$(awk -F: '$1=="domain" && NF==2 {n++} END {print n+0}' "$TMP")
if [ "$FILTERED" -lt 1000 ]; then echo "ERROR: filtered source validation failed" >&2; exit 1; fi
if [ -f "$CURRENT" ]; then cp "$CURRENT" "$CURRENT.bak"; fi
mv "$TMP" "$CURRENT"
echo "SUCCESS: filtered source updated. Run update-ru-blocked.sh to rebuild."
