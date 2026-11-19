#!/bin/sh
set -eu

DIR="/etc/mihomo/rules"
SOURCE="$DIR/ru-blocked-source.txt"
BACKUP="$DIR/ru-blocked-source.txt.bak"
RAW_STAGE="$DIR/.ru-blocked-raw-stage-$$"
FILTERED_STAGE="$DIR/.ru-blocked-filtered-stage-$$"
FILTER_FILE="$DIR/ru-blocked-filters.txt"
trap 'rm -f "$RAW_STAGE" "$FILTERED_STAGE"' EXIT HUP INT TERM

[ ! -f "$SOURCE" ] || cp "$SOURCE" "$BACKUP"
URL="https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/ru-blocked.txt"
wget -q -O "$RAW_STAGE" "$URL"
COUNT=$(awk -F: '$1=="domain" && NF==2 {n++} END {print n+0}' "$RAW_STAGE")
BAD=$(awk -F: '$1!="domain" || NF!=2 {n++} END {print n+0}' "$RAW_STAGE")
BYTES=$(wc -c < "$RAW_STAGE" | tr -d ' ')
if [ ! -s "$RAW_STAGE" ] || [ "$COUNT" -lt 1000 ] || [ "$BAD" -ne 0 ] || [ "$BYTES" -lt 10000 ]; then
    echo "ERROR: candidate source failed validation; source and provider unchanged" >&2
    exit 1
fi
python3 "$DIR/domain_filter.py" "$RAW_STAGE" "$FILTERED_STAGE" "$FILTER_FILE"
FILTERED=$(awk -F: '$1=="domain" && NF==2 {n++} END {print n+0}' "$FILTERED_STAGE")
if [ "$FILTERED" -lt 1000 ]; then
    echo "ERROR: filtered source has fewer than 1000 domains; current source preserved" >&2
    exit 1
fi
mv "$FILTERED_STAGE" "$SOURCE"
if ! "$DIR/update-ru-blocked.sh"; then
    echo "ERROR: build failed; restoring previous source" >&2
    if [ -f "$BACKUP" ]; then cp "$BACKUP" "$SOURCE"; fi
    exit 1
fi
echo "SUCCESS: source downloaded and provider rebuilt ($COUNT upstream domains, $FILTERED after filtering, $BYTES bytes)."
