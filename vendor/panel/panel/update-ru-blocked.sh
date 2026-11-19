#!/bin/sh
set -eu
exec python3 /etc/mihomo/rules/domain_provider.py "${1:---source}"
