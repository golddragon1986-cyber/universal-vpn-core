#!/bin/sh
set -eu
umask 077
test -f /etc/mihomo/rules/managed-proxies.json
test -d /migration
test ! -f /migration/.hap-armv7-ready
cp -a /etc/mihomo/. /migration/
package=/usr/local/lib/mihomo-panel
cp -a "$package"/panel/. /migration/rules/
tar -xf /etc/mihomo/.hap-iptables-legacy.tar -C /
iptables-legacy -V
test -f /migration/rules/transparent_tcp.py
test -f /migration/rules/transparent-tcp.json
cat > /migration/.hap-start.sh <<'EOF'
#!/bin/sh
set -eu
python3 /etc/mihomo/rules/transparent_tcp.py
exec /bin/sh /usr/local/lib/mihomo-panel/entrypoint.sh
EOF
chmod 700 /migration/.hap-start.sh
touch /migration/.hap-armv7-ready
echo HAP_ARMV7_PREPARED
