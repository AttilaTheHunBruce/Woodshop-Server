sudo tee /usr/local/sbin/derive-static-ip.sh > /dev/null << 'EOF'
#!/bin/sh
IFACE="eth0"
LAST_OCTET="5"
TIMEOUT=30

i=0
addr=""
while [ "$i" -lt "$TIMEOUT" ]; do
    addr=$(ip -4 -o addr show dev "$IFACE" scope global | awk '{print $4}' | cut -d/ -f1)
    [ -n "$addr" ] && break
    i=$((i + 1))
    sleep 1
done

if [ -z "$addr" ]; then
    logger -t derive-static-ip "no IPv4 on $IFACE after ${TIMEOUT}s, giving up"
    exit 1
fi

case "$addr" in
    *".${LAST_OCTET}") exit 0 ;;
esac

prefix=$(ip -4 -o addr show dev "$IFACE" scope global | awk '{print $4}' | cut -d/ -f2)
gw=$(ip route show default dev "$IFACE" | awk '/default/ {print $3; exit}')
base=$(echo "$addr" | cut -d. -f1-3)
target="${base}.${LAST_OCTET}"

logger -t derive-static-ip "eth0: DHCP gave $addr, switching to $target/$prefix"

ip addr flush dev "$IFACE"
ip addr add "${target}/${prefix}" dev "$IFACE"
[ -n "$gw" ] && ip route replace default via "$gw" dev "$IFACE"
EOF
sudo chmod +x /usr/local/sbin/derive-static-ip.sh

sudo tee /etc/systemd/system/derive-static-ip.service > /dev/null << 'EOF'
[Unit]
Description=Derive static IP (last octet .5) from DHCP lease on eth0
After=systemd-networkd.service network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/derive-static-ip.sh
EOF

sudo tee /etc/systemd/system/derive-static-ip.timer > /dev/null << 'EOF'
[Unit]
Description=Periodically ensure eth0 stays at the derived static IP

[Timer]
OnBootSec=15s
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now derive-static-ip.timer
sudo systemctl start derive-static-ip.service
ip a show eth0