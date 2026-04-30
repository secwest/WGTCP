#!/bin/bash
# bootstrap-server.sh — install + start perf daemons on a spoke VM.
# Idempotent. Run via cloud-init or rsync+ssh after VM bring-up.
#
# Daemons / artifacts created:
#   - iperf3 -s    on port 5201 (systemd unit)
#   - nginx        on :443 (snake-oil cert) serving /var/www/perf/static/{1k,64k,1m}.bin
#   - nginx        on :8443 serving an h2-friendly endpoint
#   - perfuser     SSH account with authorized_keys provisioned by caller
#
# Args: none.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

echo "==> protect modified wg userland"
# Baseline image ships a custom /usr/bin/wg that understands the
# 'Transport=' keyword. apt may upgrade wireguard-tools and clobber it.
if [[ -f /usr/bin/wg && ! -f /usr/local/sbin/wg.custom ]]; then
    sudo cp -a /usr/bin/wg /usr/local/sbin/wg.custom
fi
sudo apt-mark hold wireguard-tools 2>/dev/null || true

echo "==> packages"
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update -qq
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y -qq \
    -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    iperf3 nginx ssl-cert openssl \
    nghttp2-client nghttp2-server \
    iproute2 curl bc gawk sysstat \
    netcat-openbsd

# Restore custom wg if anything overwrote it.
if [[ -f /usr/local/sbin/wg.custom ]]; then
    sudo cp -a /usr/local/sbin/wg.custom /usr/bin/wg
fi

echo "==> iperf3 systemd"
# Ubuntu's iperf3 package may install its own unit; override with our own
sudo systemctl stop iperf3 2>/dev/null || true
sudo systemctl disable iperf3 2>/dev/null || true
sudo tee /etc/systemd/system/iperf3.service >/dev/null <<'EOF'
[Unit]
Description=iperf3 server
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/iperf3 -s -p 5201
Restart=always
RestartSec=2
User=nobody
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now iperf3

echo "==> static catalog"
sudo mkdir -p /var/www/perf/static
for sz in 1k 64k 1m; do
    f=/var/www/perf/static/${sz}.bin
    case "$sz" in
        1k)   bytes=1024 ;;
        64k)  bytes=65536 ;;
        1m)   bytes=1048576 ;;
    esac
    if [[ ! -f "$f" || "$(stat -c%s "$f")" != "$bytes" ]]; then
        sudo dd if=/dev/urandom of="$f" bs=1 count=0 seek="$bytes" 2>/dev/null
        # Use truncate which is faster than dd with bs=1
        sudo truncate -s "$bytes" "$f"
        sudo chmod 0644 "$f"
    fi
done
# Also a generic index.html
echo "ok" | sudo tee /var/www/perf/static/index.html >/dev/null
sudo cp /var/www/perf/static/index.html /var/www/perf/index.html

echo "==> nginx :443 + :8443"
sudo tee /etc/nginx/sites-available/perf >/dev/null <<'EOF'
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    server_name _;
    root /var/www/perf;
    location / { try_files $uri $uri/ =404; sendfile on; }
    access_log off;
}
server {
    listen 8443 ssl http2 default_server;
    listen [::]:8443 ssl http2 default_server;
    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    server_name _;
    root /var/www/perf;
    location / { try_files $uri $uri/ =404; sendfile on; }
    access_log off;
}
EOF
sudo ln -sf /etc/nginx/sites-available/perf /etc/nginx/sites-enabled/perf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx || sudo systemctl restart nginx

echo "==> perfuser account"
if ! id perfuser >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash perfuser
fi
sudo mkdir -p /home/perfuser/.ssh
sudo chmod 700 /home/perfuser/.ssh

# sshd: enable ControlMaster-friendly settings
if ! grep -q '^PermitUserEnvironment' /etc/ssh/sshd_config; then
    echo "PermitUserEnvironment yes" | sudo tee -a /etc/ssh/sshd_config >/dev/null
fi
sudo systemctl reload ssh || sudo systemctl reload sshd || true

echo "==> netem-friendly sysctls"
sudo sysctl -qw net.core.rmem_max=134217728
sudo sysctl -qw net.core.wmem_max=134217728
sudo sysctl -qw net.ipv4.tcp_rmem='4096 87380 67108864'
sudo sysctl -qw net.ipv4.tcp_wmem='4096 65536 67108864'

echo "bootstrap-server OK"
