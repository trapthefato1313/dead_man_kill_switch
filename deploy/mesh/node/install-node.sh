#!/usr/bin/env bash
# Bootstrap idempotente de UM no dmks (WireGuard + sink + systemd).
#
# Corre como root NO host de destino, a partir da pasta do bundle:
#   scp -r out/node/node-001 root@HOST:/tmp/dmks-node-001
#   ssh root@HOST 'cd /tmp/dmks-node-001 && ./install-node.sh'
#
# O bundle e autossuficiente: leva wg0.conf, dmks/, dmks-sink.service,
# install.env. Nao descarrega nada alem dos pacotes do sistema.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "erro: corre como root" >&2; exit 1; }

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$here/install.env"
: "${NODE_NAME:?}" "${WG_IP:?}" "${SINK_PORT:?}"
SPOOL="${SPOOL:-/var/lib/dmks-sink/spool}"

echo "== [$NODE_NAME] pacotes =="
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y wireguard-tools python3
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y wireguard-tools python3
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache wireguard-tools python3
else
  echo "erro: gestor de pacotes nao reconhecido (apt/dnf/apk)" >&2
  exit 1
fi

echo "== [$NODE_NAME] WireGuard =="
install -d -m 700 /etc/wireguard
install -m 600 "$here/wg0.conf" /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0.service

echo "== [$NODE_NAME] utilizador e spool =="
id -u dmks >/dev/null 2>&1 || \
  useradd --system --home /var/lib/dmks-sink --shell /usr/sbin/nologin dmks
install -d -m 700 -o dmks -g dmks "$SPOOL"

echo "== [$NODE_NAME] codigo =="
install -d -m 0755 /opt
rm -rf /opt/dmks
cp -r "$here/dmks" /opt/dmks
chown -R root:root /opt/dmks

echo "== [$NODE_NAME] unit systemd =="
sed -e "s|@@NODE_NAME@@|${NODE_NAME}|g" \
    -e "s|@@WG_IP@@|${WG_IP}|g" \
    -e "s|@@SINK_PORT@@|${SINK_PORT}|g" \
    -e "s|@@SPOOL@@|${SPOOL}|g" \
    "$here/dmks-sink.service" > /etc/systemd/system/dmks-sink.service

systemctl daemon-reload
systemctl enable --now dmks-sink.service

echo "== [$NODE_NAME] estado =="
systemctl --no-pager --full status dmks-sink.service || true
echo
echo "no pronto: a ouvir em ${WG_IP}:${SINK_PORT} (dentro da malha)"
echo "verifica no hub:  ping ${WG_IP}"
