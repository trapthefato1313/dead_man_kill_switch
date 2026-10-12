#!/usr/bin/env bash
# Gera os ficheiros de implantacao a partir dos templates e do .env.
#   ./render.sh            -> escreve em out/
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "erro: cria o .env primeiro ->  cp .env.example .env  &&  \$EDITOR .env" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
. ./.env
set +a

for var in DOMINIO NEWS_HOST NODE1_HOSTNAME IP_NODE1 IP_NODE2 IP_NODE3 \
           LISTMONK_DB_PASSWORD LISTMONK_ADMIN_PASSWORD \
           STALWART_RECOVERY_ADMIN \
           SWITCH_FROM SWITCH_SMTP_USER OWNER_EMAIL; do
  if [ -z "${!var:-}" ] || [[ "${!var}" == *"TROQUE"* ]] || [[ "${!var}" == *"IP_DO_NO"* ]]; then
    echo "erro: variavel $var por preencher no .env" >&2
    exit 1
  fi
done

mkdir -p out/listmonk out/stalwart out/dns out/dmks

envsubst < templates/listmonk-compose.yml.tmpl  > out/listmonk/docker-compose.yml
envsubst < templates/listmonk.config.toml.tmpl  > out/listmonk/config.toml
envsubst < templates/stalwart-compose.yml.tmpl  > out/stalwart/docker-compose.yml
envsubst < templates/dns-records.txt.tmpl       > out/dns/records.txt

# Script que liga o dead man's switch a estes 3 nos (relay failover).
cat > out/dmks/init.sh <<EOF
#!/usr/bin/env bash
# Aponta o dead man's switch aos 3 nos Stalwart como relay (failover:
# entrega exatamente uma copia por destinatario, saltando nos mortos).
# Exporta a senha da conta SMTP antes de correr o init.
set -euo pipefail
: "\${SWITCH_SMTP_PASS:?exporta SWITCH_SMTP_PASS com a senha da conta Stalwart}"

python3 -m dmks --data-dir "${DMKS_DATA:-/var/lib/dmks}" init \\
  --switch principal --name "principal" --release-mode notify \\
  --smtp-strategy failover \\
  --smtp-from "${SWITCH_FROM}" \\
  --smtp-user "${SWITCH_SMTP_USER}" \\
  --smtp-password 'env:SWITCH_SMTP_PASS' \\
  --smtp-server "${NODE1_HOSTNAME}=${NODE1_HOSTNAME}:587" \\
  --smtp-server "${NODE2_HOSTNAME}=${NODE2_HOSTNAME}:587" \\
  --smtp-server "${NODE3_HOSTNAME}=${NODE3_HOSTNAME}:587" \\
  --warn-days 15 --arm-days 20 --release-days 25 \\
  --owner-email "${OWNER_EMAIL}"

echo
echo "Proximo passo: enroll, recipient add (chave GPG), seal, checkin."
EOF
chmod +x out/dmks/init.sh

chmod 600 out/listmonk/config.toml
echo "ok: gerado em out/"
echo "  out/listmonk/   -> copia para a VPS 0"
echo "  out/stalwart/   -> copia para as VPS 1..3 (ajusta NODE_HOSTNAME em cada uma)"
echo "  out/dns/records.txt -> publica na zona do dominio"
echo "  out/dmks/init.sh    -> corre no servidor do switch (exporta SWITCH_SMTP_PASS)"
