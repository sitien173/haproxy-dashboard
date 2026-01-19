#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat << 'EOF'
Usage: setup_acme.sh -d <domain> -e <email> [-w <webroot>] [--acme-home <path>]

Options:
  -d, --domain     Domain name for the certificate (required)
  -e, --email      ACME account email (required)
  -w, --webroot    Webroot path for http-01 challenges (optional; default: standalone)
  --acme-home      Override acme.sh home path (optional)
EOF
}

DOMAIN=""
EMAIL=""
WEBROOT=""
ACME_HOME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)
      DOMAIN="$2"
      shift 2
      ;;
    -e|--email)
      EMAIL="$2"
      shift 2
      ;;
    -w|--webroot)
      WEBROOT="$2"
      shift 2
      ;;
    --acme-home)
      ACME_HOME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
  usage
  exit 1
fi

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
fi

if [[ -n "$ACME_HOME" ]]; then
  ACME_SH="${ACME_HOME}/acme.sh"
else
  ACME_SH="${HOME}/.acme.sh/acme.sh"
fi

if [[ ! -x "$ACME_SH" ]]; then
  curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"
fi

if [[ ! -x "$ACME_SH" ]]; then
  echo "acme.sh not found at ${ACME_SH}" >&2
  exit 1
fi

ISSUE_ARGS=("$ACME_SH" --issue -d "$DOMAIN")
if [[ -n "$WEBROOT" ]]; then
  ISSUE_ARGS+=(--webroot "$WEBROOT")
else
  ISSUE_ARGS+=(--standalone)
fi

"${ISSUE_ARGS[@]}"

INSTALL_DIR="/etc/haproxy-configurator/ssl"
SSL_INI="/etc/haproxy-configurator/ssl.ini"
SERVICE_NAME="haproxy-configurator"

$SUDO mkdir -p "$INSTALL_DIR"
$SUDO "$ACME_SH" --install-cert -d "$DOMAIN" \
  --fullchain-file "$INSTALL_DIR/fullchain.pem" \
  --key-file "$INSTALL_DIR/privkey.pem" \
  --reloadcmd "systemctl restart ${SERVICE_NAME}"

cat << EOF | $SUDO tee "$SSL_INI" > /dev/null
[ssl]
certificate_path = ${INSTALL_DIR}/fullchain.pem
private_key_path = ${INSTALL_DIR}/privkey.pem
EOF

echo "Installed certificate for ${DOMAIN} and updated ${SSL_INI}"
