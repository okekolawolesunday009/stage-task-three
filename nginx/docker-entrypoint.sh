#!/bin/bash
# docker-entrypoint.sh — Initialize certificates and start nginx

set -e

# Configuration
DOMAIN="${SERVER_DOMAIN:-localhost}"
EMAIL="${CERTBOT_EMAIL:-admin@example.com}"
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

mkdir -p "$CERT_DIR"
mkdir -p /var/www/letsencrypt

# Create a self-signed certificate if none exist yet.
if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ]; then
    echo "[nginx-init] Creating self-signed certificate for $DOMAIN..."
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/fullchain.pem" \
        -subj "/CN=$DOMAIN"
fi

# Create a fixed symlink so nginx.conf can always use the same path.
ln -snf "$CERT_DIR" /etc/letsencrypt/live/localhost

if [ "$DOMAIN" != "localhost" ]; then
    echo "[nginx-init] Requesting Let's Encrypt certificate for $DOMAIN..."

    nginx -g 'daemon off;' &
    NGINX_PID=$!
    sleep 2

    certbot certonly \
        --webroot \
        --webroot-path=/var/www/letsencrypt \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN" || true

    kill $NGINX_PID || true
    wait $NGINX_PID 2>/dev/null || true
    sleep 1
fi

echo "[nginx-init] Starting nginx..."
exec "$@"
