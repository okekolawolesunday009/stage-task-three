#!/bin/bash
# docker-entrypoint.sh — Initialize certificates and start nginx

set -e

# Configuration
DOMAIN="${SERVER_DOMAIN:-localhost}"
EMAIL="${CERTBOT_EMAIL:-admin@example.com}"
CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

# Only attempt certbot if domain is not localhost and certs don't exist
if [ "$DOMAIN" != "localhost" ] && [ ! -d "$CERT_DIR" ]; then
    echo "[nginx-init] Getting Let's Encrypt certificate for $DOMAIN..."
    
    # Temporarily start nginx to allow certbot to validate
    nginx -g 'daemon off;' &
    NGINX_PID=$!
    sleep 2
    
    # Request certificate
    certbot certonly \
        --webroot \
        --webroot-path=/var/www/letsencrypt \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN" || true
    
    # Stop temporary nginx
    kill $NGINX_PID || true
    wait $NGINX_PID 2>/dev/null || true
    sleep 1
fi

echo "[nginx-init] Starting nginx..."
exec "$@"
