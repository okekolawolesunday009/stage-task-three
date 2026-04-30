FROM nginx:1.25-alpine

# Install certbot and dependencies for Let's Encrypt automation
RUN apk add --no-cache \
    certbot \
    certbot-nginx \
    curl \
    bash \
    openssl

# Create directories for certificates and renewal scripts
RUN mkdir -p /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt

# Copy custom nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy entrypoint script for certificate initialization
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
