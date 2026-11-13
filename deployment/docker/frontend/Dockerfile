# =============================================================================
# SecureWatch Frontend – Multi-stage Node 20 / nginx Dockerfile (Vite)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder – compile the React application with Vite
# -----------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY frontend/package.json ./

# Install dependencies
RUN npm install

# Copy frontend source
COPY frontend/ ./

# Build production bundle with Vite
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: production – lean nginx image
# -----------------------------------------------------------------------------
FROM nginx:1.25-alpine AS production

LABEL maintainer="SecureWatch Platform <platform@securewatch.io>"
LABEL org.opencontainers.image.title="SecureWatch Frontend"

# Remove default nginx content and config
RUN rm -rf /usr/share/nginx/html/* \
    && rm -f /etc/nginx/conf.d/default.conf

# Copy custom nginx configuration
COPY deployment/docker/frontend/nginx.conf /etc/nginx/nginx.conf

# Copy built static assets from the builder stage (Vite outputs to /app/dist)
COPY --from=builder /app/dist /usr/share/nginx/html

# Ensure nginx can write its PID and cache directories
RUN chown -R nginx:nginx /var/cache/nginx /var/run /var/log/nginx \
    && chmod -R 755 /usr/share/nginx/html

EXPOSE 80

# Health check
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/nginx-health || exit 1

CMD ["nginx", "-g", "daemon off;"]
