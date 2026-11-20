FROM node:24-alpine

WORKDIR /app

# Install production dependencies first for optimal layer caching
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev --no-audit --no-fund

# Copy scanner application source
COPY bin ./bin
COPY checks ./checks
COPY core ./core
COPY ui ./ui
COPY scan.js ./scan.js

# Prepare persistent directories for scan reports & SQLite history with non-root ownership
RUN mkdir -p /app/reports /app/.secscan-history && chown -R node:node /app

USER node

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4321

EXPOSE 4321

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 4321) + '/api/meta', { headers: { Host: 'localhost:' + (process.env.PORT || 4321) } }).then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "core/server.js"]
