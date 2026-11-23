# syntax=docker/dockerfile:1
FROM node:22-alpine

LABEL org.opencontainers.image.title="sqlpulse-mcp"
LABEL org.opencontainers.image.description="Zero-LLM deterministic SQL Schema X-Ray, EXPLAIN advisor, migration lock gate and auto-PII masking MCP server"
LABEL org.opencontainers.image.source="https://github.com/dynonode/sqlpulse-mcp"
LABEL org.opencontainers.image.url="https://sqlpulse.dynonode.com"
LABEL org.opencontainers.image.vendor="Toxic Dreams (DynoNode)"
LABEL org.opencontainers.image.licenses="Proprietary-OpenCore"

ENV NODE_ENV=production

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY bin/ ./bin/
COPY src/ ./src/
COPY server.json README.md ./

RUN chown -R node:node /app
USER node

ENTRYPOINT ["node", "bin/sqlpulse.mjs", "mcp"]
