FROM node:22.16.0-bookworm-slim

ENV NODE_ENV=production

WORKDIR /app
COPY backend/package*.json ./
COPY shared/archive /shared/archive
RUN npm ci --omit=dev --prefix /shared/archive \
    && npm ci --omit=dev
COPY backend/src ./src
RUN chown -R node:node /app /shared/archive

USER node
EXPOSE 4000
CMD ["node", "src/server.js"]
