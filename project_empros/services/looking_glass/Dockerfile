FROM docker.io/node:22-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build
RUN npm prune --production

FROM docker.io/node:22-alpine
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV NATS_URL=nats://nats:4222

USER node

COPY --from=builder --chown=node:node /app/build build/
COPY --from=builder --chown=node:node /app/node_modules node_modules/
COPY --chown=node:node package.json .

EXPOSE 3000
CMD ["node", "build"]