# ---- deps ----
FROM node:20-bookworm-slim AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# ---- runtime ----
FROM node:20-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3001

# run as non-root
RUN useradd -m -u 1001 app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

USER app
CMD ["node", "src/app.js"]