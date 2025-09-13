# Build
FROM node:20-alpine AS deps
WORKDIR /app
COPY firewall-agent-ui/package.json firewall-agent-ui/package-lock.json* ./
RUN npm install --no-audit --no-fund

FROM node:20-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY firewall-agent-ui/ ./
RUN npm run build

# Run (standalone output)
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production PORT=3000
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]

