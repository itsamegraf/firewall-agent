FROM node:20-alpine
WORKDIR /app

# Install dependencies (include dev deps for build)
COPY firewall-agent-ui/package*.json ./
RUN npm install --no-audit --no-fund

# Copy source and build
COPY firewall-agent-ui/ ./
RUN npm run build

# Run the Next.js server directly (no standalone packaging)
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["npm", "start"]
