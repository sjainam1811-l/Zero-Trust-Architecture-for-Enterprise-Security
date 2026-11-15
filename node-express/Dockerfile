FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --production

# Copy application code
COPY . .

# Expose authentication service port
EXPOSE 4000

# Continuous health monitoring check
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:4000/ || exit 1

CMD ["node", "server.js"]
