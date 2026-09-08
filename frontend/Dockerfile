# Multi-stage Dockerfile for GridPulse Astro Frontend

# ==========================================
# Stage 1: Build Astro static production bundle
# ==========================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install project dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy Astro configuration and source code
COPY astro.config.mjs tailwind.config.mjs tsconfig.json ./
COPY src ./src

# Build argument for backend API URL (baked into Vite client bundle at build-time)
ARG PUBLIC_API_URL=http://localhost:8000
ENV PUBLIC_API_URL=$PUBLIC_API_URL

# Build static bundle into /app/dist
RUN npm run build


# ==========================================
# Stage 2: Serve static bundle via Nginx
# ==========================================
FROM nginx:1.27-alpine AS runner

# Remove default Nginx welcome page
RUN rm -rf /usr/share/nginx/html/*

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration with reverse proxy support
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Grant read permissions to web root
RUN chmod -R 755 /usr/share/nginx/html

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:3000/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
