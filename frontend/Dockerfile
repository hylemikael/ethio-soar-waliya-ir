# Multi-stage production Dockerfile for Ethio-SOAR (Waliya-IR) Frontend UI
FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine AS runner

# Remove default nginx static html
RUN rm -rf /usr/share/nginx/html/*

# Copy compiled frontend assets from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy production reverse-proxy and SPA routing configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD wget -q --spider http://127.0.0.1/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
