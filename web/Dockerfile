# VEX Portal web — build the Angular app, serve via nginx.
#
# Mirrors DAST-Portal's own `web/Dockerfile` (node:24-alpine build stage,
# nginx:alpine runtime) — "VEX Portal mirrors DAST-Portal so the same
# rotation maintains both" (docs/design/ui-mockups.html's own design notes).
# Unlike DAST-Portal, this backend mounts every route under `/api` (plus
# `/health`) with no client-route collisions, so there is no need for this
# image's nginx to content-negotiate or proxy anything itself — Traefik
# routes `/api/*` straight to the `vex-portal-api` service before a request
# ever reaches this container (see `compose.yaml`'s two routers on the same
# `Host(vex.shadow-lab.org)`). `nginx.conf` here only serves the built SPA.
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# Angular 21's application builder defaults to the production configuration.
RUN npx ng build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
# The application builder emits static assets under dist/<project>/browser
# — this project's name (angular.json) is "web".
COPY --from=build /app/dist/web/browser /usr/share/nginx/html
EXPOSE 80

# 127.0.0.1, not localhost: nginx.conf only `listen`s on IPv4, and this
# host's container resolver returns ::1 first for "localhost" — that
# combination makes wget's connect refuse over IPv6 while port 80 is
# genuinely open and serving on IPv4, which failed this healthcheck (and,
# because Traefik's Docker provider excludes unhealthy containers from
# routing by default, made every request 404 even though nginx itself was
# fine) until traced down for this task's report.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
