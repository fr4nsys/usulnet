// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package imagebuilder

// builtinTemplate is the in-memory shape of a starter template before
// it is persisted via SeedBuiltinTemplates.
type builtinTemplate struct {
	Name        string
	Description string
	Category    string
	Dockerfile  string
}

// builtinTemplates returns the curated starter set bundled with the
// binary. Each Dockerfile is small, AGPL-compatible (it pulls only from
// public official upstream images), and serves as a working starting
// point operators can clone before customizing. The snippets are
// authored fresh for usulnet rather than copied from any encumbered
// upstream so they can ship under AGPL-3.0-or-later alongside the rest
// of the codebase.
func builtinTemplates() []builtinTemplate {
	return []builtinTemplate{
		{
			Name:        "alpine-minimal",
			Description: "Minimal Alpine 3.21 base image with a healthcheck",
			Category:    "custom",
			Dockerfile: `# Minimal Alpine starter. Pulls only the official, AGPL-compatible
# upstream image and adds a tiny healthcheck binary.
FROM alpine:3.21
RUN apk add --no-cache curl
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/ || exit 1
CMD ["/bin/sh"]
`,
		},
		{
			Name:        "static-web-nginx",
			Description: "Static web site served by nginx-alpine",
			Category:    "web",
			Dockerfile: `# Static-site starter. Drop your built assets into ./public and the
# image will serve them on port 80 via the official nginx-alpine image.
FROM nginx:1.27-alpine
COPY public /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O- http://localhost/ || exit 1
`,
		},
		{
			Name:        "node-app",
			Description: "Production-ready Node.js 22 application",
			Category:    "api",
			Dockerfile: `# Multi-stage Node.js starter. The build stage installs every
# dependency, the final stage copies only the runtime files and runs
# the app as a non-root user.
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app ./
USER node
EXPOSE 3000
CMD ["node", "server.js"]
`,
		},
		{
			Name:        "python-app",
			Description: "Python 3.13 application using a non-root user",
			Category:    "api",
			Dockerfile: `# Python application starter. Installs requirements first so the layer
# cache survives source-only edits, then copies the source and runs as
# a non-root account.
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 1001 app && chown -R app:app /app
USER app
EXPOSE 8000
CMD ["python", "main.py"]
`,
		},
		{
			Name:        "go-app",
			Description: "Statically compiled Go binary on a distroless base",
			Category:    "api",
			Dockerfile: `# Go starter. Builds a statically-linked binary in the golang
# stage and copies only the binary into the distroless runtime.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app ./...

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/app /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
`,
		},
		{
			Name:        "postgres-extension",
			Description: "PostgreSQL 16 image with pre-loaded init SQL",
			Category:    "database",
			Dockerfile: `# Postgres starter. Drops your init scripts into the
# /docker-entrypoint-initdb.d directory the official image runs on the
# first boot of an empty data directory.
FROM postgres:16-alpine
COPY initdb /docker-entrypoint-initdb.d
EXPOSE 5432
`,
		},
		{
			Name:        "background-worker",
			Description: "Queue worker on Alpine with tini as PID 1",
			Category:    "worker",
			Dockerfile: `# Background worker starter. Uses tini as PID 1 so SIGTERM is
# propagated to the worker process during graceful shutdown.
FROM alpine:3.21
RUN apk add --no-cache tini
COPY worker /usr/local/bin/worker
RUN chmod +x /usr/local/bin/worker && adduser -D -u 1001 worker
USER worker
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/worker"]
`,
		},
	}
}
