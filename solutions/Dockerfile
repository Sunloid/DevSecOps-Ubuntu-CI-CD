# syntax=docker/dockerfile:1
# SOLUTION for the container exercises (V21-V27).  Build:  docker build -f solutions/Dockerfile -t practice-server:fixed .

# ---- build stage: compilers live here and are thrown away -----------------------------
FROM node:22-bookworm-slim AS build
ENV NODE_ENV=production
WORKDIR /build
# Only needed if better-sqlite3 has no prebuilt binary and must compile. Discarded with this stage.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# ---- runtime stage: distroless = no shell, no package manager, no curl ------------------
FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /build/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY uploads ./uploads
COPY solutions/healthcheck.js ./healthcheck.js
COPY --from=build --chown=65532:65532 /out/data ./data
USER 65532:65532
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "healthcheck.js"]
CMD ["src/server.js"]
