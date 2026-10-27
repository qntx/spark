# Lightning Address server — multi-stage image. Built from the repo root context so the
# workspace lockfile pins every dependency; the runtime stage is distroless Node 24 and runs
# the app's TypeScript entrypoint directly (Node ≥24 strips types natively).

# ---------- build ----------
FROM oven/bun:1.4.4-debian AS build
WORKDIR /repo
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Manifests first: the install layer caches on bun.lock alone.
COPY package.json bun.lock tsconfig.base.json ./
COPY packages/spark/package.json packages/spark/package.json
COPY packages/spark-wasm/package.json packages/spark-wasm/package.json
COPY apps/lnurl-server/package.json apps/lnurl-server/package.json
RUN bun install --frozen-lockfile

# Build the consumed workspace packages — spark.wasm ships inside @qntx/spark-wasm/dist.
COPY packages/spark packages/spark
COPY packages/spark-wasm packages/spark-wasm
RUN bun run --cwd packages/spark build && bun run --cwd packages/spark-wasm build

# Reinstall production-only: node_modules keeps the workspace symlinks into packages/*.
RUN rm -rf node_modules && bun install --frozen-lockfile --production --ignore-scripts

COPY apps/lnurl-server apps/lnurl-server

# ---------- runtime ----------
FROM gcr.io/distroless/nodejs24-debian12:nonroot@sha256:14d42e2511532589a7c7e01a753667a74fcc96266e137e8125006b87b0c32d0a
WORKDIR /app

COPY --from=build /repo/node_modules node_modules
COPY --from=build /repo/package.json /repo/bun.lock ./
COPY --from=build /repo/packages/spark/package.json packages/spark/package.json
COPY --from=build /repo/packages/spark/dist packages/spark/dist
COPY --from=build /repo/packages/spark/node_modules packages/spark/node_modules
COPY --from=build /repo/packages/spark-wasm/package.json packages/spark-wasm/package.json
COPY --from=build /repo/packages/spark-wasm/dist packages/spark-wasm/dist
COPY --from=build /repo/packages/spark-wasm/node_modules packages/spark-wasm/node_modules
COPY --from=build /repo/apps/lnurl-server apps/lnurl-server

# distroless:nonroot already runs uid 65532; no shell, so the healthcheck exec's node directly.
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s \
  CMD ["/nodejs/bin/node", "-e", "fetch(`http://127.0.0.1:${process.env.LNURL_PORT ?? '8080'}/health`).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

ENTRYPOINT ["/nodejs/bin/node"]
CMD ["apps/lnurl-server/src/main.ts"]

LABEL org.opencontainers.image.source="https://github.com/qntx/spark" \
      org.opencontainers.image.licenses="Apache-2.0"
