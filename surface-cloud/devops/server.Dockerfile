# Build context: repository root (parent of surface/ and surface-cloud/), so
# the image can see both the cloud module and the core `surface` module it
# depends on via `replace surface => ../../surface`.
FROM golang:1.26-alpine AS base
WORKDIR /src/surface-cloud/server
# libpcap is loaded at runtime (via dlopen) by naabu's SYN scanner; the Alpine
# dev image runs the freshly built binary, so it needs the musl build of it.
RUN apk add --no-cache libpcap git

# ---- dev: hot reload with air (source bind-mounted by compose) ----
FROM base AS dev
RUN go install github.com/air-verse/air@latest
EXPOSE 8080
CMD ["air", "-c", ".air.toml"]

# ---- build: compile static binary from both modules ----
FROM base AS build
COPY surface /src/surface
COPY surface-cloud/server /src/surface-cloud/server
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# ---- client: static bundle served by the Go server in prod ----
FROM node:24-alpine AS client
WORKDIR /client
COPY surface-cloud/client/package.json surface-cloud/client/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY surface-cloud/client/ .
RUN npm run build

# ---- libs: glibc libpcap for the prod runtime ----
FROM debian:12-slim AS libs
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# ---- prod: minimal runtime ----
# distroless/base (not static) ships glibc, which the dlopen'd libpcap needs.
FROM gcr.io/distroless/base-debian12:nonroot AS prod
COPY --from=build /out/server /server
COPY --from=client /client/dist /public
# naabu dlopens libpcap.so / .so.1 / .so.0.8 at runtime for the SYN scan.
COPY --from=libs /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so.0.8
COPY --from=libs /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so.1
COPY --from=libs /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so
ENV STATIC_DIR=/public
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/server"]
