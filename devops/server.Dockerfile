# Build context: repository root (see compose.yaml).
FROM golang:1.26-alpine AS base
WORKDIR /app
COPY server/go.mod server/go.sum ./
# Not a cache mount: the modules must live in the image layer so the dev
# go-mod-cache volume is seeded from them on first `compose up`.
RUN go mod download

# ---- dev: hot reload with air ----
FROM base AS dev
RUN go install github.com/air-verse/air@latest
EXPOSE 8080
CMD ["air", "-c", ".air.toml"]

# ---- build: compile static binary ----
FROM base AS build
COPY server/ .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# ---- client: static bundle served by the Go server in prod ----
FROM node:24-alpine AS client
WORKDIR /client
COPY client/package.json client/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY client/ .
RUN npm run build

# ---- prod: minimal runtime ----
FROM gcr.io/distroless/static-debian12:nonroot AS prod
COPY --from=build /out/server /server
COPY --from=client /client/dist /public
ENV STATIC_DIR=/public
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/server"]
