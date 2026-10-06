# Build context: repository root (see compose.yaml).
# Development only: in production the Go server serves the built client
# (see the client stage in server.Dockerfile).
FROM node:24-alpine
WORKDIR /app
COPY surface-cloud/client/package.json surface-cloud/client/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
EXPOSE 5173
CMD ["npm", "run", "dev"]
