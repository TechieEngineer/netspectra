FROM node:26-alpine AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/netspectra ./cmd/netspectra

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 netspectra && mkdir /data && chown netspectra /data
COPY --from=backend /out/netspectra /usr/local/bin/netspectra
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/netspectra"]
CMD ["--db", "/data/netscan.db"]
