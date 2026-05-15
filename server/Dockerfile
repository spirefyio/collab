# syntax=docker/dockerfile:1.7

# ----- build stage --------------------------------------------------
FROM golang:1.25-alpine AS builder

# CA bundle for any external HTTPS calls the runtime makes (OAuth).
RUN apk --no-cache add ca-certificates git

WORKDIR /app

# Copy go mod first so layer cache survives source-only edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=docker
ARG GIT_SHA=unknown
ARG BUILD_TARGET=cmd/relay

# CGO_ENABLED=0 for a fully static binary that runs on scratch/distroless.
# We use alpine for the runtime stage instead so wget is available for
# the HEALTHCHECK below, but the binary itself is still static.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X github.com/spirefyio/collab/server/internal/config.Version=${VERSION}-${GIT_SHA}" \
    -o /out/collab-server ./${BUILD_TARGET}

# ----- runtime stage ------------------------------------------------
FROM alpine:3.20 AS runtime

RUN apk --no-cache add ca-certificates wget && \
    addgroup -S collab && adduser -S -G collab collab

COPY --from=builder /out/collab-server /usr/local/bin/collab-server

USER collab
WORKDIR /home/collab

EXPOSE 8443

# Healthcheck hits /health (liveness). Orchestrators should poll
# /health/ready separately to gate traffic.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- --tries=1 http://127.0.0.1:8443/health > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/collab-server"]
