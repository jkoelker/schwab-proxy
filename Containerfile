# Build stage
FROM docker.io/golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS builder

# Set build environment for static linking
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

# Copy dependency files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies with verification
RUN go mod download && go mod verify

# Copy only Go source files and directories for better caching
# This prevents cache invalidation from non-Go file changes
COPY admin/ ./admin/
COPY auth/ ./auth/
COPY cmd/ ./cmd/
COPY config/ ./config/
COPY health/ ./health/
COPY kdf/ ./kdf/
COPY log/ ./log/
COPY metrics/ ./metrics/
COPY middleware/ ./middleware/
COPY observability/ ./observability/
COPY proxy/ ./proxy/
COPY schwabapi/ ./schwabapi/
COPY storage/ ./storage/
COPY streaming/ ./streaming/
COPY tls/ ./tls/
COPY tracing/ ./tracing/

# Build with optimizations
RUN go build \
    -ldflags='-w -s' \
    -trimpath \
    -o schwab-proxy \
    ./cmd/schwab-proxy

# Runtime stage - distroless for maximum security
FROM gcr.io/distroless/static-debian12:nonroot@sha256:2b7c93f6d6648c11f0e80a48558c8f77885eb0445213b8e69a6a0d7c89fc6ae4

LABEL org.opencontainers.image.source=https://github.com/jkoelker/schwab-proxy

# Copy the static binary
COPY --from=builder /build/schwab-proxy /usr/local/bin/schwab-proxy

# Expose port
EXPOSE 8080

# Set secure environment defaults
ENV DATA_PATH=/data \
    LISTEN_ADDR=0.0.0.0 \
    PORT=8080

# Run the application as non-root user (distroless nonroot user ID 65532)
ENTRYPOINT ["/usr/local/bin/schwab-proxy"]
