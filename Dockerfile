# Build stage
FROM golang:1.24-alpine AS builder

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
COPY api/ ./api/
COPY auth/ ./auth/
COPY cmd/ ./cmd/
COPY config/ ./config/
COPY health/ ./health/
COPY kdf/ ./kdf/
COPY log/ ./log/
COPY metrics/ ./metrics/
COPY observability/ ./observability/
COPY proxy/ ./proxy/
COPY storage/ ./storage/
COPY tls/ ./tls/
COPY tracing/ ./tracing/

# Build with optimizations
RUN go build \
    -ldflags='-w -s' \
    -trimpath \
    -o schwab-proxy \
    ./cmd/schwab-proxy

# Runtime stage - distroless for maximum security
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source https://github.com/jkoelker/schwab-proxy

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
