# Build stage
FROM docker.io/golang:1.25.4-alpine@sha256:d3f0cf7723f3429e3f9ed846243970b20a2de7bae6a5b66fc5914e228d831bbb AS builder

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
COPY api/ ./api/
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
FROM gcr.io/distroless/static-debian12:nonroot@sha256:e8a4044e0b4ae4257efa45fc026c0bc30ad320d43bd4c1a7d5271bd241e386d0

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
