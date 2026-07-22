# syntax=docker/dockerfile:1

# Multi-stage build for the 0G-PC sidecar: the client core wrapped as a
# localhost OpenAI-compatible proxy.
#
# IMPORTANT: the build context MUST be the repo root, not client/. The client
# module depends on the protocol module through a `replace => ../protocol`
# directive, so both module trees have to be present at build time:
#
#   docker build -f client/cmd/sidecar/Dockerfile -t 0g-pc-e2ee-sidecar .

FROM golang:1.24-alpine AS build
WORKDIR /src

# Copy both modules; protocol must sit next to client for the replace to resolve.
COPY protocol/ ./protocol/
COPY client/ ./client/

WORKDIR /src/client

# Warm the module cache in its own layer so dependency downloads are reused
# across builds that only change source.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Static, reproducible binary (CGO off so it runs on distroless/static).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
        -o /out/sidecar ./cmd/sidecar

# Minimal runtime: no shell, non-root, ships CA certs + tzdata (the sidecar
# dials the provider over HTTPS, so it needs the CA bundle).
FROM gcr.io/distroless/static-debian12:nonroot

# OCI metadata. `image.source` is what binds this image to the repo on GHCR:
# the registry reads it to link the package to github.com/0gfoundation/0g-pc-e2ee.
LABEL org.opencontainers.image.source="https://github.com/0gfoundation/0g-pc-e2ee"
LABEL org.opencontainers.image.title="0g-pc-e2ee-sidecar"
LABEL org.opencontainers.image.description="0G Private Computer sidecar — local OpenAI-compatible proxy that seals requests to an attested TEE provider."

COPY --from=build /out/sidecar /usr/local/bin/sidecar

# OpenAI-compatible proxy port.
EXPOSE 8787

# Bind to all interfaces so the port is reachable from outside the container
# (the binary defaults to localhost, which would be container-local only).
# The required provider flags are appended by the caller, e.g.:
#   docker run -p 8787:8787 <img> \
#     --provider-enc-key <base64url> --provider-signer 0x...
ENTRYPOINT ["/usr/local/bin/sidecar", "--listen", "0.0.0.0:8787"]
