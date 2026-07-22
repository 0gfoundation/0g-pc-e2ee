# syntax=docker/dockerfile:1

# Multi-stage build for the 0G-PC cloud-TEE gateway: the SAME client core, but
# server-run and 0G-operated, meant to run inside an attested CVM.
#
# NOTE: cmd/gateway is currently a stub (no listener yet). This image builds and
# packages the binary so the publish pipeline is ready; it does not yet EXPOSE a
# port because the server surface isn't defined.
#
# Like the sidecar, the build context MUST be the repo root (client depends on
# protocol via `replace => ../protocol`):
#
#   docker build -f client/cmd/gateway/Dockerfile -t 0g-pc-e2ee-gateway .

FROM golang:1.24-alpine AS build
WORKDIR /src

COPY protocol/ ./protocol/
COPY client/ ./client/

WORKDIR /src/client

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
        -o /out/gateway ./cmd/gateway

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/0gfoundation/0g-pc-e2ee"
LABEL org.opencontainers.image.title="0g-pc-e2ee-gateway"
LABEL org.opencontainers.image.description="0G Private Computer cloud-TEE gateway — attested, 0G-operated server running the client core for browser/thin clients."

COPY --from=build /out/gateway /usr/local/bin/gateway

ENTRYPOINT ["/usr/local/bin/gateway"]
