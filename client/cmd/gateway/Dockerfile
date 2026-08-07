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

# Two binaries, ONE image, on purpose. cvmid is the init container that publishes
# the CVM's identity to the other containers (see cmd/cvmid); shipping it here
# rather than as its own image means the compose gains no second image to pin by
# digest and no second supply-chain item for a verifier to audit — app_id already
# commits to this one.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
        -o /out/gateway ./cmd/gateway

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
        -o /out/cvmid ./cmd/cvmid

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/0gfoundation/0g-pc-e2ee"
LABEL org.opencontainers.image.title="0g-pc-e2ee-gateway"
LABEL org.opencontainers.image.description="0G Private Computer cloud-TEE gateway — attested, 0G-operated server running the client core for browser/thin clients."

COPY --from=build /out/gateway /usr/local/bin/gateway
COPY --from=build /out/cvmid /usr/local/bin/cvmid

# The gateway is the default. Because there is no CMD, a compose `command:` would
# be APPENDED to this entrypoint rather than replacing it — so the identity init
# container overrides `entrypoint:` to run cvmid (deploy/phala/docker-compose.yml).
# It must also override `user:`: cvmid writes to a shared named volume, which
# docker creates root-owned, and this image's default user is `nonroot`.
ENTRYPOINT ["/usr/local/bin/gateway"]
