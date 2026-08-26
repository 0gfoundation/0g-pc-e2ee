# syntax=docker/dockerfile:1

# The load-test upstream fixture (see cmd/mockupstream). It stands in for the
# router, the provider broker and the provider enclave so a load run measures the
# GATEWAY rather than inference capacity.
#
# This image is a test fixture and is deliberately NOT published by
# .github/workflows/docker.yml: it holds unattested keys and answers every request
# with synthetic content, so it must never end up in a deployment.
#
# Like the sidecar and gateway images, the build context MUST be the repo root
# (client depends on protocol via `replace => ../protocol`):
#
#   docker build -f client/cmd/mockupstream/Dockerfile -t 0g-pc-e2ee-mockupstream .

FROM golang:1.26-alpine AS build
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
        -o /out/mockupstream ./cmd/mockupstream

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/0gfoundation/0g-pc-e2ee"
LABEL org.opencontainers.image.title="0g-pc-e2ee-mockupstream"
LABEL org.opencontainers.image.description="Load-test fixture: a protocol-exact stand-in for the 0G router, provider broker and provider enclave. Not for deployment."

COPY --from=build /out/mockupstream /usr/local/bin/mockupstream

ENTRYPOINT ["/usr/local/bin/mockupstream"]
