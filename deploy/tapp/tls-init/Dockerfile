# syntax=docker/dockerfile:1.7
#
# tls-init for deploy/tapp: tapp-cli and nothing else. It fetches the app's TLS key
# over the tapp socket into tmpfs and exits (deploy/tapp/docker-compose.yml).
#
# The same shape as 0g-tapp's docker/tls-init/Dockerfile, built here so that the most
# privileged container of the deployment (it holds the tapp socket, which can read
# every app's key material) comes from a public, CI-built image whose every input is
# pinned:
#   - the base by digest;
#   - tapp-cli is the release binary, checked against the release's SHA256SUMS
#     value by ADD --checksum, so the build fails if a single byte differs.
# No package manager runs: tls-init talks only to a Unix socket, so it needs no CA
# certificates, and nothing else is installed.
#
# Debian, not Alpine or distroless/static: tapp-cli is linked against glibc.
FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

ARG TAPP_CLI_VERSION=v0.11.1
ARG TAPP_CLI_SHA256=1313cda04f9bba8bacfb7fb982c26cfc16f2c39de1ce7f6fca0294fc3ceb97fc

ADD --checksum=sha256:${TAPP_CLI_SHA256} --chmod=0755 \
    https://github.com/0gfoundation/0g-tapp/releases/download/${TAPP_CLI_VERSION}/tapp-cli \
    /usr/local/bin/tapp-cli

# No default subcommand: the compose file states what it wants.
ENTRYPOINT ["/usr/local/bin/tapp-cli"]
