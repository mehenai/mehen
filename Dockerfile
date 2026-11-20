# syntax=docker/dockerfile:1

# Self-hosted Mehen vault (`mehen serve`).
#
# Builds the standalone Linux glibc binary with the vault UI and local engine
# embedded, then runs it as an unprivileged user against a 0700 data volume.
# Put TLS in front (Tailscale serve, Caddy, or `docker compose --profile caddy`)
# and pass MEHEN_SERVE_ORIGIN=https://<your-vault-host>.

FROM oven/bun:1.4.2-debian AS builder
WORKDIR /src

ARG TARGETARCH
ARG MEHEN_COMMIT=0000000

COPY . .
RUN bun install --frozen-lockfile && \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch="x64" ;; \
      arm64) arch="arm64" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    bun apps/cli/scripts/build.ts --target "linux-${arch}" --no-mehen-se --commit "${MEHEN_COMMIT}" && \
    install -m 0755 "apps/cli/dist/mehen-linux-${arch}" /usr/local/bin/mehen

FROM debian:bookworm-slim AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 --system mehen && \
    useradd --uid 10001 --gid 10001 --system --home-dir /data --no-create-home --shell /usr/sbin/nologin mehen && \
    install -d -m 0700 -o mehen -g mehen /data /data/vault

COPY --from=builder /usr/local/bin/mehen /usr/local/bin/mehen

USER mehen
WORKDIR /data

ENV MEHEN_SERVE_HOST=0.0.0.0 \
    MEHEN_SERVE_PORT=7787 \
    MEHEN_SERVE_DATA=/data/vault \
    MEHEN_NO_AUTO_UPDATE=1

VOLUME ["/data"]
EXPOSE 7787

# The vault refuses any Host header other than MEHEN_SERVE_ORIGIN's host (421).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD sh -c 'host=$(printf %s "${MEHEN_SERVE_ORIGIN:-}" | sed -E "s|^https?://||; s|/.*||"); curl -fsS -H "Host: ${host:-localhost:${MEHEN_SERVE_PORT:-7787}}" "http://127.0.0.1:${MEHEN_SERVE_PORT:-7787}/healthz" > /dev/null'

ENTRYPOINT ["/usr/local/bin/mehen"]
CMD ["serve"]
