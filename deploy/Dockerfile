# idp-mcp image: mcp-gateway and registry-service, static binaries on scratch.
# Built by deploy/build.sh from binaries compiled on the host (CGO_ENABLED=0), with --network none,
# so no base image or package index is needed. Runs as uid 10001; works with a read-only root.
FROM scratch
# No --chmod here: BuildKit applies it to the created parent directories too, and a 0644 /etc is not
# traversable by uid 10001 (then /etc/resolv.conf is unreadable and DNS silently fails). The build
# context carries the right modes instead (deploy/build.sh).
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0755 mcp-gateway registry-service /usr/local/bin/
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/mcp-gateway"]
