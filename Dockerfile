# syntax=docker/dockerfile:1
# The runtime image installs the same DEB tested by the package workflow.
# Build a package first, place it in dist/, then: docker build -t netom .
FROM debian:trixie-slim
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="Netom" \
      org.opencontainers.image.source="https://github.com/FastNetMon/netom" \
      org.opencontainers.image.licenses="MPL-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
# A bind mount keeps the package archive out of the final image layers.
RUN --mount=type=bind,source=dist,target=/packages \
    apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates tini /packages/*.deb \
    && rm -rf /var/lib/apt/lists/* \
    && cp /etc/netom/netom.conf.example /etc/netom/netom.conf
WORKDIR /var/lib/netom
USER netom
EXPOSE 8080/tcp 11019/tcp
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/bin/netom"]
CMD ["--config", "/etc/netom/netom.conf"]
