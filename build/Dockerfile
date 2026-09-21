# ---
# Packages a prebuilt zot binary (make binary GOOS=linux GOARCH=<arch>) into a
# distroless static image running as the nonroot user. OCI labels are set from
# build args so CI can stamp version, revision and build time at publish.
# ---
ARG BASE_IMAGE=gcr.io/distroless/static-debian13@sha256:58133991db06659feaabe0f4e97a35cebf15ef4ea08f8a4c6d2ee5f75e4aa6a0

# ---
# Stage 1: pre-create the data dir owned by the nonroot user. distroless has no
# shell, so directories for the final image are staged here.
# ---
FROM --platform=$BUILDPLATFORM docker.io/library/alpine:3.22@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764 AS dirs

RUN mkdir -p /dirs/var/lib/registry && chown -R 65532:65532 /dirs/var/lib/registry

# ---
# Stage 2: final image
# ---
FROM $BASE_IMAGE

ARG TARGETOS
ARG TARGETARCH

ARG VERSION=dev
ARG REVISION=""
ARG CREATED=""
ARG SOURCE="https://github.com/Quad4-Software/zot"

LABEL org.opencontainers.image.title="quad4-zot" \
      org.opencontainers.image.description="Quad4's OCI registry, a zot fork" \
      org.opencontainers.image.vendor="Quad4" \
      org.opencontainers.image.url="https://quad4.io" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=dirs /dirs/var/lib/registry /var/lib/registry
COPY build/config.json /etc/zot/config.json
COPY bin/zot-${TARGETOS}-${TARGETARCH} /usr/bin/zot

USER 65532:65532
EXPOSE 5000
ENTRYPOINT ["/usr/bin/zot"]
CMD ["serve", "/etc/zot/config.json"]
