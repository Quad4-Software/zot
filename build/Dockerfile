# ---
# Packages a prebuilt zot binary (make binary GOOS=linux GOARCH=<arch>) into a
# distroless static image. OCI labels are set from build args so CI can stamp
# version, revision and build time at publish.
# ---
ARG BASE_IMAGE=gcr.io/distroless/static-debian13:latest

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

COPY build/config.json /etc/zot/config.json
COPY bin/zot-${TARGETOS}-${TARGETARCH} /usr/bin/zot

EXPOSE 5000
ENTRYPOINT ["/usr/bin/zot"]
CMD ["serve", "/etc/zot/config.json"]
