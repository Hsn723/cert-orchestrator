FROM scratch
ARG TARGETPLATFORM
LABEL org.opencontainers.image.authors="Hsn723" \
      org.opencontainers.image.title="cert-orchestrator" \
      org.opencontainers.image.source="https://github.com/hsn723/cert-orchestrator"
WORKDIR /
COPY $TARGETPLATFORM/cert-orchestrator /
COPY LICENSE /LICENSE
USER 65532:65532

ENTRYPOINT ["/cert-orchestrator"]
