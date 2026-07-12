FROM gcr.io/distroless/static:nonroot
ARG TARGETPLATFORM
ENTRYPOINT ["/usr/bin/go-certificates"]
COPY $TARGETPLATFORM/go-certificates /usr/bin/
