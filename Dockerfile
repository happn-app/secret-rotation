FROM golang:1.25.5 AS builder

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app/
ADD . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o secret-rotation main.go

FROM scratch
WORKDIR /app/
COPY --from=builder /app/secret-rotation /app/secret-rotation
EXPOSE 8080

ENTRYPOINT ["/app/secret-rotation"]
