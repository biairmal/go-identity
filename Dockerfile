# Multi-stage build: one image runs serve, worker and migrate (TRD 3.7).
# syntax=docker/dockerfile:1

FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SERVICE_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server
# Modes are set here, not with COPY --chmod: newer BuildKit applies --chmod to
# the parent directories a COPY creates, which left app/config without its
# execute bit, so the service could not read its own config.
RUN install -D -m 640 config/config.yaml /out/config/config.yaml && chmod 750 /out/server /out/config

# distroless nonroot: no shell, works under any arbitrary UID (OpenShift
# restricted-v2 SCC gets GID 0, so files are group-readable/executable).
FROM gcr.io/distroless/static-debian12:nonroot
ARG SERVICE_VERSION=dev
ENV SERVICE_VERSION=${SERVICE_VERSION}
WORKDIR /app
COPY --from=builder --chown=65532:0 /out/ /app/
USER 65532:0
EXPOSE 8080
ENTRYPOINT ["/app/server"]
CMD ["serve"]
