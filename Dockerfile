# Multi-stage build: one image runs serve, worker and migrate (TRD 3.7).
# syntax=docker/dockerfile:1

FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SERVICE_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# distroless nonroot: no shell, works under any arbitrary UID (OpenShift
# restricted-v2 SCC gets GID 0, so files are group-readable/executable).
FROM gcr.io/distroless/static-debian12:nonroot
ARG SERVICE_VERSION=dev
ENV SERVICE_VERSION=${SERVICE_VERSION}
WORKDIR /app
COPY --from=builder --chown=65532:0 --chmod=750 /out/server /app/server
COPY --chown=65532:0 --chmod=640 config/config.yaml /app/config/config.yaml
USER 65532:0
EXPOSE 8080
ENTRYPOINT ["/app/server"]
CMD ["serve"]
