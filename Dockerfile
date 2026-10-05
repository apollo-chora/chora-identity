# syntax=docker/dockerfile:1.6
#
# chora-identity Dockerfile — Go service.
#
# Build context = this repository. The service is standalone; shared Chora
# modules (chora-common, chora-contracts) are resolved through Go modules.
#
# Standard invocation:
#   docker buildx build --platform=linux/amd64 \
#     -f Dockerfile \
#     --build-arg SERVICE_NAME=chora-identity \
#     --build-arg GIT_SHA=$(git rev-parse --short HEAD) \
#     --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
#     -t walfa/chora-identity:latest \
#     .

ARG GO_VERSION=1.26.6
ARG ALPINE_VERSION=3.23
ARG SERVICE_NAME=chora-identity
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown

############################
# Stage 1 — build
############################
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder
ARG TARGETARCH

ARG SERVICE_NAME
ARG GIT_SHA
ARG BUILD_TIME

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY . .

RUN go mod download

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=${TARGETARCH}
RUN go build -trimpath -ldflags "-s -w" -o /out/service ./cmd/server

# The seed job ships alongside the server so the same image can provision a
# local admin (idempotent; driven by CHORA_SEED_* env).
RUN go build -trimpath -ldflags "-s -w" -o /out/seed ./cmd/seed

############################
# Stage 2 — runtime
############################
FROM alpine:${ALPINE_VERSION}

ARG SERVICE_NAME
ARG GIT_SHA
ARG BUILD_TIME

RUN apk add --no-cache ca-certificates \
    && addgroup -S app \
    && adduser -S -G app app

LABEL org.opencontainers.image.title="${SERVICE_NAME}" \
      org.opencontainers.image.source="https://github.com/apollo-chora/chora-identity" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_TIME}" \
      io.chora.service="${SERVICE_NAME}"

WORKDIR /

COPY --from=builder /out/service /service
COPY --from=builder /out/seed /seed

# The federated closure-saga subscriber loads this PII map at the default
# relative path config/PII_Closure_Map.yaml (runtime WORKDIR is /). Without
# this COPY the subscriber boots DISABLED.
COPY --from=builder /src/config/PII_Closure_Map.yaml /config/PII_Closure_Map.yaml

USER app:app
ENTRYPOINT ["/service"]
