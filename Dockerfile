# syntax=docker/dockerfile:1
FROM golang:1.27 AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=v1.0.1
ARG COMMIT=dev
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/oskal ./cmd/oskal && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/oskal-controller ./cmd/oskal-controller

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source="https://github.com/ckodex-labs/ckodex-oskal" \
      org.opencontainers.image.description="CKODEX OSKAL Continuous Assurance Controller and CLI" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /
COPY --from=builder /out/oskal /oskal
COPY --from=builder /out/oskal-controller /oskal-controller
USER 65532:65532

ENTRYPOINT ["/oskal-controller"]
