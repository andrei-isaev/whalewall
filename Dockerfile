FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

WORKDIR /build
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .

# build as PIE to take advantage of exploit mitigations
ARG VERSION=devel
ARG TARGETOS
ARG TARGETARCH
RUN --network=none test "${TARGETOS}/${TARGETARCH}" = "linux/amd64" && \
    go build -buildmode pie -buildvcs=false \
    -ldflags "-s -w -X main.version=${VERSION}" -trimpath \
    -o /whalewall ./cmd/whalewall

FROM ghcr.io/capnspacehook/pie-loader:latest@sha256:660685044d849a46508c034ab956ec633c4fd8536a301fd0540b43784a4e8688
COPY --from=builder /whalewall /whalewall

# apparently giving capabilities to containers doesn't work when the
# container isn't running as root inside the container, see
# https://github.com/moby/moby/issues/8460

ENTRYPOINT [ "/whalewall" ]
CMD [ "-d", "/data" ]
