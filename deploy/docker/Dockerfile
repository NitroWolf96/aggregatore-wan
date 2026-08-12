# Multi-arch build: docker buildx build --platform linux/amd64,linux/arm64 .
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags '-s -w' -o /out/treccia-server ./cmd/treccia-server && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags '-s -w' -o /out/treccia-client ./cmd/treccia-client

FROM alpine:3.20
RUN apk add --no-cache iproute2 iptables ca-certificates
COPY --from=build /out/treccia-server /out/treccia-client /usr/local/bin/
COPY deploy/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# Needs: --cap-add NET_ADMIN --device /dev/net/tun -p 51820:51820/udp
EXPOSE 51820/udp
ENTRYPOINT ["/entrypoint.sh"]
CMD ["treccia-server", "-config", "/etc/treccia/server.yaml"]
