FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.23@sha256:8a5046497cda39860b832ffdbe8dd66018a0f05bb01352f533a36e7e2ced66a0 AS wireproxy-build
ARG WIREPROXY_VERSION=2.1.0
ARG WIREPROXY_COMMIT=02588433b6328171b594d76f3f16bd3404258a83
RUN apk add --no-cache git \
 && git clone --quiet --depth 1 --branch "v${WIREPROXY_VERSION}" https://github.com/bropines/awg-wireproxy.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${WIREPROXY_COMMIT}"
WORKDIR /src
RUN go get golang.org/x/net@v0.62.0 golang.org/x/crypto@v0.58.0 \
 && go mod download \
 && mkdir -p /out \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=v${WIREPROXY_VERSION}" -o /out/wireproxy ./cmd/wireproxy

FROM --platform=$BUILDPLATFORM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS certs
ARG CA_CERTIFICATES_VERSION=20261020-r0
RUN apk add --no-cache "ca-certificates-bundle=${CA_CERTIFICATES_VERSION}"

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine3.23@sha256:8a5046497cda39860b832ffdbe8dd66018a0f05bb01352f533a36e7e2ced66a0 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/awg-switcher ./cmd/awg-switcher

FROM scratch
COPY --from=wireproxy-build /out/wireproxy /usr/local/bin/wireproxy
COPY --from=build /out/awg-switcher /usr/local/bin/awg-switcher
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY LICENSE THIRD_PARTY_NOTICES.md DEPENDENCIES.md /usr/share/doc/awg-switcher/
COPY licenses/ /usr/share/licenses/awg-switcher/
USER 10001:10001
WORKDIR /app
EXPOSE 20171
HEALTHCHECK --interval=20s --timeout=5s --start-period=90s --retries=3 CMD ["/usr/local/bin/awg-switcher", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/awg-switcher"]
