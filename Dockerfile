FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS wireproxy
ARG WIREPROXY_VERSION=2.1.0
ARG WIREPROXY_SHA256=aa05dbc67198b56417334e4aa8bfca73cd23ba946eb70e1c7205b2319d618311
ARG CA_CERTIFICATES_VERSION=20261020-r0
RUN apk add --no-cache "ca-certificates-bundle=${CA_CERTIFICATES_VERSION}" \
 && wget -q "https://github.com/bropines/awg-wireproxy/releases/download/v${WIREPROXY_VERSION}/awg-wireproxy_${WIREPROXY_VERSION}_linux_amd64.tar.gz" -O /tmp/wireproxy.tgz \
 && echo "${WIREPROXY_SHA256}  /tmp/wireproxy.tgz" | sha256sum -c - \
 && mkdir -p /out && tar -xzf /tmp/wireproxy.tgz -C /out

FROM golang:1.27.1-alpine3.23@sha256:0908ac9b9319e09d7c238aabe914e0395c51d63c4e3d0ae8c554fda9158a5769 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/awg-switcher ./cmd/awg-switcher

FROM scratch
COPY --from=wireproxy /out/wireproxy /usr/local/bin/wireproxy
COPY --from=build /out/awg-switcher /usr/local/bin/awg-switcher
COPY --from=wireproxy /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY LICENSE THIRD_PARTY_NOTICES.md DEPENDENCIES.md /usr/share/doc/awg-switcher/
COPY licenses/ /usr/share/licenses/awg-switcher/
USER 10001:10001
WORKDIR /app
EXPOSE 20171
HEALTHCHECK --interval=20s --timeout=5s --start-period=90s --retries=3 CMD ["/usr/local/bin/awg-switcher", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/awg-switcher"]
