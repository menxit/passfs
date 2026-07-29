ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go test ./...
RUN CGO_ENABLED=0 go build \
	-trimpath \
	-ldflags "-s -w -X main.version=0.1.0-docker" \
	-o /out/passfs \
	./cmd/passfs

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ca-certificates \
		dbus-user-session \
		fuse3 \
		procps \
		systemd \
	&& rm -rf /var/lib/apt/lists/* \
	&& useradd --create-home --shell /bin/bash tester \
	&& install -d -m 0755 /var/lib/systemd/linger \
	&& touch /var/lib/systemd/linger/tester

COPY --from=builder /out/passfs /usr/local/bin/passfs

WORKDIR /home/tester
ENV container=docker
ENV TERM=xterm-256color

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
