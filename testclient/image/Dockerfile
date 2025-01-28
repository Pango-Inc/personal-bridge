FROM golang:alpine AS builder

COPY . /app
WORKDIR /app
RUN go build .

FROM alpine:latest
RUN apk add --no-cache wireguard-tools tcpdump vim iproute2 curl lsof bind-tools bash wget jq iptables
COPY --from=builder /app/proxy /usr/local/bin/proxy
