package testclient

// embed docker image sources into the binary
// we cannot use embed.FS, because it does not allow to embed files in different go module

var dockerSources = map[string]string{
	"Dockerfile": `
FROM golang:alpine as builder

COPY . /app
WORKDIR /app
RUN go build .

FROM alpine:latest
RUN apk add --no-cache wireguard-tools tcpdump vim iproute2 curl lsof bind-tools bash wget jq iptables
COPY --from=builder /app/proxy /usr/local/bin/proxy
`,
	"go.mod": `
module proxy

go 1.23

require (
	github.com/elazarl/goproxy v0.0.0-20240909085733-6741dbfc16a1 // indirect
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/text v0.16.0 // indirect
)
`,
	"go.sum": `
github.com/elazarl/goproxy v0.0.0-20240909085733-6741dbfc16a1 h1:g7YUigN4dW2+zpdusdTTghZ+5Py3BaUMAStvL8Nk+FY=
github.com/elazarl/goproxy v0.0.0-20240909085733-6741dbfc16a1/go.mod h1:thX175TtLTzLj3p7N/Q9IiKZ7NF+p72cvL91emV0hzo=
golang.org/x/net v0.26.0 h1:soB7SVo0PWrY4vPW/+ay0jKDNScG2X9wFeYlXIvJsOQ=
golang.org/x/net v0.26.0/go.mod h1:5YKkiSynbBIh3p6iOc/vibscux0x38BZDkn8sCUPxHE=
golang.org/x/text v0.16.0 h1:a94ExnEXNtEwYLGJSIUxnWoxoRz/ZcCsV63ROupILh4=
golang.org/x/text v0.16.0/go.mod h1:GhwF1Be+LQoKShO3cGOHzqOgRrGaYc9AvblQOmPVHnI=
`,

	"main.go": `
package main

import (
	"github.com/elazarl/goproxy"
	"log"
	"net/http"
)

func main() {
	log.Println("Starting proxy on :8080")
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	log.Fatal(http.ListenAndServe(":8080", proxy))
}
`,
}
