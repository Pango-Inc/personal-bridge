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

go 1.23.2

require github.com/elazarl/goproxy v1.7.0

require (
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
`,
	"go.sum": `
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/elazarl/goproxy v1.7.0 h1:EXv2nV4EjM60ZtsEVLYJG4oBXhDGutMKperpHsZ/v+0=
github.com/elazarl/goproxy v1.7.0/go.mod h1:X/5W/t+gzDyLfHW4DrMdpjqYjpXsURlBt9lpBDxZZZQ=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/stretchr/testify v1.10.0 h1:Xv5erBjTwe/5IxqUQTdXv5kgmIvbHo3QQyRwhJsOfJA=
github.com/stretchr/testify v1.10.0/go.mod h1:r2ic/lqez/lEtzL7wO/rwa5dbSLXVDPFyf8C91i36aY=
golang.org/x/net v0.34.0 h1:Mb7Mrk043xzHgnRM88suvJFwzVrRfHEHJEl5/71CKw0=
golang.org/x/net v0.34.0/go.mod h1:di0qlW3YNM5oh6GqDGQr92MyTozJPmybPK4Ev/Gm31k=
golang.org/x/text v0.21.0 h1:zyQAAkrwaneQ066sspRyJaG9VNi/YJ1NfzcGB3hZ/qo=
golang.org/x/text v0.21.0/go.mod h1:4IBbMaMmOPCJ8SecivzSH54+73PCFmPWxNTLm+vZkEQ=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
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
