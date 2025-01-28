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
