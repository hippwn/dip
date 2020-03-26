package main

import (

	//"crypto/x509"

	"net/http"

	//	"strings"

	"./proxy"
)

// A very simple http proxy

func main() {
	//simpleProxyHandler := http.HandlerFunc(simpleProxyHandlerFunc)
	p := &proxy.Proxy{}
	http.ListenAndServe(":8080", p)
	//createCerts("test")
}
