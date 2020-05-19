package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// ReverseProxy xx
type ReverseProxy struct {
	httputil.ReverseProxy

	currentDirector int
	Directors       []func(req *http.Request)
}

func serveFiles() http.Handler {
	return http.FileServer(http.Dir("./www"))
}

// NewMultiHostReverseProxy xx
func NewMultiHostReverseProxy(targets ...*url.URL) (reverseProxy *ReverseProxy) {
	reverseProxy = &ReverseProxy{currentDirector: 0}

	for _, target := range targets {
		reverseProxy.AddHost(target)
	}

	return reverseProxy
}

// AddHost xx
func (p *ReverseProxy) AddHost(target *url.URL) {
	targetQuery := target.RawQuery
	p.Directors = append(p.Directors, func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = SingleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	})
}

// NextDirector xx
func (p *ReverseProxy) NextDirector() func(*http.Request) {
	// using round robin balancing
	p.currentDirector++
	if p.currentDirector >= len(p.Directors) {
		p.currentDirector = 0
	}
	return p.Directors[p.currentDirector]
}

// ServeHTTP xx
func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.Director = p.NextDirector()
	req.Header.Set("X-Forwarded-For", req.URL.Hostname())
	p.ReverseProxy.ServeHTTP(rw, req)
}
