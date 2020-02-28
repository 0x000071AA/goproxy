package main

import (
	"log"
	"net/http"
	"net/url"
)

func main() {
	var targets []*url.URL

	for _, host := range []string{"http://127.0.0.1:8080"} {
		rpURL, err := url.Parse(host)
		if err != nil {
			log.Fatalf("Error parsing url %v", err)
		}
		targets = append(targets, rpURL)
	}

	reverseProxy := NewMultiHostReverseProxy(targets...)

	proxy := &http.Server{
		Addr:    ":80",
		Handler: reverseProxy,
	}

	defer func() {
		err := proxy.Close()
		if err != nil {
			log.Fatalf("Error closing proxy: %v", err)
		}
	}()

	err := proxy.ListenAndServe()
	if err != nil {
		log.Fatal("Error: ", err)
	}
}
