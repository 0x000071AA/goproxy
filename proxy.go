package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
)

func main() {
	var targets []*url.URL

	r := mux.NewRouter()

	r.HandleFunc("/")

	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode()
	})

	r.HandleFunc("/users").Methods("GET")
	r.HandleFunc("/users/{user}").Methods("POST")
	r.HandleFunc("/users/{user}").Methods("PUT")
	r.HandleFunc("/users/{user}").Methods("DELETE")

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
