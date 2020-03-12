package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
)

func main() {
	var targets []*url.URL

	r := mux.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "application/json")
			next.ServeHTTP(w, r)
		})
	})

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			t, _ := template.ParseFiles("www/authentication.gohtml")
			t.Execute(w, nil)
		} else {
			r.ParseForm()
			//r.Form["user"]
			//r.Form["password"]
		}
	})

	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode("{ health : true }")
	})

	r.HandleFunc("/users", GetUser).Methods("GET")
	r.HandleFunc("/users/{user}", CreateUser).Methods("POST")
	r.HandleFunc("/users/{user}", UpdateUser).Methods("PUT")
	r.HandleFunc("/users/{user}", DeleteUser).Methods("DELETE")

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
