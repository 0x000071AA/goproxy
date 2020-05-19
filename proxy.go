package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/mux"
	yaml "gopkg.in/yaml.v3"
)

type TargetHostConfig struct {
	Passthrough    bool     `yaml:"passthrough"`
	Targets        []string `yaml:"targets"`
	ReadinessProbe string   `yaml:"readinessProbe"`
	AllowedPaths   []string `yaml:"allowed"`
	Paths          []string `yaml:"paths"`
}

func getProxyConfig() TargetHostConfig {
	basedir, exists := os.LookupEnv(ProxyConfigDirectory)
	if !exists {
		log.Panic("no config directory")
	}
	yamlFile, err := ioutil.ReadFile(basedir)
	if err != nil {
		log.Panic("can not read config file: " + err.Error())
	}

	var config TargetHostConfig

	errUnmarshal := yaml.Unmarshal(yamlFile, &config)
	if errUnmarshal != nil {
		log.Panic("no valid yaml: " + errUnmarshal.Error())
	}

	return config
}

func main() {
	var targets []*url.URL

	// http://127.0.0.1:8080

	proxyConfPtr := flag.String("proxy_config", "nil", "Base directory for proxy config file")
	certbotConfPtr := flag.String("certbot_config", "nil", "Base directory for certbot config file")

	flag.Parse()

	if *proxyConfPtr == "nil" && *certbotConfPtr == "nil" {
		flag.Usage()
	}

	if err := os.Setenv(ProxyConfigDirectory, *proxyConfPtr); err != nil {
		log.Panic("could not set [proxy_conf]")
	}
	if err := os.Setenv(CertBotConfigDirectory, *certbotConfPtr); err != nil {
		log.Panic("could not set [certbot_config]")
	}

	//???
	StartCertBot()

	config := getProxyConfig()

	r := mux.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "application/json")
			next.ServeHTTP(w, r)
		})
	})

	r.Use(AuthenticationMiddleware(config))

	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(`{ "health" : true }`)
	})

	r.HandleFunc("/readiness", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("using readinessprobe: %s", config.ReadinessProbe)
		resp, err := http.Get(config.ReadinessProbe)
		if err != nil || resp.StatusCode != http.StatusOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	for _, host := range config.Targets {
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
