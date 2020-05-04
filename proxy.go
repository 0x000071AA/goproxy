package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

type TargetHostConfig struct {
	Targets []string `yaml:"targets"`
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

	config := getProxyConfig()

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
