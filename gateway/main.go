package main

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Routes []Route `yaml:"routes"`
}

type Route struct {
	Path       string `yaml:"path"`
	ServiceURL string `yaml:"service_url"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	configFile, err := os.ReadFile("../config.yaml")
	if err != nil {
		logger.Error("could not read config file", "error", err)
		os.Exit(1)
	}

	var config Config
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		logger.Error("could not parse config file", "error", err)
		os.Exit(1)
	}

	for _, route := range config.Routes {
		targetURL, err := url.Parse(route.ServiceURL)
		if err != nil {
			logger.Error("Invalid service URL", "path", route.Path, "error", err)
			continue
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		handler := func(p *httputil.ReverseProxy, t *url.URL, path string) func(http.ResponseWriter, *http.Request) {
			return func(w http.ResponseWriter, r *http.Request) {
				logger.Info("request received",
					"method", r.Method,
					"path", r.URL.Path,
					"forwarding_to", t,
				)
				p.ServeHTTP(w, r)
			}
		}(proxy, targetURL, route.Path)

		http.HandleFunc(route.Path, handler)
	}

	logger.Info("Starting ML API Gateway", "port", 8080)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}
