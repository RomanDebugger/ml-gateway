package main

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Routes []Route `yaml:"routes"`
}

type Route struct {
	Path       string `yaml:"path"`
	ServiceURL string `yaml:"service_url"`
}

func authenticationMiddleware(next http.Handler, validKeys []string, logger *slog.Logger) http.Handler {
	keySet := make(map[string]struct{})
	for _, key := range validKeys {
		keySet[key] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")

		if _, found := keySet[apiKey]; !found {
			logger.Warn("invalid API key", "key", apiKey, "remote_addr", r.RemoteAddr)
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	err := godotenv.Load("../.env")
	if err != nil {
		logger.Warn("Error loading .env file, continuing without it")
	}
	apiKeysEnv := os.Getenv("API_KEYS")
	if apiKeysEnv == "" {
		logger.Error("API_KEYS environment variable not set. Shutting down.")
		os.Exit(1)
	}
	validApiKeys := strings.Split(apiKeysEnv, ",")

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

	mux := http.NewServeMux()
	for _, route := range config.Routes {
		targetURL, err := url.Parse(route.ServiceURL)
		if err != nil {
			logger.Error("Invalid service URL", "path", route.Path, "error", err)
			continue
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("request received", "method", r.Method, "path", r.URL.Path, "forwarding_to", targetURL)
			proxy.ServeHTTP(w, r)
		})
		authedHandler := authenticationMiddleware(proxyHandler, validApiKeys, logger)
		mux.HandleFunc(route.Path, authedHandler.ServeHTTP)
	}

	logger.Info("Starting ML API Gateway", "port", 8080)
	if err := http.ListenAndServe(":8080", mux); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}
