package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
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
			logger.Warn("invalid API key provided", "key", apiKey, "source_ip", r.RemoteAddr)
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func rateLimiterMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	limiters := make(map[string]*rate.Limiter)
	var mu sync.Mutex

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		mu.Lock()
		if _, found := limiters[apiKey]; !found {
			limiters[apiKey] = rate.NewLimiter(5, 10)
		}
		limiter := limiters[apiKey]
		mu.Unlock()

		if !limiter.Allow() {
			logger.Warn("rate limit exceeded", "key", apiKey, "source_ip", r.RemoteAddr)
			http.Error(w, `{"error": "Too Many Requests"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	validApiKeys, err := loadApiKeys(logger)
	if err != nil {
		logger.Error("failed to load API keys", "error", err)
		os.Exit(1)
	}

	config, err := loadConfig(logger)
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	for _, route := range config.Routes {
		targetURL, err := url.Parse(route.ServiceURL)
		if err != nil {
			logger.Error("invalid service URL in config", "path", route.Path, "url", route.ServiceURL, "error", err)
			continue
		}
		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("request proxied", "path", r.URL.Path, "source_ip", r.RemoteAddr)
			proxy.ServeHTTP(w, r)
		})
		var finalHandler http.Handler = proxyHandler
		finalHandler = rateLimiterMiddleware(finalHandler, logger)
		finalHandler = authenticationMiddleware(finalHandler, validApiKeys, logger)
		mux.Handle(route.Path, finalHandler)
	}

	logger.Info("Starting ML API Gateway", "port", 8080)
	if err := http.ListenAndServe(":8080", mux); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}

func loadApiKeys(logger *slog.Logger) ([]string, error) {
	if err := godotenv.Load("../.env"); err != nil {
		logger.Warn("could not load .env file", "error", err)
	}

	apiKeysEnv := os.Getenv("API_KEYS")
	if apiKeysEnv == "" {
		return nil, fmt.Errorf("API_KEYS environment variable is not set")
	}
	return strings.Split(apiKeysEnv, ","), nil
}

func loadConfig(logger *slog.Logger) (*Config, error) {
	configFile, err := os.ReadFile("../config.yaml")
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		return nil, fmt.Errorf("could not parse config file: %w", err)
	}
	return &config, nil
}
