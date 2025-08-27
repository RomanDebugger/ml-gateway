package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"ml-gateway/gateway/metrics"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
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

type unifiedResponseWriter struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func newResponseWriter(w http.ResponseWriter) *unifiedResponseWriter {
	return &unifiedResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           new(bytes.Buffer),
	}
}

func (urw *unifiedResponseWriter) WriteHeader(code int) {
	urw.statusCode = code
	urw.ResponseWriter.WriteHeader(code)
}

func (urw *unifiedResponseWriter) Write(body []byte) (int, error) {
	urw.body.Write(body)
	return urw.ResponseWriter.Write(body)
}

type contextKey string

const responseWriterKey = contextKey("responseWriter")

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		urw := newResponseWriter(w)
		ctx := context.WithValue(r.Context(), responseWriterKey, urw)
		next.ServeHTTP(urw, r.WithContext(ctx))
		duration := time.Since(start).Seconds()
		metrics.HTTPRequestDuration.WithLabelValues(r.URL.Path, r.Method).Observe(duration)
		metrics.HTTPRequestsTotal.WithLabelValues(r.URL.Path, r.Method, strconv.Itoa(urw.statusCode)).Inc()
	})
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

func cachingMiddleware(next http.Handler, logger *slog.Logger, redisClient *redis.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Error("failed to read request body for caching", "error", err)
			http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		hash := sha256.Sum256(bodyBytes)
		cacheKey := fmt.Sprintf("cache:%s:%s", r.URL.Path, hex.EncodeToString(hash[:]))

		cachedResponse, err := redisClient.Get(context.Background(), cacheKey).Bytes()
		if err == nil {
			logger.Info("cache hit", "key", cacheKey)
			w.Header().Set("Content-Type", "application/json")
			w.Write(cachedResponse)
			return
		}
		logger.Info("cache miss", "key", cacheKey)
		next.ServeHTTP(w, r)
		if urw, ok := r.Context().Value(responseWriterKey).(*unifiedResponseWriter); ok {
			if urw.statusCode >= 200 && urw.statusCode < 300 {
				redisClient.Set(context.Background(), cacheKey, urw.body.Bytes(), 10*time.Minute)
			}
		}
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

	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		logger.Info("Starting metrics server", "port", 9091)
		if err := http.ListenAndServe(":9091", metricsMux); err != nil {
			logger.Error("failed to start metrics server", "error", err)
		}
	}()

	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		logger.Error("could not connect to Redis", "error", err)
		os.Exit(1)
	}
	logger.Info("Successfully connected to Redis")

	mux := http.NewServeMux()
	for _, route := range config.Routes {
		targetURL, err := url.Parse(route.ServiceURL)
		if err != nil {
			logger.Error("invalid service URL in config", "path", route.Path, "error", err)
			continue
		}
		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.Transport = &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
		}

		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("request proxied", "path", r.URL.Path, "source_ip", r.RemoteAddr)
			proxy.ServeHTTP(w, r)
		})
		var finalHandler http.Handler = proxyHandler
		finalHandler = cachingMiddleware(finalHandler, logger, redisClient)
		finalHandler = rateLimiterMiddleware(finalHandler, logger)
		finalHandler = authenticationMiddleware(finalHandler, validApiKeys, logger)
		finalHandler = metricsMiddleware(finalHandler)
		mux.Handle(route.Path, finalHandler)
	}

	logger.Info("Starting ML API Gateway", "port", 8080)
	if err := http.ListenAndServe(":8080", mux); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}
}

func loadApiKeys(logger *slog.Logger) ([]string, error) {
	if err := godotenv.Load(".env"); err != nil {
		logger.Warn("could not load .env file", "error", err)
	}
	apiKeysEnv := os.Getenv("API_KEYS")
	if apiKeysEnv == "" {
		return nil, fmt.Errorf("API_KEYS environment variable is not set")
	}
	return strings.Split(apiKeysEnv, ","), nil
}

func loadConfig(logger *slog.Logger) (*Config, error) {
	configFile, err := os.ReadFile("config.yaml")
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %w", err)
	}
	var config Config
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		return nil, fmt.Errorf("could not parse config file: %w", err)
	}
	return &config, nil
}
