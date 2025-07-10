package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jkoelker/schwab-proxy/api"
	"github.com/jkoelker/schwab-proxy/auth"
	"github.com/jkoelker/schwab-proxy/config"
	"github.com/jkoelker/schwab-proxy/log"
	"github.com/jkoelker/schwab-proxy/observability"
	"github.com/jkoelker/schwab-proxy/proxy"
	"github.com/jkoelker/schwab-proxy/storage"
	tls "github.com/jkoelker/schwab-proxy/tls"
)

const (
	// otelShutdownTimeout is the timeout for shutting down OpenTelemetry providers.
	otelShutdownTimeout = 5 * time.Second
	// serverReadTimeout is the timeout for reading HTTP requests.
	serverReadTimeout = 15 * time.Second
	// serverWriteTimeout is the timeout for writing HTTP responses.
	serverWriteTimeout = 15 * time.Second
	// serverIdleTimeout is the timeout for idle connections.
	serverIdleTimeout = 30 * time.Second
	// gracefulShutdownTimeout is the timeout for graceful shutdown.
	gracefulShutdownTimeout = 15 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize structured logging
	log.InitializeLogger(cfg.DebugLogging)

	// Create base context for the application
	ctx := context.Background()

	// Initialize OpenTelemetry
	otelProviders, err := initializeOTel(ctx, cfg)
	if err != nil {
		return err
	}
	defer shutdownOTel(otelProviders)

	// Initialize storage
	store, err := initializeStorage(ctx, cfg)
	if err != nil {
		return err
	}

	defer func() { _ = store.Close() }()

	// Initialize services and providers
	tokenService, clientService, providerClient := initializeServices(ctx, cfg, store)

	// Initialize TLS manager
	tlsManager, err := initializeTLS(ctx, cfg)
	if err != nil {
		return err
	}

	// Create and start server
	server, apiProxy, err := createServer(
		cfg,
		providerClient,
		tokenService,
		clientService,
		store,
		otelProviders,
		tlsManager,
	)
	if err != nil {
		return err
	}

	startServer(ctx, server)

	// Handle graceful shutdown
	return handleShutdown(ctx, server, apiProxy)
}

// initializeOTel initializes OpenTelemetry and returns providers.
func initializeOTel(ctx context.Context, cfg *config.Config) (*observability.OTelProviders, error) {
	otelProviders, err := observability.InitializeOTel(ctx, cfg)
	if err != nil {
		log.Error(ctx, err, "Failed to initialize OpenTelemetry")

		return nil, fmt.Errorf("failed to initialize OpenTelemetry: %w", err)
	}

	return otelProviders, nil
}

// shutdownOTel shuts down OpenTelemetry providers.
func shutdownOTel(otelProviders *observability.OTelProviders) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), otelShutdownTimeout)
	defer cancel()

	if err := otelProviders.Shutdown(shutdownCtx); err != nil {
		log.Error(shutdownCtx, err, "Failed to shutdown OpenTelemetry providers")
	}
}

// initializeStorage initializes the storage system.
func initializeStorage(ctx context.Context, cfg *config.Config) (*storage.Store, error) {
	// Get KDF parameters from config
	kdfParams, err := cfg.GetStorageKDFParams()
	if err != nil {
		log.Error(ctx, err, "Failed to get storage KDF parameters")

		return nil, fmt.Errorf("failed to get storage KDF parameters: %w", err)
	}

	// Initialize storage with migration support
	store, err := storage.NewStoreWithMigration(ctx, cfg.DataPath, []byte(cfg.StorageSeed), kdfParams)
	if err != nil {
		log.Error(ctx, err, "Failed to initialize storage", "data_path", cfg.DataPath)

		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	return store, nil
}

// initializeServices initializes the application services.
func initializeServices(ctx context.Context, cfg *config.Config, store *storage.Store) (
	*auth.TokenService,
	*auth.ClientService,
	*api.SchwabClient,
) {
	tokenService := auth.NewTokenService(store)
	clientService := auth.NewClientService(store)

	// Initialize API client with provider-specific implementation
	providerClient := api.NewSchwabClient(cfg, tokenService)

	// Try to initialize with existing token
	err := providerClient.Initialize(ctx)
	if err != nil {
		log.Warn(ctx, "No existing token found", "error", err.Error())
		log.Info(ctx, "Use the /setup endpoint to authenticate")
	} else {
		log.Info(ctx, "Successfully loaded existing provider token")
	}

	return tokenService, clientService, providerClient
}

// initializeTLS initializes the TLS manager.
func initializeTLS(ctx context.Context, cfg *config.Config) (*tls.Manager, error) {
	tlsManager := tls.NewManager(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err := tlsManager.Initialize(ctx); err != nil {
		log.Error(ctx, err, "Failed to initialize TLS")

		return nil, fmt.Errorf("failed to initialize TLS: %w", err)
	}

	return tlsManager, nil
}

// createServer creates and configures the HTTP server.
func createServer(
	cfg *config.Config,
	providerClient *api.SchwabClient,
	tokenService *auth.TokenService,
	clientService *auth.ClientService,
	store *storage.Store,
	otelProviders *observability.OTelProviders,
	tlsManager *tls.Manager,
) (*http.Server, *proxy.APIProxy, error) {
	// Create API proxy
	apiProxy, err := proxy.NewAPIProxy(
		cfg,
		providerClient,
		tokenService,
		clientService,
		store,
		otelProviders,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create API proxy: %w", err)
	}

	// Create HTTP server with middleware
	addr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.Port)

	// Wrap the API proxy with middleware stack
	// Order: CorrelationID -> Logging -> Metrics -> Tracing -> APIProxy
	loggingOpts := []func(*log.LoggingOptions){}
	if !cfg.DebugHealthChecks {
		loggingOpts = append(loggingOpts, log.WithDebugHealthChecks(false))
	}

	handler := log.CorrelationIDMiddleware(
		log.LoggingMiddleware(
			observability.MetricsMiddleware(
				observability.TracingMiddleware(apiProxy),
			),
			loggingOpts...,
		),
	)

	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
		TLSConfig:    tlsManager.Config(),
	}

	return server, apiProxy, nil
}

// startServer starts the HTTP server in a goroutine.
func startServer(ctx context.Context, server *http.Server) {
	log.Info(ctx, "HTTPS server starting", "address", server.Addr)

	// Start server in background
	go func() {
		// ListenAndServeTLS with empty cert/key paths since we're using GetCertificate
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(
			err,
			http.ErrServerClosed,
		) {
			log.Error(ctx, err, "Server error")
		}
	}()
}

// handleShutdown handles graceful shutdown of the server.
func handleShutdown(ctx context.Context, server *http.Server, apiProxy *proxy.APIProxy) error {
	// Set up graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until signal received
	<-shutdown
	log.Info(ctx, "Shutting down server")

	// Create shutdown context with timeout derived from main context
	shutdownCtx, cancel := context.WithTimeout(ctx, gracefulShutdownTimeout)
	defer cancel()

	// Shutdown background services first
	apiProxy.Shutdown()

	// Shutdown server
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error(ctx, err, "Server shutdown error")

		return fmt.Errorf("server shutdown error: %w", err)
	}

	log.Info(ctx, "Server gracefully stopped")

	return nil
}
