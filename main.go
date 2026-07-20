package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/pubsub/v2"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"happn.io/secret-rotation/pkg/config"
	"happn.io/secret-rotation/pkg/handlers/gandi"
	"happn.io/secret-rotation/pkg/handlers/jwk"
	"happn.io/secret-rotation/pkg/handlers/jwt"
	"happn.io/secret-rotation/pkg/handlers/password"
	"happn.io/secret-rotation/pkg/http_handler"
	"happn.io/secret-rotation/pkg/metrics"
	"happn.io/secret-rotation/pkg/types"
)

func GetHandlerByName(ctx context.Context, name string, client *secretmanager.Client, secret *secretmanagerpb.Secret, cfg config.Config) (types.SecretRotationHandler, error) {
	switch name {
	case "gandi":
		return gandi.New(ctx, client, secret, cfg), nil
	case "jwt":
		return jwt.New(ctx, client, secret, cfg), nil
	case "jwk":
		return jwk.New(ctx, client, secret, cfg), nil
	case "password":
		return password.New(ctx, client, secret, cfg), nil
	default:
		return nil, errors.New("unknown handler: " + name)
	}
}

func HandleMessageFactory(cfg config.Config, metrics *metrics.Metrics) func(ctx context.Context, msg *pubsub.Message) {
	return func(ctx context.Context, msg *pubsub.Message) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
		start := time.Now()
		attributes := types.PubSubAttributes{
			SecretId:   msg.Attributes["secretId"],
			EventType:  msg.Attributes["eventType"],
			DateFormat: msg.Attributes["dateFormat"],
			Timestamp:  msg.Attributes["timestamp"],
			VersionId:  msg.Attributes["versionId"],
			DeleteType: msg.Attributes["deleteType"],
		}
		if attributes.EventType != "SECRET_ROTATE" {
			msg.Ack()
			return
		}
		client, err := secretmanager.NewClient(ctx)
		if err != nil {
			logger.With("component", "secretmanager").ErrorContext(ctx, "Failed to create secret manager client", "error", err)
			metrics.RotationErrorCount.WithLabelValues("secret_manager_client_creation_error", attributes.SecretId, "").Inc()
			msg.Nack()
			return
		}
		defer client.Close()
		pubsubMsg := types.PubSubMessage{
			Attributes: attributes,
			Data:       msg.Data,
		}
		logger.With("component", "pubsub").InfoContext(ctx, "Received message for secret: %s, event type: %s", attributes.SecretId, attributes.EventType)
		secret, err := client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
			Name: attributes.SecretId,
		})
		if err != nil {
			logger.With("component", "secretmanager").ErrorContext(ctx, "Failed to get secret", "error", err)
			metrics.RotationErrorCount.WithLabelValues("secret_fetch_error", attributes.SecretId, "").Inc()
			msg.Nack()
			return
		}
		logger.With("component", "secretmanager").InfoContext(ctx, "Fetched secret", "secret_name", secret.Name)
		handlerName := secret.Labels[cfg.HandlerLabelKey]
		if handlerName == "" {
			logger.With("component", "secretmanager").ErrorContext(ctx, "No handler label found for secret", "secret_name", secret.Name)
			metrics.RotationErrorCount.WithLabelValues("missing_handler_label", attributes.SecretId, "").Inc()
			msg.Nack()
			return
		}
		handler, err := GetHandlerByName(ctx, handlerName, client, secret, cfg)
		if err != nil {
			logger.With("component", "secretmanager").ErrorContext(ctx, "Failed to get handler", "error", err)
			metrics.RotationErrorCount.WithLabelValues("handler_fetch_error", attributes.SecretId, handlerName).Inc()
			msg.Nack()
			return
		}
		logger.With("component", "secretmanager").InfoContext(ctx, "Using handler", "handler_name", handler.Name(), "secret_name", secret.Name)
		err = handler.Handle(pubsubMsg)
		metrics.RotationDuration.WithLabelValues(handler.Name(), attributes.SecretId).
			Observe(time.Since(start).Seconds())

		if err != nil {
			logger.With("component", "secretmanager").ErrorContext(ctx, "Error handling message with handler", "handler_name", handler.Name(), "error", err)
			metrics.RotationErrorCount.WithLabelValues("handler_execution_error", attributes.SecretId, handler.Name()).Inc()
			msg.Nack()
			return
		}
		metrics.RotationCount.WithLabelValues(handler.Name(), attributes.SecretId).Inc()
		logger.With("component", "secretmanager").InfoContext(ctx, "Successfully handled message with handler", "handler_name", handler.Name())
		msg.Ack()
	}
}

func main() {
	ctx := context.Background()
	cfg := config.LoadConfig(ctx)
	reg := prometheus.NewRegistry()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	// Add go runtime metrics and process collectors.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		version.NewCollector("secret-rotation"),
	)
	metrics := metrics.New(reg)

	// Expose /metrics HTTP endpoint using the created custom registry.
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", http_handler.ReadyHandler)
	mux.HandleFunc("/healthz", http_handler.HealthHandler)
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))

	logger.With("component", "http").InfoContext(ctx, "listening on", "host", cfg.Host)
	go func() {
		if err := http.ListenAndServe(cfg.Host, mux); err != nil {
			logger.With("component", "http").ErrorContext(ctx, "server exited", "error", err)
		}
	}()

	client, err := pubsub.NewClient(ctx, cfg.GcpProjectId)
	if err != nil {
		logger.With("component", "pubsub").ErrorContext(ctx, "Could not instantiate pubsub client", "error", err)
	}
	sub := client.Subscriber(cfg.PubsubSubscription)
	err = sub.Receive(ctx, HandleMessageFactory(cfg, metrics))
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.With("component", "pubsub").ErrorContext(ctx, "Error receiving messages", "error", err)
	}
}
