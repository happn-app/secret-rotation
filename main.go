package main

import (
	"context"
	"errors"
	"log"
	"net/http"
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
	"happn.io/secret-rotation/pkg/http_handler"
	"happn.io/secret-rotation/pkg/metrics"
	"happn.io/secret-rotation/pkg/types"
)

func GetHandlerByName(name string, ctx context.Context, client *secretmanager.Client, secret *secretmanagerpb.Secret) (types.SecretRotationHandler, error) {
	switch name {
	case "gandi":
		return gandi.New(ctx, client, secret), nil
	default:
		return nil, errors.New("unknown handler: " + name)
	}
}

func HandleMessageFactory(cfg config.Config, metrics *metrics.Metrics) func(ctx context.Context, msg *pubsub.Message) {
	return func(ctx context.Context, msg *pubsub.Message) {
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
			log.Printf("Failed to create secret manager client: %v", err)
			metrics.RotationErrorCount.WithLabelValues("secret_manager_client_creation_error", attributes.SecretId, "").Inc()
			msg.Nack()
			return
		}
		defer client.Close()
		pubsubMsg := types.PubSubMessage{
			Attributes: attributes,
			Data:       msg.Data,
		}
		log.Printf("Received message for secret: %s, event type: %s", attributes.SecretId, attributes.EventType)
		secret, err := client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
			Name: attributes.SecretId,
		})
		if err != nil {
			log.Printf("Failed to get secret: %v", err)
			metrics.RotationErrorCount.WithLabelValues("secret_fetch_error", attributes.SecretId, "").Inc()
			msg.Nack()
			return
		}
		log.Printf("Fetched secret: %s", secret.Name)
		handlerName := secret.Labels[cfg.HandlerLabelKey]
		if handlerName == "" {
			log.Printf("No handler label found for secret: %s", secret.Name)
			metrics.RotationErrorCount.WithLabelValues("missing_handler_label", attributes.SecretId, "").Inc()
			msg.Nack()
			return
		}
		handler, err := GetHandlerByName(handlerName, ctx, client, secret)
		if err != nil {
			log.Printf("Failed to get handler: %v", err)
			metrics.RotationErrorCount.WithLabelValues("handler_fetch_error", attributes.SecretId, handlerName).Inc()
			msg.Nack()
			return
		}
		log.Printf("Using handler: %s for secret: %s", handler.Name(), secret.Name)
		err = handler.Handle(pubsubMsg)
		metrics.RotationDuration.WithLabelValues(handler.Name(), attributes.SecretId).
    Observe(time.Since(start).Seconds())

		if err != nil {
			log.Printf("Error handling message with handler %s: %v", handler.Name(), err)
			metrics.RotationErrorCount.WithLabelValues("handler_execution_error", attributes.SecretId, handler.Name()).Inc()
			msg.Nack()
			return
		}
		metrics.RotationCount.WithLabelValues(handler.Name(), attributes.SecretId).Inc()
		log.Printf("Successfully handled message with handler %s", handler.Name())
		msg.Ack()
	}
}

func main() {
	cfg := config.LoadConfig()
	ctx := context.Background()
	reg := prometheus.NewRegistry()

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

	log.Printf("listening on %s", cfg.Host)
	go func() {
		if err := http.ListenAndServe(cfg.Host, mux); err != nil {
			log.Fatalf("server exited: %v", err)
		}
	}()

	client, err := pubsub.NewClient(ctx, cfg.GcpProjectId)
	if err != nil {
		log.Fatalf("Could not instantiate pubsub client: %s", err)
	}
	sub := client.Subscriber(cfg.PubsubSubscription)
	err = sub.Receive(ctx, HandleMessageFactory(cfg, metrics))
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("Error receiving messages: %s", err)
	}
}
