package main

import (
	"context"
	"errors"
	"log"

	"cloud.google.com/go/pubsub/v2"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"happn.io/secret-rotation/pkg/config"
	"happn.io/secret-rotation/pkg/handlers/gandi"
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

func HandleMessageFactory(cfg config.Config) func(ctx context.Context, msg *pubsub.Message) {
	return func(ctx context.Context, msg *pubsub.Message) {
		// Acknowledge the message
		attributes := types.PubSubAttributes{
			SecretId:   msg.Attributes["secretId"],
			EventType:  msg.Attributes["eventType"],
			DateFormat: msg.Attributes["dateFormat"],
			Timestamp:  msg.Attributes["timestamp"],
			VersionId:  msg.Attributes["versionId"],
			DeleteType: msg.Attributes["deleteType"],
		}
		client, err := secretmanager.NewClient(ctx)
		if err != nil {
			log.Printf("Failed to create secret manager client: %v", err)
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
      msg.Nack()
			return
		}
		log.Printf("Fetched secret: %s", secret.Name)
    handlerName := secret.Labels[cfg.HandlerLabelKey]
    handler, err := GetHandlerByName(handlerName, ctx, client, secret)
    err = handler.Handle(pubsubMsg)
    if err != nil {
      log.Printf("Error handling message with handler %s: %v", handler.Name(), err)
      msg.Nack()
      return
    }
    log.Printf("Successfully handled message with handler %s", handler.Name())
    msg.Ack()
	}
}

func main() {
	cfg := config.LoadConfig()
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, cfg.GcpProjectId)
	if err != nil {
		log.Fatalf("Could not instantiate pubsub client: %s", err)
	}
	sub := client.Subscriber(cfg.PubsubSubscription)
	err = sub.Receive(ctx, HandleMessageFactory(cfg))
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("Error receiving messages: %s", err)
	}
}
