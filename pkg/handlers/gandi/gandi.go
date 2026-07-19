package gandi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"happn.io/secret-rotation/pkg/config"
	"happn.io/secret-rotation/pkg/types"
)

// Docs: https://api.gandi.net/docs/organization/#v5-organization-access-tokens

type GandiResponseBodyEntity struct {
  Id string `json:"id"`
  Name string `json:"name"`
  Type string `json:"type"`
}

type GandiResponseBody struct {
  Token string `json:"access_token"`
  Entities []GandiResponseBodyEntity `json:"entities"`
  ExpiresAt time.Time `json:"expires_at"`
  ID string `json:"id"`
  Name string `json:"name"`
  Scopes []string `json:"scopes"`
}

type GandiHandler struct {
  ctx   context.Context
  client *secretmanager.Client
  secret *secretmanagerpb.Secret
	projectId string
	logger *slog.Logger
}

func New(ctx context.Context, client *secretmanager.Client, secret *secretmanagerpb.Secret, cfg config.Config) GandiHandler {
  return GandiHandler{
    ctx:   ctx,
    client: client,
    secret: secret,
		projectId: cfg.GcpProjectId,
		logger: slog.New(slog.NewJSONHandler(
			os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel},
		)).With(
			"component", "secret_handler",
			"handler", "gandi",
		),
  }
}

func (handler GandiHandler) Name() string {
  return "gandi"
}

func (handler GandiHandler) Handle(msg types.PubSubMessage) error {
  token := string(msg.Data)
	handler.logger.InfoContext(handler.ctx, "Performing POST request to Gandi API (https://api.gandi.net/v5/organization/access-tokens)")
  req, err := http.NewRequestWithContext(handler.ctx, "POST", "https://api.gandi.net/v5/organization/access-tokens", nil)
  if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to create HTTP request", "error", err)
    return err
  }
  // Add necessary headers and authentication to the request.
  req.Header.Add("Content-Type", "application/json")
  req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
  resp, err := http.DefaultClient.Do(req)
  if err != nil {
    return err
  }
  defer resp.Body.Close()
  var body GandiResponseBody
  err = json.NewDecoder(resp.Body).Decode(&body)
  if err != nil {
    handler.logger.ErrorContext(handler.ctx, "Failed to decode HTTP response", "error", err)
    return err
  }

  // Process the response and update the secret in Secret Manager.
  _, err = handler.client.AddSecretVersion(handler.ctx, &secretmanagerpb.AddSecretVersionRequest{
    Parent: msg.Attributes.SecretId,
    Payload: &secretmanagerpb.SecretPayload{
      Data: []byte(body.Token),
    },
  })
  if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to add new secret version", "error", err)
    return err
  }
  return nil
}
