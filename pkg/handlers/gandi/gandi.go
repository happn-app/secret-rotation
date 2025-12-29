package gandi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
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
}

func New(ctx context.Context, client *secretmanager.Client, secret *secretmanagerpb.Secret) GandiHandler {
  return GandiHandler{
    ctx:   ctx,
    client: client,
    secret: secret,
  }
}

func (handler GandiHandler) Name() string {
  return "gandi"
}

func (handler GandiHandler) Handle(msg types.PubSubMessage) error {
  token := string(msg.Data)
  // Implement the logic to rotate Gandi API key here.
  req, err := http.NewRequestWithContext(handler.ctx, "POST", "https://api.gandi.net/v5/organization/access-tokens", nil)
  if err != nil {
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
    return err
  }
  return nil
}
