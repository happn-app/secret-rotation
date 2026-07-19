package jwt

import (
	"context"
	"crypto/sha1"
	"fmt"
	"log/slog"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"happn.io/secret-rotation/pkg/config"
	types "happn.io/secret-rotation/pkg/types"
	"happn.io/secret-rotation/pkg/utils"
)

const (
	JWK_SECRET_NAME_LABEL = "jwt_rsa__jwk_secret_name"
)

type JwtHandler struct {
  ctx   context.Context
  client *secretmanager.Client
  secret *secretmanagerpb.Secret
	projectId string
	logger *slog.Logger
}

func New(ctx context.Context, client *secretmanager.Client, secret *secretmanagerpb.Secret, cfg config.Config) JwtHandler {
  return JwtHandler{
    ctx:   ctx,
    client: client,
    secret: secret,
		projectId: cfg.GcpProjectId,
		logger : slog.New(slog.NewJSONHandler(
			os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel},
		)).With(
			"component", "secret_handler",
			"handler", "jwt",
		),
  }
}

func (handler JwtHandler) Name() string {
	return "jwt"
}

func (handler JwtHandler) GetJwk() (jwk.Key, error) {
	secretName := handler.secret.Labels[JWK_SECRET_NAME_LABEL]
	if secretName == "" {
		return nil, fmt.Errorf("%s label is missing in the secret", JWK_SECRET_NAME_LABEL)
	}

	jwkSecretVersion, err := handler.client.AccessSecretVersion(handler.ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", handler.projectId, secretName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get JWK secret version: %v", err)
	}

	jwkSet, err := jwk.Parse(jwkSecretVersion.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK set: %v", err)
	}

	if jwkSet.Len() == 0 {
		return nil, fmt.Errorf("JWK set is empty")
	}

	jwk, ok := jwkSet.Key(0)
	if !ok {
		return nil, fmt.Errorf("failed to get JWK from set")
	}
	return jwk, nil
}

func (handler JwtHandler) GetPublicKeyId(publicKeySecretNameLabel string) (string, error) {
	publicKeySecretName := handler.secret.Labels[publicKeySecretNameLabel]

	publicKeyData, err := handler.client.AccessSecretVersion(handler.ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", handler.projectId, publicKeySecretName),
	})
	if err != nil {
		return "", err
	}

	publicKeyPem := publicKeyData.Payload.Data
	hasher := sha1.New()
	hasher.Write(publicKeyPem)
	return fmt.Sprintf("%x", hasher.Sum(nil))[0:8], nil
}

func (handler JwtHandler) Handle(msg types.PubSubMessage) error {
	key, err := handler.GetJwk()
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to get JWK", "error", err)
		return err
	}
	oldJwt, err := jwt.Parse(msg.Data)
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to parse old JWT", "error", err)
		return err
	}

	issuedAt, ok := oldJwt.IssuedAt()
	if !ok {
		handler.logger.ErrorContext(handler.ctx, "Failed to get issued at from old JWT")
		return fmt.Errorf("failed to get issued at from old JWT")
	}
	expiration, ok := oldJwt.Expiration()
	if !ok {
		handler.logger.ErrorContext(handler.ctx, "Failed to get expiration from old JWT")
		return fmt.Errorf("failed to get expiration from old JWT")
	}
	ttl := expiration.Sub(issuedAt)
	newIssuedAt := time.Now()
	newExpiration := newIssuedAt.Add(ttl)
	jti, err := uuid.NewV7()
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to generate new JWT ID", "error", err)
		return err
	}
	oldJwt.Set("iat", newIssuedAt.Unix())
	oldJwt.Set("exp", newExpiration.Unix())
	oldJwt.Set("jti", jti.String())
	oldJwt.Set("iss", "secret-rotator")

	alg, ok := key.Algorithm()
	if !ok {
		handler.logger.ErrorContext(handler.ctx, "Failed to get algorithm from JWK")
		return fmt.Errorf("failed to get algorithm from JWK")
	}
	signedJwt, err := jwt.Sign(oldJwt, jwt.WithKey(alg, key))
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to sign new JWT", "error", err)
		return err
	}
	// Store the new JWT in the secret manager
	_, err = utils.AddSecretVersion(handler.ctx, handler.client, handler.secret.Name, signedJwt)
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to add new secret version", "error", err)
		return err
	}
	return nil
}
