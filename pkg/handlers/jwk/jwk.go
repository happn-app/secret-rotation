package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"happn.io/secret-rotation/pkg/config"
	"happn.io/secret-rotation/pkg/types"
	"happn.io/secret-rotation/pkg/utils"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

type JWKHandler struct {
	ctx       context.Context
	client    *secretmanager.Client
	secret    *secretmanagerpb.Secret
	projectId string
	logger    *slog.Logger
}

func New(ctx context.Context, client *secretmanager.Client, secret *secretmanagerpb.Secret, cfg config.Config) JWKHandler {
	return JWKHandler{
		ctx:       ctx,
		client:    client,
		secret:    secret,
		projectId: cfg.GcpProjectId,
		logger: slog.New(slog.NewJSONHandler(
			os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel},
		)).With(
			"component", "secret_handler",
			"handler", "jwk",
		),
	}
}

func (handler JWKHandler) Name() string {
	return "jwk"
}

func (handler JWKHandler) NewRSAJWK(algorithm string, keyBits int) (jwk.Key, error) {
	rsaRaw, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	rsaKey, err := jwk.Import[jwk.RSAPrivateKey](rsaRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to import RSA key: %w", err)
	}
	return rsaKey, nil
}

func (handler JWKHandler) NewECDSAJWK(algorithm string, keyBits int) (jwk.Key, error) {
	var curve elliptic.Curve
	switch keyBits {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported key size: %d", keyBits)
	}
	ecRaw, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	ecKey, err := jwk.Import[jwk.ECDSAPrivateKey](ecRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to import ECDSA key: %w", err)
	}
	return ecKey, nil
}

func (handler JWKHandler) NewEd25519JWK(algorithm string, keyBits int) (jwk.Key, error) {
	_, edRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	edKey, err := jwk.Import[jwk.Key](edRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to import Ed25519 key: %w", err)
	}
	return edKey, nil
}

func (handler JWKHandler) NewOctJWK(algorithm string, keyBits int) (jwk.Key, error) {
	octKey := make([]byte, keyBits/8)
	_, err := rand.Read(octKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate oct key: %w", err)
	}
	key, err := jwk.Import[jwk.Key](octKey)
	if err != nil {
		return nil, fmt.Errorf("failed to import oct key: %w", err)
	}
	return key, nil
}

func (handler JWKHandler) NewRSASSAJWK(algorithm string, keyBits int) (jwk.Key, error) {
	rsaRaw, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	rsaKey, err := jwk.Import[jwk.RSAPrivateKey](rsaRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to import RSA key: %w", err)
	}
	return rsaKey, nil
}

func (handler JWKHandler) GetNewJwk(algorithm string, keyBits int) (jwk.Key, error) {
	switch algorithm {
	case "RS256":
	case "RS384":
	case "RS512":
		return handler.NewRSAJWK(algorithm, keyBits)
	case "ES256":
	case "ES384":
	case "ES512":
		return handler.NewECDSAJWK(algorithm, keyBits)
	case "HS256":
	case "HS384":
	case "HS512":
		return handler.NewOctJWK(algorithm, keyBits)
	case "EdDSA":
		return handler.NewEd25519JWK(algorithm, keyBits)
	case "PS256":
	case "PS384":
	case "PS512":
		return handler.NewRSASSAJWK(algorithm, keyBits)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
}

func (handler JWKHandler) Handle(msg types.PubSubMessage) error {
	jwkSet, err := jwk.Parse(msg.Data)
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to parse JWK set", "error", err)
		return err
	}
	oldJwk, ok := jwkSet.Key(0)
	if !ok {
		handler.logger.ErrorContext(handler.ctx, "Failed to get JWK from set")
		return fmt.Errorf("failed to get JWK from set")
	}
	algorithm, ok := oldJwk.Algorithm()
	if !ok {
		handler.logger.ErrorContext(handler.ctx, "Failed to get algorithm from JWK")
		return fmt.Errorf("failed to get algorithm from JWK")
	}
	keyBits, err := GetKeyBits(oldJwk)
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to get key bits from JWK", "error", err)
		return err
	}
	newJwk, err := handler.GetNewJwk(algorithm.String(), keyBits)
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to get new JWK", "error", err)
		return err
	}
	err = jwk.AssignKeyID(newJwk)
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to assign key ID to new JWK", "error", err)
		return err
	}

	marshalled, err := json.Marshal(newJwk)
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to marshal new JWK", "error", err)
		return err
	}
	_, err = utils.AddSecretVersion(handler.ctx, handler.client, handler.secret.Name, marshalled)
	if err != nil {
		handler.logger.ErrorContext(handler.ctx, "Failed to add new secret version", "error", err)
		return err
	}
	return nil
}
