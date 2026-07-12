package jwt_rsa

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang-jwt/jwt/v5"
	types "happn.io/secret-rotation/pkg/types"
)

func parseRSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rsaKey, nil
}

const (
	PRIVATE_KEY_SECRET_NAME_LABEL = "jwt_rsa__private_key_secret_name"
	SIGNING_METHOD_LABEL             = "jwt_rsa__signing_method"
	AUD_LABEL                     = "jwt_rsa__claims__aud"
	SUB_LABEL                     = "jwt_rsa__claims__sub"
)

type JwtHandler struct {
  ctx   context.Context
  client *secretmanager.Client
  secret *secretmanagerpb.Secret
	projectId string
}

func New(ctx context.Context, client *secretmanager.Client, secret *secretmanagerpb.Secret, projectId string) JwtHandler {
  return JwtHandler{
    ctx:   ctx,
    client: client,
    secret: secret,
		projectId: projectId,
  }
}

func (handler JwtHandler) Name() string {
	return "jwt"
}

func (handler JwtHandler) SigningMethod() *jwt.SigningMethodRSA {
	signingMethodString := handler.secret.Labels[SIGNING_METHOD_LABEL]
	switch signingMethodString {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	default:
		return jwt.SigningMethodRS256 // default to RS256 if unknown method or unspecified
	}
}

func (handler JwtHandler) Handle(msg types.PubSubMessage) error {
	privateKeySecretName := handler.secret.Labels[PRIVATE_KEY_SECRET_NAME_LABEL]
	if privateKeySecretName == "" {
		return fmt.Errorf("%s label is missing in the secret", PRIVATE_KEY_SECRET_NAME_LABEL)
	}
	privateKeySecretVersion, err := handler.client.AccessSecretVersion(handler.ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", handler.projectId, privateKeySecretName),
	})
	if err != nil {
		return fmt.Errorf("failed to get secret version: %v", err)
	}
	privateKey, err := parseRSAPrivateKey(privateKeySecretVersion.Payload.Data)
	if err != nil {
		return fmt.Errorf("failed to parse RSA private key: %v", err)
	}

	sub := handler.secret.Labels[SUB_LABEL]
	if sub == "" {
		return fmt.Errorf("%s label is missing in the secret", SUB_LABEL)
	}
	aud := handler.secret.Labels[AUD_LABEL]
	if aud == "" {
		return fmt.Errorf("%s label is missing in the secret", AUD_LABEL)
	}
	nextRotationTime := handler.secret.Rotation.GetNextRotationTime()
	// Compute JWT 'exp' claim based on the next rotation time, or default to 1 hour if not set
	expirationTime := time.Now().Add(time.Hour)
	if nextRotationTime != nil {
		expirationTime = nextRotationTime.AsTime().Add(time.Hour) // Add 1 hour buffer to ensure the token is valid until the next rotation
	}
	extraClaims := make(map[string]string)
	for key, value := range handler.secret.Labels {
		if strings.HasPrefix(key, "jwt_rsa__claims__") {
			claimKey, _ := strings.CutPrefix(key, "jwt_rsa__claims__")
			extraClaims[claimKey] = value
		}
	}

	token := jwt.NewWithClaims(
		handler.SigningMethod(),
		jwt.MapClaims{
			"iss": "secret-rotator",
			"sub": sub,
			"aud": aud,
			"exp": expirationTime.Unix(),
			"iat": time.Now().Unix(),
		},
	)
	for key, value := range extraClaims {
		token.Claims.(jwt.MapClaims)[key] = value
	}
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign JWT: %v", err)
	}

  _, err = handler.client.AddSecretVersion(handler.ctx, &secretmanagerpb.AddSecretVersionRequest{
    Parent: msg.Attributes.SecretId,
    Payload: &secretmanagerpb.SecretPayload{
      Data: []byte(tokenString),
    },
  })
  if err != nil {
    return err
  }
	return nil
}
