package rsa

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"happn.io/secret-rotation/pkg/types"
)

const (
	RSA_PUBLIC_KEY_SECRET_NAME_LABEL = "rsa__public_key_secret_name"
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

type RSAHandler struct {
  ctx   context.Context
  client *secretmanager.Client
  secret *secretmanagerpb.Secret
	projectId string
}

func New(ctx context.Context, client *secretmanager.Client, secret *secretmanagerpb.Secret, projectId string) RSAHandler {
  return RSAHandler{
    ctx:   ctx,
    client: client,
    secret: secret,
		projectId: projectId,
  }
}

func (handler RSAHandler) Name() string {
  return "rsa"
}

func (handler RSAHandler) GetKeyLength() (int, error) {
	latestVersion, err := handler.client.AccessSecretVersion(handler.ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: handler.secret.Name + "/versions/latest",
	})
	if err != nil {
		return 0, fmt.Errorf("failed to access secret version: %v", err)
	}
	currentSecretData := latestVersion.Payload.GetData()
	privateKey, err := parseRSAPrivateKey(currentSecretData)
	if err != nil {
		return 0, fmt.Errorf("failed to parse RSA private key: %v", err)
	}
	return privateKey.N.BitLen(), nil
}

func (handler RSAHandler) Handle(msg types.PubSubMessage) error {
	publicKeySecret, err := handler.client.GetSecret(handler.ctx, &secretmanagerpb.GetSecretRequest{
		Name: handler.secret.Labels[RSA_PUBLIC_KEY_SECRET_NAME_LABEL],
	})
	if err != nil {
		return fmt.Errorf("failed to get public key secret: %v", err)
	}
	keyLength, err := handler.GetKeyLength()
	if err != nil {
		return fmt.Errorf("failed to get key length: %v", err)
	}
	newKey, err := rsa.GenerateKey(nil, keyLength)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %v", err)
	}

	_, err = handler.client.AddSecretVersion(handler.ctx, &secretmanagerpb.AddSecretVersionRequest{
		Payload: &secretmanagerpb.SecretPayload{
			Data: pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(newKey),
			}),
		},
		Parent: handler.secret.Name,
	})
	if err != nil {
		return fmt.Errorf("failed to add new secret version for private key: %v", err)
	}
	_, err = handler.client.AddSecretVersion(handler.ctx, &secretmanagerpb.AddSecretVersionRequest{
		Payload: &secretmanagerpb.SecretPayload{
			Data: pem.EncodeToMemory(
				&pem.Block{
					Type: "PUBLIC KEY",
					Bytes: x509.MarshalPKCS1PublicKey(&newKey.PublicKey),
				},
			),
		},
		Parent: publicKeySecret.Name,
	})
	if err != nil {
		return fmt.Errorf("failed to add new secret version for public key: %v", err)
	}

	return nil
}
