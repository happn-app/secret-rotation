package utils

import (
	"context"
	"fmt"
	"regexp"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

func GetVersionIdFromName(versionName string) (int64, error) {
	var versionId int64
	_, err := regexp.Match("\\d+$", []byte(versionName))
	if err != nil {
		return 0, err
	}
	return versionId, nil
}

func AddSecretVersion(ctx context.Context, client *secretmanager.Client, secretName string, payload []byte) (*secretmanagerpb.SecretVersion, error) {
	version, err := client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: payload,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add new secret version: %w", err)
	}

	versionId, err := GetVersionIdFromName(version.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get version ID from name: %w", err)
	}

	// Create an alias for the old secret version (alias 'previous')
	_, err = client.UpdateSecret(ctx, &secretmanagerpb.UpdateSecretRequest{
		Secret: &secretmanagerpb.Secret{
			VersionAliases: map[string]int64{
				"previous": versionId - 1,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create alias for old secret version: %w, previous_version_id: %d, version_id: %d", err, versionId-1, versionId)
	}
	return version, nil
}
