package password

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/sethvargo/go-password/password"
	"happn.io/secret-rotation/pkg/config"
	"happn.io/secret-rotation/pkg/types"
	"happn.io/secret-rotation/pkg/utils"
)

const (
	PASSWORD_CONSTRAINTS_LABEL = "password_constraints"
)

type PasswordHandler struct {
	ctx context.Context
	client *secretmanager.Client
	secret *secretmanagerpb.Secret
	projectId string
	logger *slog.Logger
}

func New(ctx context.Context, client *secretmanager.Client, secret *secretmanagerpb.Secret, cfg config.Config) PasswordHandler {
	return PasswordHandler{
		ctx:   ctx,
		client: client,
		secret: secret,
		projectId: cfg.GcpProjectId,
		logger: slog.New(slog.NewJSONHandler(
			os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel},
		)).With(
			"component", "secret_handler",
			"handler", "password",
		),
	}
}

func (handler PasswordHandler) ParseConstraints(constraintString string) (map[string]int, error) {
	constraints := map[string]int{
		"length":    32,
		"uppercase": 1,
		"lowercase": 1,
		"digits":    1,
		"special":   1,
	}
	pairs := strings.SplitSeq(constraintString, ";")
	for pair := range pairs {
		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid constraint format: %s", pair)
		}
		key := parts[0]
		value, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid constraint value for %s: %s", key, parts[1])
		}
		constraints[key] = value
	}

	return constraints, nil
}

func (handler PasswordHandler) Name() string {
	return "password"
}

func (handler PasswordHandler) Handle(msg types.PubSubMessage) error {
	constraintString := handler.secret.Labels[PASSWORD_CONSTRAINTS_LABEL]
	if constraintString == "" {
		constraintString = "length=32;uppercase=1;lowercase=1;digits=1;special=1"
	}
	constraints, err := handler.ParseConstraints(constraintString)
	if err != nil {
		return fmt.Errorf("failed to parse constraints: %w", err)
	}
	password, err := password.Generate(
		constraints["length"],
		constraints["digits"],
		constraints["special"],
		constraints["uppercase"] > 0,
		true,
	)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}
	handler.logger.InfoContext(handler.ctx, "Generated new password", "secret_name", handler.secret.Name)
	// Store the generated password in the secret manager
	_, err = utils.AddSecretVersion(handler.ctx, handler.client, handler.secret.Name, []byte(password))
	if err != nil {
		return fmt.Errorf("failed to add secret version: %w", err)
	}
	return nil
}
