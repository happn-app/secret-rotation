package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Host               string     `yaml:"host"`
	GcpProjectId       string     `yaml:"gcp_project_id"`
	PubsubSubscription string     `yaml:"pubsub_subscription"`
	HandlerLabelKey    string     `yaml:"handler_label_key"`
	LogLevel           slog.Level `yaml:"log_level"`
}

func LoadConfig(ctx context.Context) Config {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "/etc/secret-rotation/config.yaml"
	}
	configBytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var config Config
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		panic(err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: config.LogLevel}))
	logger.With(
		"component", "config",
	).With(
		"function", "LoadConfig",
	).InfoContext(
		ctx,
		"Loaded configuration from path",
		"path", path,
		"config", fmt.Sprintf("%+v", config),
	)
	return config
}
