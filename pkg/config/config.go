package config

import (
	"log"
	"os"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Host 				 string        `yaml:"host"`
	GcpProjectId  string        `yaml:"gcp_project_id"`
  PubsubSubscription string        `yaml:"pubsub_subscription"`
  HandlerLabelKey  string        `yaml:"handler_label_key"`
}

func LoadConfig() Config {
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
	log.Printf("[LoadConfig] Loaded config: %+v", config)
	log.Printf("[LoadConfig] Config path: %s", path)
	return config
}
