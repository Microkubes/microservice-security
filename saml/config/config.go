package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// Config holds the microservice full configuration.
type Config struct {
	// Services is a map of <service-name>:<service base URL>. For example,
	// "user-microservice": "http://kong.gateway:8001/user"
	Services map[string]string `json:"services"`
	// Keys is a map <key name>:<key file path>. Should contain at least a "default" entry.
	// The keys are used for JWT generation and signing.
	// Example:
	// {
	//   "default": "keys/default.rsa.priv",
	//   "system": "keys/internal.system.key.rsa.priv"
	// }
	Keys map[string]string `json:"keys"`
}

// LoadConfig loads a Config from a configuration JSON file.
func LoadConfig(confFile string) (*Config, error) {
	if confFile == "" {
		confFile = os.Getenv("SERVICE_CONFIG_FILE")
		if confFile == "" {
			confFile = "config.json"
		}
	}

	confBytes, err := ioutil.ReadFile(confFile)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	err = json.Unmarshal(confBytes, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
