package uaa

import (
	"fmt"
	"os"
)

type UAAConfig struct {
	Host         string
	RedirectPath string
	LoginPath    string
	LoginScope   string
	ClientId     string
	ClientSecret string
}

func GetConfigFromEnv() UAAConfig {
	return UAAConfig{
		Host:         parseEnvProperty(UAA_HOST),
		RedirectPath: parseEnvProperty(UAA_REDIRECT_PATH),
		LoginPath:    parseEnvProperty(UAA_LOGIN_PATH),
		LoginScope:   parseEnvProperty(UAA_LOGIN_SCOPE),
		ClientId:     parseEnvProperty(UAA_CLIENT_ID),
		ClientSecret: parseEnvProperty(UAA_CLIENT_SECRET),
	}
}

func parseEnvProperty(property string) string {
	value := os.Getenv(property)
	if value == "" {
		panic(fmt.Sprintf("%s needs to be set", property))
	}
	return value
}
