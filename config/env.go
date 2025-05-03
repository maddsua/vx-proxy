package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func LoadEnvValue(val *string) {

	if val == nil || *val == "" {
		return
	}

	key := strings.ToUpper(strings.TrimSpace(*val))
	if !strings.HasPrefix(key, "$") {
		return
	}

	slog.Debug(fmt.Sprintf("Config variable '%s' is loaded from env", key))

	*val = strings.TrimSpace(os.Getenv(key))
}
