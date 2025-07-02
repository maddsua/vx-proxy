package utils

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func ExpandEnv(val *string) {

	if val == nil || *val == "" {
		return
	}

	key := strings.ToUpper(strings.TrimSpace(*val))
	if !strings.HasPrefix(key, "$") {
		return
	}

	slog.Debug(fmt.Sprintf("ENV: Expanded '%s'", key))

	*val = strings.TrimSpace(os.Getenv(key))
}
