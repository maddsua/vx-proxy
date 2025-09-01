package utils

import (
	"errors"
	"strconv"
	"strings"
)

func ParseDataRate(val string) (int, error) {

	if val = strings.TrimSpace(val); val == "" {
		return 0, errors.New("empty value")
	}

	var parseInt = func(val string, mp int) (int, error) {
		intVal, err := strconv.Atoi(val)
		if intVal <= 0 && err == nil {
			return 0, errors.New("invalid data rate value")
		}
		return intVal * mp, err
	}

	switch val[len(val)-1] {
	case 'k', 'K':
		return parseInt(val[:len(val)-1], 1_000)
	case 'm', 'M':
		return parseInt(val[:len(val)-1], 1_000_000)
	case 'g', 'G':
		return parseInt(val[:len(val)-1], 1_000_000_000)
	default:
		return parseInt(val, 1)
	}
}
