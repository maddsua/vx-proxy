package auth

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/google/uuid"
)

type Controller interface {
	Type() string
	WithPassword(ctx context.Context, auth PasswordAuth) (*Session, error)
	ErrorRate() float64
	Shutdown(ctx context.Context) error
}

type UserPassword struct {
	Username string
	Password string
}

type PasswordAuth struct {
	UserPassword
	ClientIP net.IP
	NasAddr  net.IP
	NasPort  int
}

var ErrUnauthorized = errors.New("Unauthorized")

func SessionIdFromBytes(val []byte) uuid.NullUUID {

	if val, err := uuid.FromBytes(val); err == nil {
		return uuid.NullUUID{UUID: val, Valid: true}
	}

	if val, err := uuid.ParseBytes(val); err == nil {
		return uuid.NullUUID{UUID: val, Valid: true}
	}

	return uuid.NullUUID{}
}

func ParseTextID(val string) (string, error) {

	if val = strings.TrimSpace(val); val == "" {
		return "", errors.New("empty value")
	}

	for _, char := range val {

		switch char {
		case '-', '_':
			continue
		}

		switch {

		case char >= '0' && char <= '9':
			continue
		case char >= 'A' && char <= 'Z':
			continue
		case char >= 'a' && char <= 'z':
			continue

		default:
			return "", errors.New("unexpected character")
		}
	}

	return val, nil
}
