package auth

import (
	"context"
	"errors"
	"net"

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
