package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type Controller interface {
	ID() string
	WithPassword(ctx context.Context, auth PasswordProxyAuth) (*Session, error)
	Close() error
}

type ProxyUser struct {
	Username string
	Password string
}

type PasswordProxyAuth struct {
	ProxyUser
	ClientIP net.IP
	NasAddr  net.IP
	NasPort  int
}

type CacheEntry interface {
	EntryExpires() (time.Time, bool)
}

type Session struct {
	Context       context.Context
	CancelContext context.CancelFunc
	ContextWg     sync.WaitGroup
	ID            uuid.UUID
	UserID        string
	MaxDataRateRx int
	MaxDataRateTx int
	IdleTimeout   time.Duration
	LastActivity  time.Time
	LastActSync   time.Time
	AcctRxBytes   atomic.Int64
	AcctTxBytes   atomic.Int64
}

func (this *Session) EntryExpires() (time.Time, bool) {
	return this.Context.Deadline()
}

type CredentialsMiss struct {
	Expires  time.Time
	Username string
}

func (this *CredentialsMiss) EntryExpires() (time.Time, bool) {

	if this.Expires.IsZero() {
		return this.Expires, false
	}

	return this.Expires, true
}

var ErrUnauthorized = errors.New("Unauthorized")

func SessionIdFromBytes(bytes []byte) uuid.NullUUID {

	if val, err := uuid.FromBytes(bytes); err == nil {
		return uuid.NullUUID{UUID: val, Valid: true}
	}

	if val, err := uuid.ParseBytes(bytes); err == nil {
		return uuid.NullUUID{UUID: val, Valid: true}
	}

	return uuid.NullUUID{}
}

type Config struct {
	Radius RadiusConfig `yaml:"radius"`
}

func (this *Config) Validate() error {

	if err := this.Radius.Validate(); err != nil {
		return fmt.Errorf("radius: %s", err.Error())
	}

	return nil
}
