package auth

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type Controller interface {
	Type() string
	WithPassword(ctx context.Context, auth PasswordProxyAuth) (*Session, error)

	ErrorRate() float64

	Shutdown(ctx context.Context) error
}

type BasicCredentials struct {
	Username string
	Password string
}

type PasswordProxyAuth struct {
	BasicCredentials
	ClientIP net.IP
	NasAddr  net.IP
	NasPort  int
}

type CacheEntry interface {
	EntryExpires() (time.Time, bool)
}

type Session struct {
	ID            uuid.UUID
	UserName      *string
	ClientID      string
	MaxDataRateRx int
	MaxDataRateTx int
	IdleTimeout   time.Duration

	LastActivity time.Time
	LastActSync  time.Time

	AcctRxBytes atomic.Int64
	AcctTxBytes atomic.Int64

	//	Session context must by used by all consumers, such as read/write operations and dials
	Context context.Context
	//	Terminate is a conext cancel function that is used to terminated all data operations that belong to a session
	Terminate context.CancelFunc

	//	Session wait group can be 'locked' by consumers to prevent it from being erased while it's being in use
	//	This isn't a memory safety mechanism, but rather a way to ensure that data accouting works right
	Wg sync.WaitGroup
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
