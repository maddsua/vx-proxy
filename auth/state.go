package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type expirer interface {
	Expired() bool
}

type stateEntry struct {
	Key string
	Val expirer
}

type sessionState struct {
	entries map[string]expirer
	mtx     sync.Mutex
}

func (this *sessionState) LoadSession(key string) (*Session, bool) {

	this.mtx.Lock()
	defer this.mtx.Unlock()

	val, ok := this.entries[key]
	if !ok || val.Expired() {
		return nil, false
	}

	switch val := val.(type) {
	case *Session:
		return val, true
	default:
		return nil, true
	}
}

func (this *sessionState) LookupSessionEntry(id uuid.UUID) (*Session, bool) {

	this.mtx.Lock()
	defer this.mtx.Unlock()

	for _, val := range this.entries {
		if sess, ok := val.(*Session); ok && sess.ID == id && !sess.IsCancelled() {
			return sess, true
		}
	}

	return nil, false
}

func (this *sessionState) Store(key string, val expirer) {

	this.mtx.Lock()
	defer this.mtx.Unlock()

	if oldVal, has := this.entries[key]; has {
		if sess, ok := oldVal.(*Session); ok {
			sess.Terminate()
			this.entries[fmt.Sprintf("re_%d_%s", time.Now().UnixNano(), key)] = sess
		}
	}

	this.entries[key] = val
}

func (this *sessionState) Del(key string) {

	this.mtx.Lock()
	defer this.mtx.Unlock()

	delete(this.entries, key)
}

func (this *sessionState) Entries() []stateEntry {

	this.mtx.Lock()
	defer this.mtx.Unlock()

	var entries []stateEntry

	for key, val := range this.entries {
		entries = append(entries, stateEntry{Key: key, Val: val})
	}

	return entries
}
