package env

import (
	"os"
	"strings"
)

type Value string

func Get(key string) Value {
	return Value(strings.TrimSpace(os.Getenv(strings.ToUpper(key))))
}

func (this Value) IsTrue() bool {
	return strings.ToLower(string(this)) == "true"
}

func (this Value) IsFalse() bool {
	return strings.ToLower(string(this)) == "false"
}

func (this Value) IsEmpty() bool {
	return this == ""
}

func (this Value) ToLower() string {
	return strings.ToLower(string(this))
}

func (this Value) ToUpper() string {
	return strings.ToUpper(string(this))
}
