package utils

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type PortRange struct {
	Begin int
	End   int
}

func (this PortRange) MarshalYAML() (any, error) {
	return this.String(), nil
}

func (this *PortRange) UnmarshalYAML(val *yaml.Node) error {

	if val.Value == "" {
		return errors.New("empty token")
	}

	before, after, has := strings.Cut(val.Value, "-")
	if !has {

		port, err := strconv.Atoi(val.Value)
		if err != nil {
			return fmt.Errorf("failed to parse port: %v", err)
		}

		this.Begin = port
		this.End = port

		return nil
	}

	begin, err := strconv.Atoi(strings.TrimSpace(before))
	if err != nil {
		return fmt.Errorf("failed to parse range begin: %v", err)
	}

	end, err := strconv.Atoi(strings.TrimSpace(after))
	if err != nil {
		return fmt.Errorf("failed to parse range end: %v", err)
	}

	if end <= begin {
		return errors.New("invalid range values")
	}

	this.Begin = begin
	this.End = end

	return nil
}

func (this PortRange) String() string {
	return fmt.Sprintf("%d-%d", this.Begin, this.End)
}

func (this PortRange) Size() int {
	if size := this.End - this.Begin; size > 1 {
		return size
	} else if size == 0 {
		return 1
	}
	return 0
}
