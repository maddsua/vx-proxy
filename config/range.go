package config

import (
	"errors"
	"strconv"
	"strings"
)

func ParseRange(token string) ([2]int, error) {

	if token == "" {
		return [2]int{}, errors.New("empty token")
	}

	before, after, has := strings.Cut(token, "-")
	if !has {

		val, err := strconv.Atoi(token)
		if err != nil {
			return [2]int{}, err
		}

		return [2]int{val, val}, nil
	}

	begin, err := strconv.Atoi(strings.TrimSpace(before))
	if err != nil {
		return [2]int{}, err
	}

	end, err := strconv.Atoi(strings.TrimSpace(after))
	if err != nil {
		return [2]int{}, err
	}

	if end <= begin {
		return [2]int{}, errors.New("invalid range")
	}

	return [2]int{begin, end}, nil
}
