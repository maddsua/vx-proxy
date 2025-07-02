package utils

import "os"

func FindLocation(locations []string) (string, bool) {

	for _, val := range locations {
		if stat, err := os.Stat(val); err == nil && stat.Mode().IsRegular() {
			return val, true
		}
	}

	return "", false
}
