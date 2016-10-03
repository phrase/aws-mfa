package metadata

import "strings"

func InstanceID() (string, error) {
	b, err := readPath("/latest/meta-data/instance-id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
