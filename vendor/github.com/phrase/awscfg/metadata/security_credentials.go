package metadata

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

func IAMRoles() ([]string, error) {
	b, err := readPath("/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(bytes.TrimSpace(b))), nil
}

func IAMCredentials(role string) (c *Credentials, err error) {
	r, err := getPath("/latest/meta-data/iam/security-credentials/" + role)
	if err != nil {
		return nil, err
	}
	return c, json.NewDecoder(r).Decode(&c)
}

type Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
	LastUpdated     time.Time
	Type            string
	Code            string
}
