package awscfg

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

// NewFromLocalConfig reads config from cfg used by the aws command line tool
func NewFromLocalConfig() (*aws.Config, error) {
	creds, err := parseConfigFile(os.ExpandEnv("$HOME/.aws/credentials"))
	if err != nil {
		return nil, err
	}
	def, ok := creds["default"]
	if !ok {
		return nil, fmt.Errorf("no default config found")
	}
	id, secret := def["aws_access_key_id"], def["aws_secret_access_key"]
	if id == "" || secret == "" {
		return nil, fmt.Errorf("aws_access_key_id and aws_secret_access_key not found")
	}
	c := aws.NewConfig().WithCredentials(credentials.NewStaticCredentials(id, secret, ""))

	if cfg, err := parseConfigFile(os.ExpandEnv("$HOME/.aws/config")); err == nil {
		if cfg2, ok := cfg["default"]; ok {
			for k, v := range cfg2 {
				switch k {
				case "region":
					c = c.WithRegion(v)
				}
			}
		}
	}
	return c, nil
}

func parseConfigFile(path string) (m localConfig, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return parseLocalConfig(f)
}

func parseLocalConfig(in io.Reader) (m localConfig, err error) {
	scanner := bufio.NewScanner(in)
	var section string
	m = localConfig{}
	for scanner.Scan() {
		txt := scanner.Text()
		if strings.HasPrefix(txt, "[") && strings.HasSuffix(txt, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(txt, "["), "]")
		} else {
			if _, ok := m[section]; !ok {
				m[section] = map[string]string{}
			}
			parts := strings.SplitN(txt, "=", 2)
			if len(parts) == 2 && parts[1] != "" {
				k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				m[section][k] = v
			}
		}
	}
	return m, scanner.Err()
}

type localConfig map[string]map[string]string
