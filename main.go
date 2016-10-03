package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/phrase/awscfg"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ae, err := awsEnv(cfg)
	if err != nil {
		return err
	}
	args := []string{}
	if len(os.Args) > 1 {
		args = os.Args[1:]
	}
	c := exec.Command("aws", args...)
	c.Env = append(os.Environ(), ae...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Run()
}

func awsEnv(cfg *aws.Config) (out []string, err error) {
	c, err := cfg.Credentials.Get()
	if err != nil {
		return nil, err
	}
	out = append(out,
		"AWS_ACCESS_KEY_ID="+c.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY="+c.SecretAccessKey,
	)
	if cfg.Region != nil {
		out = append(out, "AWS_DEFAULT_REGION="+*cfg.Region)
	}
	if c.SessionToken != "" {
		out = append(out, "AWS_SESSION_TOKEN="+c.SessionToken)
	}
	return out, nil
}

func loadConfig() (*aws.Config, error) {
	p := os.Getenv("AWS_CREDENTIALS_PATH")
	if p == "" {
		return nil, errors.New("AWS_CREDENTIALS_PATH must be set")
	}
	return awscfg.NewFromPath(p)
}
