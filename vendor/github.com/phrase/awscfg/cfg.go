package awscfg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/phrase/yubioath"
)

func NewFromPath(path string) (*aws.Config, error) {
	cfg, err := readConfigFromFile(path)
	if err != nil {
		return nil, err
	}

	creds, err := getSTSCredentials(cfg)
	if err != nil {
		return nil, err
	}

	config := aws.NewConfig().WithCredentials(credentials.NewStaticCredentials(*creds.AccessKeyId, *creds.SecretAccessKey, *creds.SessionToken))
	if cfg.AWSDefaultRegion != "" {
		config = config.WithRegion(cfg.AWSDefaultRegion)
	}
	return config, nil
}

var doDebug = os.Getenv("DEBUG") == "true"

func debugStream() io.Writer {
	if doDebug {
		return os.Stderr
	}
	return ioutil.Discard
}

var dbg = log.New(debugStream(), "[DEBUG] ", log.Lshortfile)

func getSTSCredentials(cfg *config) (creds *sts.Credentials, err error) {
	cachePath := "/tmp/aws/" + cfg.AWSAccessKeyID + ".json"

	dbg.Printf("reading credentials from %s", cachePath)
	creds, err = readCredentialsFromFile(cachePath)
	if err == nil {
		if creds.Expiration.After(time.Now().Add(1 * time.Minute)) {
			dbg.Printf("credentials present and not out of date: valid for %s", creds.Expiration.Sub(time.Now()))
			return creds, nil
		}
		dbg.Print("credentials present but out of date")
		os.RemoveAll(cachePath)
	} else if os.IsNotExist(err) {
		dbg.Print("credentials not found")
	} else {
		dbg.Printf("unknown error: %s", err)
	}
	awsCfg := aws.NewConfig().WithCredentials(credentials.NewStaticCredentials(cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, ""))
	if cfg.AWSDefaultRegion != "" {
		awsCfg = awsCfg.WithRegion(cfg.AWSDefaultRegion)
	}
	if doDebug {
		awsCfg.HTTPClient = &http.Client{Transport: &transport{}}
	}
	stsClient := sts.New(session.New(awsCfg))
	i := iam.New(session.New(awsCfg))
	res, err := i.ListMFADevices(nil)
	if err != nil {
		return nil, err
	}
	if len(res.MFADevices) != 1 {
		return nil, fmt.Errorf("expected 1 mfa device, was %d", len(res.MFADevices))
	}
	d := res.MFADevices[0]

	dur := 6 * time.Hour
	if cfg.AWSDuration != "" {
		dur, err = time.ParseDuration(cfg.AWSDuration)
		if err != nil {
			return nil, err
		}
	}

	d64 := int64(dur.Seconds())

	token, err := readToken(cfg)
	if err != nil {
		return nil, err
	}
	tokenRes, err := stsClient.GetSessionToken(&sts.GetSessionTokenInput{SerialNumber: d.SerialNumber, DurationSeconds: &d64, TokenCode: &token})
	if err != nil {
		return nil, err
	}
	creds = tokenRes.Credentials
	if err := storeCredentials(cachePath, creds); err != nil {
		log.Printf("error storing credentials: %s", err)
		// ignore for now
	}
	return creds, nil
}

var insertMsg = "insert your yubikey please"

func readToken(cfg *config) (string, error) {
	if k := cfg.AWSYubikey; k != "" {
		ctx, cf := context.WithCancel(context.Background())
		defer cf()
		if _, err := exec.LookPath("dmenu"); err == nil {
			exec.CommandContext(ctx, "dmenu", "-p", insertMsg).Start()
		}
		key, ok, err := readKeyFromYubi(ctx, k)
		if ok {
			return key, nil
		} else if err != nil {
			log.Printf("error loading key from yubioath: %s", err)
		}
	}
	return readMFAToken(cfg.AWSAccountName, os.Stdin)
}

func readKeyFromPinentry(ctx context.Context) (string, bool, error) {
	c := exec.CommandContext(ctx, "pinentry")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	c.Stdin = strings.NewReader("GETPIN\n")
	c.Stdout = stdout
	c.Stderr = stderr
	err := c.Run()
	if err != nil {
		return "", false, fmt.Errorf("%s: %s", err, stderr)
	}
	for _, l := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(l, "D ") {
			return strings.TrimSpace(strings.TrimPrefix(l, "D ")), true, nil
		}
	}
	return "", false, fmt.Errorf("unable to extract pin from %q", stdout.String())
}

func readKeyFromYubi(ctx context.Context, key string) (string, bool, error) {
	keys, err := loadKeysFromYubi(ctx)
	if err != nil {
		return "", false, err
	}
	v, ok := keys[key]
	return v, ok, nil
}

func loadKeysFromYubi(ctx context.Context) (yubiauth.Keys, error) {
	keys, found, err := yubiauth.ReadYubioath()
	if err != nil {
		return nil, err
	} else if found {
		return keys, nil
	}
	fmt.Fprintf(os.Stderr, insertMsg)
	keys, err = yubiauth.WaitForKeys(ctx)
	if err != nil {
		if err != context.DeadlineExceeded {
			log.Printf("err=%q", err)
		} else {
			io.WriteString(os.Stderr, "\n")
		}
	}
	fmt.Fprintf(os.Stderr, "\nloaded mfa tokens\n")
	return keys, nil
}

type mfaReader func(context.Context, chan string) error

func readMFAToken(name string, in io.Reader) (string, error) {
	scanner := bufio.NewScanner(in)
	msg := "AWS MFA token"
	if name != "" {
		msg += fmt.Sprintf(" for account %s", name)
	}
	msg += " please: "
	fmt.Fprint(os.Stderr, msg)
	for scanner.Scan() {
		i := strings.TrimSpace(scanner.Text())
		if len(i) == 6 {
			return i, nil
		}
		fmt.Fprint(os.Stderr, msg)
	}
	return "", scanner.Err()
}

func storeCredentials(path string, i interface{}) error {
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	return json.NewEncoder(f).Encode(i)
}

func readCredentialsFromFile(path string) (creds *sts.Credentials, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return creds, json.NewDecoder(f).Decode(&creds)
}

func readConfigFromFile(path string) (cfg *config, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return cfg, json.NewDecoder(f).Decode(&cfg)
}

func readMFACode(accountName string) string {
	msg := "please provide your AWS MFA access token"
	if accountName != "" {
		msg += " for account " + accountName
	}
	msg += ": "
	for {
		fmt.Fprint(os.Stderr, msg)
		var code string
		_, err := fmt.Scanf("%s", &code)
		if err == nil && validCode(code) {
			return code
		}
	}
}

func validCode(code string) bool {
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(code) == 6
}

type config struct {
	AWSAccessKeyID     string `json:"aws_access_key_id"`
	AWSSecretAccessKey string `json:"aws_secret_access_key"`
	AWSDefaultRegion   string `json:"aws_default_region"`
	AWSKeyName         string `json:"aws_key_name"`
	AWSAccountName     string `json:"aws_account_name,omitempty"`
	AWSDuration        string `json:"aws_duration,omitempty"`
	AWSYubikey         string `json:"aws_yubikey,omitempty"`
}

type transport struct {
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	log.Printf("method=%s url=%s", r.Method, r.URL)
	rsp, err := http.DefaultClient.Do(r)
	return rsp, err
}
