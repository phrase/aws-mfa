package yubiauth

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Command interface {
	CombinedOutput() ([]byte, error)
}

type Commander func(string, ...string) ([]byte, error)

func defaultCommander(cmd string, args ...string) ([]byte, error) {
	return exec.Command(cmd, args...).CombinedOutput()
}

func WaitForKeys(ctx context.Context) (Keys, error) {
	return waitForKeysWithCommander(ctx, defaultCommander)
}

func ReadYubioath() (Keys, bool, error) {
	return readYubioathWithCommander(defaultCommander)
}

func waitForKeysWithCommander(ctx context.Context, cmd Commander) (Keys, error) {
	if keys, found, err := readYubioathWithCommander(cmd); err != nil {
		return nil, err
	} else if found {
		return keys, nil
	}
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case _ = <-t.C:
			keys, found, err := readYubioathWithCommander(cmd)
			if err != nil {
				return nil, err
			} else if found {
				return keys, nil
			}
		}
	}
}

func readYubioathWithCommander(cmd Commander) (Keys, bool, error) {
	// TODO: try to make it also work using (and detecting) 'ykman oath code'
	var b []byte
	var err error
	b, err = cmd("ykman", "oath", "code")
	if err != nil {
		if bytes.Contains(b, msgYkmanKeyNotFound) {
			return nil, false, nil
		}
		b, err = cmd("yubioath")
		if err != nil {
			if bytes.Contains(b, msgYubiKeyNotFound) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("looks like you neither have ykman nor yubioath installed:%s\n%s", b, err)
		}
	}
	return parseOutput(b), true, nil
}

var ErrTimeoutWaitingForKeys = fmt.Errorf("timeout waiting for keys")

var (
	msgYubiKeyNotFound  = []byte("No YubiKey found!")
	msgYkmanKeyNotFound = []byte("No YubiKey detected!")
)

func isExecutableNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "executable file not found")
}

type Keys map[string]string

func (k Keys) Lookup(key string) (string, bool) {
	v, ok := k[key]
	return v, ok
}

func parseOutput(in []byte) Keys {
	m := Keys{}
	for _, line := range strings.Split(strings.TrimSpace(string(in)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.Join(fields[0:len(fields)-1], " ")
		m[name] = fields[len(fields)-1]
	}
	return m
}
