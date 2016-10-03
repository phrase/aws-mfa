package metadata

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func newClient() *http.Client {
	c := &http.Client{}
	c.Timeout = 100 * time.Millisecond
	return c
}

func readPath(path string) ([]byte, error) {
	r, err := getPath(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ioutil.ReadAll(r)
}

func getPath(path string) (io.ReadCloser, error) {
	rsp, err := newClient().Get(endpoint + "/" + strings.TrimPrefix(path, "/"))
	if err != nil {
		return nil, err
	}
	if rsp.Status[0] != '2' {
		b, _ := ioutil.ReadAll(rsp.Body)
		return nil, fmt.Errorf("got status %s but expected 2x. body=%s", rsp.Status, string(b))
	}
	return rsp.Body, nil
}
