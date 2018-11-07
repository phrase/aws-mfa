package awscfg

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/phrase/awscfg/metadata"
)

func NewFromMetadata() (*aws.Config, error) {
	az, err := metadata.AvailabilityZone()
	if err != nil {
		return nil, err
	}
	region := RegionFromAZ(az)
	roles, err := metadata.IAMRoles()
	if err != nil {
		return nil, err
	} else if len(roles) == 0 {
		return nil, fmt.Errorf("no roles found")
	}
	return aws.NewConfig().
			WithCredentials(metadataCredentials(roles[0])).
			WithRegion(region),
		nil
}

func metadataCredentials(role string) *credentials.Credentials {
	return credentials.NewCredentials(&metadataProvider{role: role})
}

type metadataProvider struct {
	role   string
	cached *metadata.Credentials
}

func (m *metadataProvider) Retrieve() (v credentials.Value, err error) {
	c, err := metadata.IAMCredentials(m.role)
	if err != nil {
		return v, err
	}
	m.cached = c
	return credentials.Value{AccessKeyID: c.AccessKeyId, SecretAccessKey: c.SecretAccessKey, SessionToken: c.Token}, nil
}

func (m *metadataProvider) IsExpired() bool {
	if m.cached == nil {
		dbg.Printf("cached is nil")
		return true
	}
	if m.cached.Expiration.Before(time.Now().UTC().Add(5 * time.Minute)) {
		dbg.Printf("token expired")
		return true
	}
	return false
}

func RegionFromAZ(az string) string {
	return az[0 : len(az)-1]
}
