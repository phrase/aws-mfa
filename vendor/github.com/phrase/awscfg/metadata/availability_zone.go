package metadata

func AvailabilityZone() (string, error) {
	b, err := readPath("/latest/meta-data/placement/availability-zone/")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
