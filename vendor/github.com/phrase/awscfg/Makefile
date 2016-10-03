.PHONY: vendor

PACKAGES = $(shell go list ./... | grep -v "/vendor")

default: build

all: build test vet

gen:
	go generate ${PACKAGES}

build: gen
	go install ${PACKAGES}

test:
	go test ${PACKAGES}

vet:
	go vet ${PACKAGES}
