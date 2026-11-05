.PHONY: build install test lint sbom
BINARY=picard
EXE=$(if $(filter Windows_NT,$(OS)),.exe,)

default: build

build:
	go build -o ${BINARY}${EXE}

install:
	go install .

test:
	go test ./...

lint:
	go vet ./...

sbom:
	syft . -o cyclonedx-json=picard.cdx.json
