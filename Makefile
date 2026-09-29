PREFIX ?= $(HOME)/.local
VERSION ?= 0.0.0~dev
FUZZTIME ?= 30s
FUZZWORKERS ?= 2
GOVULNCHECK ?= govulncheck

.PHONY: all test test-integration check lint fuzz vulncheck install deb test-deb clean
all:
	go build -trimpath -o cv2-fido ./cmd/cv2-fido

test:
	go test -race ./...

test-integration:
	go test -race -tags=integration -count=1 -timeout=2m -v ./...

check:
	go vet ./...

lint:
	golangci-lint run ./...
	golangci-lint fmt --diff

fuzz:
	go test ./internal/hid -run='^$$' -fuzz='^FuzzHIDSequence$$' -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	go test ./internal/hid -run='^$$' -fuzz='^FuzzUHIDOutput$$' -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	go test ./internal/authenticator -run='^$$' -fuzz='^FuzzCTAPAuthorization$$' -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)
	go test ./internal/tpm -run='^$$' -fuzz='^FuzzDecodeKey$$' -fuzztime=$(FUZZTIME) -parallel=$(FUZZWORKERS)

vulncheck:
	$(GOVULNCHECK) ./...

install: all
	install -Dm755 cv2-fido "$(DESTDIR)$(PREFIX)/bin/cv2-fido"

deb:
	VERSION="$(VERSION)" ./build-deb.sh

test-deb:
	sh packaging/test-deb.sh

clean:
	rm -f cv2-fido
