VERSION := $(shell cat VERSION)
CARGO ?= $(if $(wildcard $(HOME)/.cargo/bin/cargo),$(HOME)/.cargo/bin/cargo,cargo)
export MACOSX_DEPLOYMENT_TARGET := 13.0

.PHONY: build test integration clean app test-native legacy-test
build:
	$(CARGO) build --release --locked
	mkdir -p dist
	cp target/release/whale target/release/whale-helper dist/

test:
	$(CARGO) test --locked
	$(CARGO) fmt --check
	$(CARGO) clippy --all-targets --locked -- -D warnings

integration:
	WHALE_TEST_CORE="$(CURDIR)/.tools/xray" $(CARGO) test --locked --test xray_contract

clean:
	$(CARGO) clean

app: build
	sh scripts/build-app.sh

test-native: build
	sh scripts/test-native.sh

legacy-test:
	go test -race ./...
	go vet ./...
