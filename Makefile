IMAGE_NAME := bws2passwd
VERSION    := $(shell grep '^version' pyproject.toml | sed 's/version = "\(.*\)"/\1/')

.PHONY: build bump-patch bump-minor bump-major

build:
	docker build -t dustylefevre/$(IMAGE_NAME):$(VERSION) -t dustylefevre/$(IMAGE_NAME):latest .

bump-patch:
	uv version --bump patch

bump-minor:
	uv version --bump minor

bump-major:
	uv version --bump major
