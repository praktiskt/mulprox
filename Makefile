.PHONY: build test test-race e2e run clean docker-build docker-run

LDFLAGS := -s -w -buildid=

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o mulprox .

test:
	go test -v $(shell go list ./... | grep -v /e2e)

test-race:
	go test -race -v $(shell go list ./... | grep -v /e2e)

e2e:
	go test -v -short=false ./e2e/...

run:
	go run . serve

clean:
	rm -f mulprox

docker-build:
	docker build -t mulprox:build .

docker-run: docker-build
	docker run -p 8080:8080 mulprox:build

docker-tag: docker-build
	docker tag mulprox:build praktiskt/mulprox:latest

docker-push: docker-tag
	docker push praktiskt/mulprox:latest
