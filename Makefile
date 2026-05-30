.PHONY: build build-all test test-race e2e run clean docker-build docker-run bench

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

build-all:
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/mulprox-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/mulprox-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/mulprox-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/mulprox-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/mulprox-windows-amd64.exe .
	sha256sum dist/* | sed "s/dist\///gi"

clean:
	rm -rf mulprox dist

docker-build:
	docker build -t mulprox:build .

docker-run: docker-build
	docker run -p 8080:8080 mulprox:build

docker-tag: docker-build
	docker tag mulprox:build praktiskt/mulprox:latest

docker-push: docker-tag
	docker push praktiskt/mulprox:latest

bench:
	go test -bench=. -benchtime=10x -count=3 $(shell go list ./... | grep -v /e2e)
	go test -bench=. -benchtime=5x -count=3 -run='^$$' ./e2e/
