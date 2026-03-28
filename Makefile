.PHONY: build test test-race e2e run clean docker-build docker-run

build:
	go build -o mulprox .

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
	docker build -t mulprox .

docker-run:
	docker run -p 8080:8080 mulprox
