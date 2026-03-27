.PHONY: build test run clean docker-build docker-run

build:
	go build -o mulprox .

test:
	go test -v ./...

run:
	go run . serve

clean:
	rm -f mulprox

docker-build:
	docker build -t mulprox .

docker-run:
	docker run -p 8080:8080 mulprox
