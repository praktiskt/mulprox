FROM golang:1.26 AS build
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . /app
ENV LDFLAGS="-s -w -buildid="
RUN --mount=type=cache,target=/root/.cache/go-build \
    GOOS=linux go build -trimpath -ldflags="$LDFLAGS" -o /dist/app


RUN ldd /dist/app | tr -s [:blank:] '\n' | grep ^/ | xargs -I % install -D % /dist/%
RUN ln -s ld-musl-x86_64.so.1 /dist/lib/libc.musl-x86_64.so.1

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /dist /
USER 65534
ENTRYPOINT [ "/app" ]
