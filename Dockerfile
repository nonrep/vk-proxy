FROM golang:alpine AS builder

WORKDIR /build

COPY go.mod .

COPY . .

ENV GO111MODULE=on

RUN apk add --no-cache openssl

RUN go build -o proxy proxy.go

FROM alpine

WORKDIR /build

COPY --from=builder /build/proxy /build/proxy

CMD [". /proxy.go"]
