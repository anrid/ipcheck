# Build
FROM golang:1.19-alpine3.17 AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY cmd cmd
COPY pkg pkg
COPY data data

RUN CGO_ENABLED=0 go build -o /ipcheck ./cmd/ipcheck/ipcheck.go

# Deploy
FROM alpine:3.17

WORKDIR /

COPY --from=build /ipcheck /ipcheck
COPY --from=build /app/data/test-ips.txt /test-ips.txt

ENTRYPOINT ["/ipcheck"]
