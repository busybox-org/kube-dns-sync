FROM golang:latest

WORKDIR /go/src
COPY ./ /go/src

# build code \
RUN go mod tidy \
  && CGO_ENABLED=0 GOOS=linux go build -ldflags \
  "-w -s" -o main cmd/main.go

FROM alpine:latest

WORKDIR /app
COPY --from=0 --chmod=a+x /go/src/main .

ENTRYPOINT ["/app/main"]