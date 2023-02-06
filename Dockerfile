FROM golang:1.20

ENV GO111MODULE=on

ADD . /usr/local/go/src/tenableContainerSecurity
WORKDIR /usr/local/go/src/tenableContainerSecurity
RUN go mod download && go mod verify 
RUN go build -v

CMD ["app"]