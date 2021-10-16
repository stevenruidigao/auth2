#!/bin/bash
gofmt -w *.go && go build main.go && ./main
