#!/bin/bash
gofmt -w *.go && go build authenticate && ./authenticate
