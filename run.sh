#!/bin/bash
export PATH=$PATH:/usr/local/go/bin;
gofmt -w *.go && go build authenticate && ./authenticate
