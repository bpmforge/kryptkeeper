#!/bin/sh
set -e
cp -r /src /work
cd /work
go mod init estcheck >/dev/null 2>&1 || true
go get github.com/globalsign/est@v1.0.7 >/tmp/get.log 2>&1
go mod tidy >>/tmp/get.log 2>&1 || cat /tmp/get.log
go run . 2>&1
