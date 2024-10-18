#!/bin/bash
set -e
cd $(dirname $0)
cd test
go build
./test
