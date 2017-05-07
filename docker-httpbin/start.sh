#!/usr/bin/env bash

set -euo pipefail
set -x

docker-compose down -v

docker-compose up -d nginx

docker-compose ps