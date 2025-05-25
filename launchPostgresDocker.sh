#!/bin/sh
docker run --name my-postgres \
  -e POSTGRES_PASSWORD=mypassword \
  -p 5432:5432 \
  -v $(pwd)/init-scripts:/docker-entrypoint-initdb.d \
  -d postgres