#!/bin/bash

image="node:20-alpine"
uid="$(id -u $USER)"

docker run -u $uid -w /app -v $(pwd):/app $image npm i && \
docker run -u $uid -w /app -v $(pwd):/app $image npm run build
