FROM alpine:3.3
MAINTAINER MaidSafe Developers <dev@maidsafe.net>

RUN apk update && apk add --update bash && rm -rf /var/cache/apk/*
ENV SHELL /bin/bash

WORKDIR /deploy
COPY safe_vault ./
COPY run.sh safe_vault.crust.config ./

EXPOSE 5000 5100
ENV RUST_LOG=safe_vault=debug
ENTRYPOINT ["./run.sh"]
