FROM debian:jessie
MAINTAINER Adam Cigánek <adam.ciganek@maidsafe.net>

EXPOSE 5000 5100
ENV RUST_LOG=warn
ENV USER root

WORKDIR /deploy
COPY install.sh run.sh safe_vault.crust.config ./
RUN ./install.sh && rm install.sh
ENTRYPOINT ["./run.sh"]
