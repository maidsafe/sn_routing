FROM debian:jessie
MAINTAINER Adam Cigánek <adam.ciganek@maidsafe.net>

EXPOSE 5000 5100
ENV RUST_LOG=error
ENV USER root

WORKDIR /deploy
COPY install.sh ./
RUN ./install.sh && rm install.sh
COPY run.sh safe_vault.crust.config ./
ENTRYPOINT ["./run.sh"]
