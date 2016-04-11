FROM ubuntu:15.10
MAINTAINER Adam Cigánek <adam.ciganek@maidsafe.net>
RUN apt-get update && apt-get install -y build-essential \
                                         curl \
                                         file \
                                         libsodium-dev \
                                         pkg-config \
                                         sudo
RUN curl -sSf https://static.rust-lang.org/rustup.sh | sh -s -- -y
RUN cargo install safe_vault

# Remove stuff that is no longer needed, to save some space.
ENV SUDO_FORCE_REMOVE=yes
RUN apt-get remove -y build-essential curl file pkg-config sudo && \
    apt-get autoremove -y && \
    apt-get autoclean -y

COPY safe_vault.crust.config /root/.cargo/bin/
ENV PATH ${PATH}:/root/.cargo/bin
ENV RUST_LOG=warn
EXPOSE 5483
ENTRYPOINT ["safe_vault"]

