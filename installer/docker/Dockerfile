FROM ubuntu:15.10
MAINTAINER Adam Cigánek <adam.ciganek@maidsafe.net>

EXPOSE 5000 5100
ENV RUST_LOG=warn

# If we decide to install safe-vault from APT, instead of from source, this is
# how to do it:
# EXPOSE 5483 5484
# RUN apt-get update && apt-get install -y curl sudo
# RUN curl http://apt-alpha.maidsafe.net/repos/maidsafe.apt.gpg.key | apt-key add -
# RUN curl -o /etc/apt/sources.list.d/maidsafe.list http://apt-alpha.maidsafe.net/repos/maidsafe.list
# RUN apt-get update && apt-get install -y safe-vault

RUN apt-get update && apt-get install -y build-essential \
                                         curl \
                                         file \
                                         libsodium-dev \
                                         pkg-config \
                                         sudo
RUN curl -sSf https://static.rust-lang.org/rustup.sh | sh -s -- -y
RUN cargo install safe_vault --git https://github.com/maidsafe/safe_vault.git

# Remove stuff that is no longer needed, to save some space.
RUN curl -sSf https://static.rust-lang.org/rustup.sh | sh -s -- -y --uninstall
RUN SUDO_FORCE_REMOVE=yes \
    apt-get remove -y build-essential curl file pkg-config sudo && \
    apt-get autoremove -y && \
    apt-get autoclean -y

COPY safe_vault.crust.config /root/.cargo/bin/
COPY run_safe_vault.sh /usr/local/bin/
RUN chmod a+x /usr/local/bin/run_safe_vault.sh
ENTRYPOINT ["run_safe_vault.sh"]
