# Deploying safe vault with Docker

This document describes how to deploy and run Safe Vault inside a Docker
container. For more information about Docker, see the [Docker documentation](https://docs.docker.com/).

## Safe Vault image

Safe Vault is available as a docker image called **msafe/vault** on Docker Hub.
Alternatively, it's possible to build the image using the Dockerfile found in `installer/docker`.

To pull the latest Safe Vault image from Docker Hub:

```
docker pull msafe/vault
```

To build the image from source:

```
docker build -t msafe/vault path/to/safe_vault/Dockerfile
```

## Configuring the container

The vault process inside the container listens for incomming connections
on port 5000 (both TCP and UDP) and runs local service discovery on port 5100.
These ports can be mapped to any ports on the host machine using Docker's port
publishing feature:

```
docker run --rm -it -p 6000:5000 msafe/vault
```

(Note: `-it` means the container will run in interactive mode and output to stdout/stderr on the host machine. `--rm` means the container will be removed after it stops)

Here, we published the listening port to port 6000 on the host machine and we
didn't publish the local discovery port (so only vaults running in the same docker network can use it).

The vault itself can be configured using environment variables:

- `VAULT_WALLET_ADDRESS` - wallet adress
- `VAULT_MAX_CAPACITY` - maximum storage capacity (in bytes)

Example:

```
docker run --rm -it -p 5000:5000 -e "VAULT_WALLET_ADDRESS=xyz" -e "VAULT_MAX_CAPACITY=1073741824" msafe/vault
```

## Deploying to cloud

This section describes how to deploy vault container to Digital Ocean. It relies on [Docker Machine](https://docs.docker.com/machine/overview/) which makes it easy to adapt this information to deploying to other cloud providers, virtual machines or bare metal servers.

### Prerequisites:
- [Docker Machine](https://docs.docker.com/machine/install-machine/)
- Digital Ocean access token (can be generated in the Digital Ocean Control Panel)

### Spin up a droplet

Run this command:

```
docker-machine create --driver digitalocean --digitalocean-access-token=YOUR_ACCESS_TOKEN safe-vault-droplet
```

It will create and run a new droplet (cloud host) named "safe-vault-droplet". For more information about additional options, see the Docker machine [documentation on Digital Ocean](https://docs.docker.com/machine/drivers/digital-ocean/).

We can how check the droplet's IP address:

```
docker-machine ip safe-vault-droplet
```

Or ssh to it:

```
docker-machine ssh safe-vault-droplet
```

### Configure docker to use the new droplet

Before installing the vault container on the new droplet, we need to tell docket about it:

```
eval $(docker-machine env vault-test)
```

This will export a set of environment variables to the current shell telling `docker` to run its commands against the new droplet and not the local machine.

### Install and run Safe Vault container on the droplet

```
docker run -d -p 5000:5000 --name safe-vault --restart=unless-stopped msafe/vault
```

The above command runs detached container named "safe-vault" on port 5000 and instructs it to restart automatically when the droplet reboots.

