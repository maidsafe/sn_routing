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

## Running the container

To run the container in "interactive" mode, so we can see its output in stdout/stderr:

```
docker run --rm -it -P msafe/vault
```

To run it in detached (daemonized) mode:

```
docker run -d -P msafe/vault
```

Note the `-P` switch tells docker to publish exposed ports. This is necessary so
other nodes and clients can connect to this vault.

## Configuring the vault

The vault can be configured using environment variables:

- `VAULT_WALLET_ADDRESS` - wallet adress
- `VAULT_MAX_CAPACITY` - maximum storage capacity (in bytes)

Example:

```
docker run --rm -it -P -e "VAULT_WALLET_ADDRESS=xyz" -e "VAULT_MAX_CAPACITY=1073741824" msafe/vault
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
docker run -d -P --name safe-vault --restart=unless-stopped msafe/vault
```

The above command runs detached container named "safe-vault" on port 5000 and instructs it to restart automatically when the droplet reboots.

