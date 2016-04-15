# Deploying safe_vault with Docker

Safe vault is available as **msafe/vault** image on Docker Hub.

## Container confguration

The vault listens on port 5000 inside the container. This port can be mapped to
any host port (here to port 7123):

```
docker run -p 7123:5000 msafe/vault
```

The vault confgiguration options can be set via environment variables:

- `VAULT_WALLET_ADDRESS` - wallet adress
- `VAULT_MAX_CAPACITY` - maximum storage capacity (in bytes)

```
docker run -p 5000:5000 -e "VAULT_WALLET_ADDRESS=xxxx" -e "VAULT_MAX_CAPACITY=1073741824" msafe/vault
```

## Deploying to Digital Ocean

To deploy vault to Digital Ocean, we must first spin up a droplet ready to host
docker containers. To do that, we will use [docker-machine](https://docs.docker.com/machine/) which supports deplying to Digital Ocean out of the box (among other cloud providers).

First, spin up a droplet:

```
docker-machine create --driver digitalocean --digitalocean-access-token=YOUR_ACCESS_TOKEN vault-test
```

The above example creates a droplet called "vault-test" using your access token (which you need to generate in the Digital Ocean Control Panel). This droplet is already preconfigured to run docker containers. Next, export some environment variables into the current shell, so the `docker`
command knows which host to run then on:

```
eval $(docker-machine env vault-test)
```

Then install and run the vault image on the droplet:

```
docker run -d -p 5000:5000 --name vault --restart=unless-stopped msafe/vault
```

The above command runs detached container named "vault" on port 5000 and instructs it to restart automatically when the droplet reboots.

