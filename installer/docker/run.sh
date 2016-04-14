#! /bin/bash

function generate_config() {
  local path=$1

  if [ -n "$VAULT_WALLET_ADDRESS" ]; then
    local wallet_address="\"$VAULT_WALLET_ADDRESS\""
  else
    local wallet_address=null
  fi

  local max_capacity=${VAULT_MAX_CAPACITY:-null}

  rm -f $path
  echo "{"                                      >> $path
  echo "  \"wallet_address\": $wallet_address," >> $path
  echo "  \"max_capacity\": $max_capacity"      >> $path
  echo "}"                                      >> $path
}

generate_config safe_vault.vault.config
./safe_vault
