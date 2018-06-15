#!/bin/sh -xe
# Developer Python3 virtualenv setup for Certbot

if command -v python3; then
    export VENV_NAME="${VENV_NAME:-venv3}"
    export VENV_ARGS="--python python3"
else
    echo "Couldn't find python3 in $PATH"
    exit 1
fi

./tools/_venv_common.sh \
  -e acme[dev] \
  -e .[dev,docs] \
  -e certbot-apache \
  -e certbot-dns-cloudflare \
  -e certbot-dns-cloudxns \
  -e certbot-dns-digitalocean \
  -e certbot-dns-dnsimple \
  -e certbot-dns-dnsmadeeasy \
  -e certbot-dns-google \
  -e certbot-dns-luadns \
  -e certbot-dns-nsone \
  -e certbot-dns-rackspace \
  -e certbot-dns-route53 \
  -e certbot-nginx \
  -e letshelp-certbot \
  -e certbot-compatibility-test
