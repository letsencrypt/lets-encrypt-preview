#!/bin/sh -xe
# Developer virtualenv setup for Certbot client

if command -v python2; then
    export VENV_ARGS="--python python2"
elif command -v python2.7; then
    export VENV_ARGS="--python python2.7"
else
    echo "Couldn't find python2 or python2.7 in $PATH"
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
  -e certbot-dns-gehirn \
  -e certbot-dns-google \
  -e certbot-dns-linode \
  -e certbot-dns-luadns \
  -e certbot-dns-nsone \
  -e certbot-dns-ovh \
  -e certbot-dns-rfc2136 \
  -e certbot-dns-route53 \
  -e certbot-dns-sakuracloud \
  -e certbot-dns-dnspod \
  -e certbot-nginx \
  -e certbot-postfix \
  -e letshelp-certbot \
  -e certbot-compatibility-test
