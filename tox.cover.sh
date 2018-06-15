#!/bin/sh -xe

# USAGE: ./tox.cover.sh [package]
#
# This script is used by tox.ini (and thus Travis CI) in order to
# generate separate stats for each package. It should be removed once
# those packages are moved to separate repo.
#
# -e makes sure we fail fast and don't submit coveralls submit

if [ "xxx$1" = "xxx" ]; then
  pkgs="certbot acme certbot_apache certbot_dns_cloudflare certbot_dns_cloudxns certbot_dns_digitalocean certbot_dns_dnsimple certbot_dns_dnsmadeeasy certbot_dns_google certbot_dns_luadns certbot_dns_nsone certbot_dns_rackspace certbot_dns_rfc2136 certbot_dns_route53 certbot_nginx letshelp_certbot"
else
  pkgs="$@"
fi

cover () {
  if [ "$1" = "certbot" ]; then
    min=98
  elif [ "$1" = "acme" ]; then
    min=100
  elif [ "$1" = "certbot_apache" ]; then
    min=100
  elif [ "$1" = "certbot_dns_cloudflare" ]; then
    min=98
  elif [ "$1" = "certbot_dns_cloudxns" ]; then
    min=99
  elif [ "$1" = "certbot_dns_digitalocean" ]; then
    min=98
  elif [ "$1" = "certbot_dns_dnsimple" ]; then
    min=98
  elif [ "$1" = "certbot_dns_dnsmadeeasy" ]; then
    min=99
  elif [ "$1" = "certbot_dns_google" ]; then
    min=99
  elif [ "$1" = "certbot_dns_luadns" ]; then
    min=98
  elif [ "$1" = "certbot_dns_nsone" ]; then
    min=99
  elif [ "$1" = "certbot_dns_rackspace" ]; then
    min=98
  elif [ "$1" = "certbot_dns_rfc2136" ]; then
    min=99
  elif [ "$1" = "certbot_dns_route53" ]; then
    min=92
  elif [ "$1" = "certbot_nginx" ]; then
    min=97
  elif [ "$1" = "letshelp_certbot" ]; then
    min=100
  else
    echo "Unrecognized package: $1"
    exit 1
  fi

  pkg_dir=$(echo "$1" | tr _ -)
  pytest --cov "$pkg_dir" --cov-append --cov-report= --numprocesses auto --pyargs "$1"
  coverage report --fail-under="$min" --include="$pkg_dir/*" --show-missing
}

rm -f .coverage  # --cov-append is on, make sure stats are correct
for pkg in $pkgs
do
  cover $pkg
done
