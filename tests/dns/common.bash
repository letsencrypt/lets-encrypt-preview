#!/usr/bin/env bash

function random_subdomain() {
    </dev/urandom tr -dc 'a-z' | head -c 13
}
