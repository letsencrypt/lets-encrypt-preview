#!/usr/bin/env bats

load 'common'

function setup() {
    # Skip if any required environment variable is unset or empty
    [ -z "$TEST_CLOUDFLARE_DOMAIN" ]  && skip '$TEST_CLOUDFLARE_DOMAIN variable not set'
    [ -z "$TEST_CLOUDFLARE_EMAIL" ]   && skip '$TEST_CLOUDFLARE_EMAIL variable not set'
    [ -z "$TEST_CLOUDFLARE_API_KEY" ] && skip '$TEST_CLOUDFLARE_API_KEY variable not set'

    # Create a temporary directory the test
    pattern="${BATS_TMPDIR:-/tmp/}/$(basename "$BATS_TEST_FILENAME").XXXXXX"
    tmpdir=$(mktemp -d "$pattern")

    # Provide common args that should be used with each certbot invocation
    common_args="--staging --agree-tos --register-unsafely-without-email --config-dir=$tmpdir/config --work-dir=$tmpdir/work --logs-dir=$tmpdir/logs"
}

function teardown() {
    # Clean up the temporary directory used for credentials files
    [ -z "$tmpdir" ] || [ ! -d "$tmpdir" ] || rm -rf "$tmpdir"
}

function write_credentials () {
    credentials="$tmpdir/credentials"

    echo "dns_cloudflare_email = $TEST_CLOUDFLARE_EMAIL" > "$credentials"
    echo "dns_cloudflare_api_key = $TEST_CLOUDFLARE_API_KEY" >> "$credentials"

    echo "$credentials"
}

@test "obtain and renew certificate" {
    run certbot certonly $common_args --dns-cloudflare -d $(random_subdomain).$TEST_CLOUDFLARE_DOMAIN --dns-cloudflare-credentials="$(write_credentials)"
    [ "$status" -eq 0 ]

    run certbot renew $common_args --force-renewal
    [ "$status" -eq 0 ]
    [[ "$output" =~ .*"Renewing an existing certificate".* ]]
    [[ "$output" =~ .*"all renewals succeeded".* ]]
}

@test "obtain certificate for three subdomains" {
    run certbot certonly $common_args --dns-cloudflare -d $(random_subdomain).$TEST_CLOUDFLARE_DOMAIN,$(random_subdomain).$TEST_CLOUDFLARE_DOMAIN,$(random_subdomain).$TEST_CLOUDFLARE_DOMAIN --dns-cloudflare-credentials="$(write_credentials)"
    [ "$status" -eq 0 ]
}

@test "attempt with invalid domain" {
    run certbot certonly $common_args --dns-cloudflare -d invalid.example.com --dns-cloudflare-credentials="$(write_credentials)"
    [ "$status" -ne 0 ]
    [[ "$output" =~ .*"confirm that the domain name has been entered correctly".* ]]
}

@test "attempt with empty credentials" {
    echo "# Intentionally empty" > "$tmpdir/no-credentials"

    run certbot certonly $common_args --dns-cloudflare -d $(random_subdomain).$TEST_CLOUDFLARE_DOMAIN --dns-cloudflare-credentials="$tmpdir/no-credentials"
    [ "$status" -ne 0 ]
    [[ "$output" =~ .*"Missing properties in credentials configuration file".* ]]
    [[ "$output" =~ .*"should be email address".* ]]
    [[ "$output" =~ .*"should be API key".* ]]
}

@test "attempt with missing credentials file" {
    run certbot certonly $common_args --dns-cloudflare -d $(random_subdomain).$TEST_CLOUDFLARE_DOMAIN --dns-cloudflare-credentials="$tmpdir/not-a-file"
    [ "$status" -ne 0 ]
    [[ "$output" =~ .*"File not found".* ]]
}

@test "attempt with incomplete API key" {
    bad_credentials="$tmpdir/bad_credentials"

    echo "dns_cloudflare_email = $TEST_CLOUDFLARE_EMAIL" > "$bad_credentials"
    echo "dns_cloudflare_api_key = ${TEST_CLOUDFLARE_API_KEY:0:-1}" >> "$bad_credentials"

    run certbot certonly $common_args --dns-cloudflare -d $(random_subdomain).$TEST_CLOUDFLARE_DOMAIN --dns-cloudflare-credentials="$bad_credentials"
    [ "$status" -ne 0 ]
    [[ "$output" =~ .*"Invalid request headers".* ]]
    [[ "$output" =~ .*"confirm that you have supplied valid Cloudflare API credentials".* ]]
    [[ "$output" =~ .*"copy your entire API key".* ]]
}

@test "attempt with incorrect API key" {
    bad_credentials="$tmpdir/bad_credentials"

    echo "dns_cloudflare_email = $TEST_CLOUDFLARE_EMAIL" > "$bad_credentials"
    echo "dns_cloudflare_api_key = 0123456789abcdef0123456789abcdef01234567" >> "$bad_credentials"

    run certbot certonly $common_args --dns-cloudflare -d $(random_subdomain).$TEST_CLOUDFLARE_DOMAIN --dns-cloudflare-credentials="$bad_credentials"
    [ "$status" -ne 0 ]
    [[ "$output" =~ .*"Unknown X-Auth-Key or X-Auth-Email".* ]]
    [[ "$output" =~ .*"confirm that you have supplied valid Cloudflare API credentials".* ]]
}

@test "attempt with incorrect e-mail address" {
    bad_credentials="$tmpdir/bad_credentials"

    echo "dns_cloudflare_email = invalid@example.com" > "$bad_credentials"
    echo "dns_cloudflare_api_key = $TEST_CLOUDFLARE_API_KEY" >> "$bad_credentials"

    run certbot certonly $common_args --dns-cloudflare -d $(random_subdomain).$TEST_CLOUDFLARE_DOMAIN --dns-cloudflare-credentials="$bad_credentials"
    [ "$status" -ne 0 ]
    [[ "$output" =~ .*"Unknown X-Auth-Key or X-Auth-Email".* ]]
    [[ "$output" =~ .*"confirm that you have supplied valid Cloudflare API credentials".* ]]
    [[ "$output" =~ .*"enter the correct email address".* ]]
}

