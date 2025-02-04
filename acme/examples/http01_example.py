"""Example ACME-V2 API for HTTP-01 challenge.

Brief:

This a complete usage example of the python-acme API.

Limitations of this example:
    - Works for only one Domain name
    - Performs only HTTP-01 challenge
    - Uses ACME-v2

Workflow:
    (Account creation)
    - Create account key
    - Register account and accept TOS
    (Certificate actions)
    - Select HTTP-01 within offered challenges by the CA server
    - Set up http challenge resource
    - Set up standalone web server
    - Create domain private key and CSR
    - Issue certificate
    - Renew certificate
    - Revoke certificate
    (Account update actions)
    - Change contact information
    - Deactivate Account
"""
from contextlib import contextmanager

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose
import OpenSSL

from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import messages
from acme import standalone

# Constants:

# This is the staging point for ACME-V2 within Let's Encrypt.
DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

USER_AGENT = 'python-acme-example'

# Account key size
ACC_KEY_BITS = 2048

# Certificate private key size
CERT_PKEY_BITS = 2048

# Domain name for the certificate.
DOMAIN = 'client.example.com'

# If you are running Boulder locally, it is possible to configure any port
# number to execute the challenge, but real CA servers will always use port
# 80, as described in the ACME specification.
PORT = 80


# Useful methods and classes:


def new_csr_comp(domain_name, pkey_pem=None):
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        pkey = rsa.generate_private_key(public_exponent=65537, key_size=CERT_PKEY_BITS)
        pkey_pem = pkey.public_bytes(serialization.Encoding.PEM)

    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    return pkey_pem, csr_pem


def select_http01_chall(orderr):
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.HTTP01):
                return i

    raise Exception('HTTP-01 challenge was not offered by the CA server.')


@contextmanager
def challenge_server(http_01_resources):
    """Manage standalone server set up and shutdown."""

    # Setting up a fake server that binds at PORT and any address.
    address = ('', PORT)
    try:
        servers = standalone.HTTP01DualNetworkedServers(address,
                                                        http_01_resources)
        # Start client standalone web server.
        servers.serve_forever()
        yield servers
    finally:
        # Shutdown client web server and unbind from PORT
        servers.shutdown_and_server_close()


def perform_http01(client_acme, challb, orderr):
    """Set up standalone webserver and perform HTTP-01 challenge."""

    response, validation = challb.response_and_validation(client_acme.net.key)

    resource = standalone.HTTP01RequestHandler.HTTP01Resource(
        chall=challb.chall, response=response, validation=validation)

    with challenge_server({resource}):
        # Let the CA server know that we are ready for the challenge.
        client_acme.answer_challenge(challb, response)

        # Wait for challenge status and then issue a certificate.
        # It is possible to set a deadline time.
        finalized_orderr = client_acme.poll_and_finalize(orderr)

    return finalized_orderr.fullchain_pem


# Main examples:


def example_http():
    """This example executes the whole process of fulfilling a HTTP-01
    challenge for one specific domain.

    The workflow consists of:
    (Account creation)
    - Create account key
    - Register account and accept TOS
    (Certificate actions)
    - Select HTTP-01 within offered challenges by the CA server
    - Set up http challenge resource
    - Set up standalone web server
    - Create domain private key and CSR
    - Issue certificate
    - Renew certificate
    - Revoke certificate
    (Account update actions)
    - Change contact information
    - Deactivate Account

    """
    # Create account key

    acc_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537,
                                     key_size=ACC_KEY_BITS,
                                     backend=default_backend()))

    # Register account and accept TOS

    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(DIRECTORY_URL, net)
    client_acme = client.ClientV2(directory, net=net)

    # Terms of Service URL is in client_acme.directory.meta.terms_of_service
    # Registration Resource: regr
    # Creates account with contact information.
    email = ('fake@example.com')
    regr = client_acme.new_account(
        messages.NewRegistration.from_data(
            email=email, terms_of_service_agreed=True))

    # Create domain private key and CSR
    pkey_pem, csr_pem = new_csr_comp(DOMAIN)

    # Issue certificate

    orderr = client_acme.new_order(csr_pem)

    # Select HTTP-01 within offered challenges by the CA server
    challb = select_http01_chall(orderr)

    # The certificate is ready to be used in the variable "fullchain_pem".
    fullchain_pem = perform_http01(client_acme, challb, orderr)

    # Renew certificate

    _, csr_pem = new_csr_comp(DOMAIN, pkey_pem)

    orderr = client_acme.new_order(csr_pem)

    challb = select_http01_chall(orderr)

    # Performing challenge
    fullchain_pem = perform_http01(client_acme, challb, orderr)

    # Revoke certificate

    fullchain_com = x509.load_pem_x509_certificate(fullchain_pem)

    try:
        client_acme.revoke(fullchain_com, 0)  # revocation reason = 0
    except errors.ConflictError:
        # Certificate already revoked.
        pass

    # Query registration status.
    client_acme.net.account = regr
    try:
        regr = client_acme.query_registration(regr)
    except errors.Error as err:
        if err.typ == messages.ERROR_PREFIX + 'unauthorized':
            # Status is deactivated.
            pass
        raise

    # Change contact information

    email = 'newfake@example.com'
    regr = client_acme.update_registration(
        regr.update(
            body=regr.body.update(
                contact=('mailto:' + email,)
            )
        )
    )

    # Deactivate account/registration

    regr = client_acme.deactivate_registration(regr)


if __name__ == "__main__":
    example_http()
