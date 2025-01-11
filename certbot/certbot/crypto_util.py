"""Certbot client crypto utility functions.

.. todo:: Make the transition to use PSS rather than PKCS1_v1_5 when the server
    is capable of handling the signatures.

"""
import datetime
import hashlib
import logging
import re
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
import josepy
from OpenSSL import crypto
from OpenSSL import SSL

from acme import crypto_util as acme_crypto_util
from certbot import errors
from certbot import interfaces
from certbot import util
from certbot.compat import os

# Cryptography ed448 and ed25519 modules do not exist on oldest tests
if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

logger = logging.getLogger(__name__)


# High level functions

def generate_key(key_size: int, key_dir: Optional[str], key_type: str = "rsa",
                 elliptic_curve: str = "secp256r1", keyname: str = "key-certbot.pem",
                 strict_permissions: bool = True) -> util.Key:
    """Initializes and saves a privkey.

    Inits key and saves it in PEM format on the filesystem.

    .. note:: keyname is the attempted filename, it may be different if a file
        already exists at the path.

    :param int key_size: key size in bits if key size is rsa.
    :param str key_dir: Optional key save directory.
    :param str key_type: Key Type [rsa, ecdsa]
    :param str elliptic_curve: Name of the elliptic curve if key type is ecdsa.
    :param str keyname: Filename of key
    :param bool strict_permissions: If true and key_dir exists, an exception is raised if
        the directory doesn't have 0700 permissions or isn't owned by the current user.

    :returns: Key
    :rtype: :class:`certbot.util.Key`

    :raises ValueError: If unable to generate the key given key_size.

    """
    try:
        key_pem = make_key(
            bits=key_size, elliptic_curve=elliptic_curve or "secp256r1", key_type=key_type,
        )
    except ValueError as err:
        logger.debug("", exc_info=True)
        logger.error("Encountered error while making key: %s", str(err))
        raise err

    # Save file
    key_path = None
    if key_dir:
        util.make_or_verify_dir(key_dir, 0o700, strict_permissions)
        key_f, key_path = util.unique_file(
            os.path.join(key_dir, keyname), 0o600, "wb")
        with key_f:
            key_f.write(key_pem)
        if key_type == 'rsa':
            logger.debug("Generating RSA key (%d bits): %s", key_size, key_path)
        else:
            logger.debug("Generating ECDSA key (%d bits): %s", key_size, key_path)

    return util.Key(key_path, key_pem)


def generate_csr(privkey: util.Key, names: Union[List[str], Set[str]], path: Optional[str],
                 must_staple: bool = False, strict_permissions: bool = True) -> util.CSR:
    """Initialize a CSR with the given private key.

    :param privkey: Key to include in the CSR
    :type privkey: :class:`certbot.util.Key`
    :param set names: `str` names to include in the CSR
    :param str path: Optional certificate save directory.
    :param bool must_staple: If true, include the TLS Feature extension "OCSP Must-Staple"
    :param bool strict_permissions: If true and path exists, an exception is raised if
        the directory doesn't have 0755 permissions or isn't owned by the current user.

    :returns: CSR
    :rtype: :class:`certbot.util.CSR`

    """
    csr_pem = acme_crypto_util.make_csr(
        privkey.pem, names, must_staple=must_staple)

    # Save CSR, if requested
    csr_filename = None
    if path:
        util.make_or_verify_dir(path, 0o755, strict_permissions)
        csr_f, csr_filename = util.unique_file(
            os.path.join(path, "csr-certbot.pem"), 0o644, "wb")
        with csr_f:
            csr_f.write(csr_pem)
        logger.debug("Creating CSR: %s", csr_filename)

    return util.CSR(csr_filename, csr_pem, "pem")


# WARNING: the csr and private key file are possible attack vectors for TOCTOU
# We should either...
# A. Do more checks to verify that the CSR is trusted/valid
# B. Audit the parsing code for vulnerabilities

def valid_csr(csr: bytes) -> bool:
    """Validate CSR.

    Check if `csr` is a valid CSR with a correct self-signed signature.

    :param bytes csr: CSR in PEM.

    :returns: Validity of CSR.
    :rtype: bool

    """
    try:
        req = x509.load_pem_x509_csr(csr)
        return req.is_signature_valid
    except (ValueError, TypeError):
        logger.debug("", exc_info=True)
        return False


def csr_matches_pubkey(csr: bytes, privkey: bytes) -> bool:
    """Does private key correspond to the subject public key in the CSR?

    :param bytes csr: CSR in PEM.
    :param bytes privkey: Private key file contents (PEM)

    :returns: Correspondence of private key to CSR subject public key.
    :rtype: bool

    """
    req = x509.load_pem_x509_csr(csr)
    pkey = serialization.load_pem_private_key(privkey, password=None)
    return req.is_signature_valid and req.public_key() == pkey.public_key()


def import_csr_file(
    csrfile: str, data: bytes
) -> Tuple[acme_crypto_util.Format, util.CSR, List[str]]:
    """Import a CSR file, which can be either PEM or DER.

    :param str csrfile: CSR filename
    :param bytes data: contents of the CSR file

    :returns: (`acme_crypto_util.Format.PEM`,
               util.CSR object representing the CSR,
               list of domains requested in the CSR)
    :rtype: tuple

    """
    try:
        # Try to parse as DER first, then fall back to PEM.
        csr = x509.load_der_x509_csr(data)
    except ValueError:
        try:
            csr = x509.load_pem_x509_csr(data)
        except ValueError:
            raise errors.Error("Failed to parse CSR file: {0}".format(csrfile))

    domains = acme_crypto_util.get_names_from_subject_and_extensions(csr.subject, csr.extensions)
    # Internally we always use PEM, so re-encode as PEM before returning.
    data_pem = csr.public_bytes(serialization.Encoding.PEM)
    return (
        acme_crypto_util.Format.PEM,
        util.CSR(file=csrfile, data=data_pem, form="pem"),
        domains,
    )


def make_key(bits: int = 2048, key_type: str = "rsa",
             elliptic_curve: Optional[str] = None) -> bytes:
    """Generate PEM encoded RSA|EC key.

    :param int bits: Number of bits if key_type=rsa. At least 2048 for RSA.
    :param str key_type: The type of key to generate, but be rsa or ecdsa
    :param str elliptic_curve: The elliptic curve to use.

    :returns: new RSA or ECDSA key in PEM form with specified number of bits
              or of type ec_curve when key_type ecdsa is used.
    :rtype: str
    """
    key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    if key_type == 'rsa':
        if bits < 2048:
            raise errors.Error("Unsupported RSA key length: {}".format(bits))

        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    elif key_type == 'ecdsa':
        if not elliptic_curve:
            raise errors.Error("When key_type == ecdsa, elliptic_curve must be set.")
        try:
            name = elliptic_curve.upper()
            if name in ('SECP256R1', 'SECP384R1', 'SECP521R1'):
                curve = getattr(ec, elliptic_curve.upper())
                if not curve:
                    raise errors.Error(f"Invalid curve type: {elliptic_curve}")
                key = ec.generate_private_key(
                    curve=curve(),
                    backend=default_backend()
                )
            else:
                raise errors.Error("Unsupported elliptic curve: {}".format(elliptic_curve))
        except TypeError:
            raise errors.Error("Unsupported elliptic curve: {}".format(elliptic_curve))
        except UnsupportedAlgorithm as e:
            raise e from errors.Error(str(e))
    else:
        raise errors.Error("Invalid key_type specified: {}.  Use [rsa|ecdsa]".format(key_type))
    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )


def valid_privkey(privkey: Union[str, bytes]) -> bool:
    """Is valid RSA private key?

    :param privkey: Private key file contents in PEM

    :returns: Validity of private key.
    :rtype: bool

    """
    if isinstance(privkey, str):
        privkey = privkey.encode()
    try:
        serialization.load_pem_private_key(privkey, password=None)
    except ValueError:
        return False
    else:
        return True


def verify_renewable_cert(renewable_cert: interfaces.RenewableCert) -> None:
    """For checking that your certs were not corrupted on disk.

    Several things are checked:
        1. Signature verification for the cert.
        2. That fullchain matches cert and chain when concatenated.
        3. Check that the private key matches the certificate.

    :param renewable_cert: cert to verify
    :type renewable_cert: certbot.interfaces.RenewableCert

    :raises errors.Error: If verification fails.
    """
    verify_renewable_cert_sig(renewable_cert)
    verify_fullchain(renewable_cert)
    verify_cert_matches_priv_key(renewable_cert.cert_path, renewable_cert.key_path)


def verify_renewable_cert_sig(renewable_cert: interfaces.RenewableCert) -> None:
    """Verifies the signature of a RenewableCert object.

    :param renewable_cert: cert to verify
    :type renewable_cert: certbot.interfaces.RenewableCert

    :raises errors.Error: If signature verification fails.
    """
    try:
        with open(renewable_cert.chain_path, 'rb') as chain_file:
            chain = x509.load_pem_x509_certificate(chain_file.read(), default_backend())
        with open(renewable_cert.cert_path, 'rb') as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        pk = chain.public_key()
        assert cert.signature_hash_algorithm # always present for RSA and ECDSA
        verify_signed_payload(pk, cert.signature, cert.tbs_certificate_bytes,
                                cert.signature_hash_algorithm)
    except (OSError, ValueError, InvalidSignature) as e:
        error_str = "verifying the signature of the certificate located at {0} has failed. \
                Details: {1}".format(renewable_cert.cert_path, e)
        logger.exception(error_str)
        raise errors.Error(error_str)


def verify_signed_payload(public_key: Union[DSAPublicKey, 'Ed25519PublicKey', 'Ed448PublicKey',
                                            EllipticCurvePublicKey, RSAPublicKey,
                                            'X25519PublicKey', 'X448PublicKey'],
                          signature: bytes, payload: bytes,
                          signature_hash_algorithm: hashes.HashAlgorithm) -> None:
    """Check the signature of a payload.

    :param RSAPublicKey/EllipticCurvePublicKey public_key: the public_key to check signature
    :param bytes signature: the signature bytes
    :param bytes payload: the payload bytes
    :param hashes.HashAlgorithm signature_hash_algorithm: algorithm used to hash the payload

    :raises InvalidSignature: If signature verification fails.
    :raises errors.Error: If public key type is not supported
    """
    if isinstance(public_key, RSAPublicKey):
        public_key.verify(
            signature, payload, PKCS1v15(), signature_hash_algorithm
        )
    elif isinstance(public_key, EllipticCurvePublicKey):
        public_key.verify(
            signature, payload, ECDSA(signature_hash_algorithm)
        )
    else:
        raise errors.Error("Unsupported public key type.")


def verify_cert_matches_priv_key(cert_path: str, key_path: str) -> None:
    """ Verifies that the private key and cert match.

    :param str cert_path: path to a cert in PEM format
    :param str key_path: path to a private key file

    :raises errors.Error: If they don't match.
    """
    try:
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.use_certificate_file(cert_path)
        context.use_privatekey_file(key_path)
        context.check_privatekey()
    except (OSError, SSL.Error) as e:
        error_str = "verifying the certificate located at {0} matches the \
                private key located at {1} has failed. \
                Details: {2}".format(cert_path,
                        key_path, e)
        logger.exception(error_str)
        raise errors.Error(error_str)


def verify_fullchain(renewable_cert: interfaces.RenewableCert) -> None:
    """ Verifies that fullchain is indeed cert concatenated with chain.

    :param renewable_cert: cert to verify
    :type renewable_cert: certbot.interfaces.RenewableCert

    :raises errors.Error: If cert and chain do not combine to fullchain.
    """
    try:
        with open(renewable_cert.chain_path) as chain_file:
            chain = chain_file.read()
        with open(renewable_cert.cert_path) as cert_file:
            cert = cert_file.read()
        with open(renewable_cert.fullchain_path) as fullchain_file:
            fullchain = fullchain_file.read()
        if (cert + chain) != fullchain:
            error_str = "fullchain does not match cert + chain for {0}!"
            error_str = error_str.format(renewable_cert.lineagename)
            raise errors.Error(error_str)
    except OSError as e:
        error_str = "reading one of cert, chain, or fullchain has failed: {0}".format(e)
        logger.exception(error_str)
        raise errors.Error(error_str)
    except errors.Error as e:
        raise e


def pyopenssl_load_certificate(data: bytes) -> Tuple[crypto.X509, int]:
    """Load PEM/DER certificate.

    :raises errors.Error:

    """

    openssl_errors = []

    for file_type in (crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1):
        try:
            return crypto.load_certificate(file_type, data), file_type
        except crypto.Error as error:  # TODO: other errors?
            openssl_errors.append(error)
    raise errors.Error("Unable to load: {0}".format(",".join(
        str(error) for error in openssl_errors)))


def get_sans_from_cert(
    cert: bytes, typ: Union[acme_crypto_util.Format, int] = acme_crypto_util.Format.PEM
) -> List[str]:
    """Get a list of Subject Alternative Names from a certificate.

    :param str cert: Certificate (encoded).
    :param Format typ: Which format the `cert` bytes are in.

    :returns: A list of Subject Alternative Names.
    :rtype: list

    """
    typ = acme_crypto_util.Format(typ)
    if typ == acme_crypto_util.Format.PEM:
        x509_cert = x509.load_pem_x509_certificate(cert)
    else:
        assert typ == acme_crypto_util.Format.DER
        x509_cert = x509.load_der_x509_certificate(cert)

    try:
        san_ext = x509_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return []

    return san_ext.value.get_values_for_type(x509.DNSName)


def get_names_from_cert(
    cert: bytes, typ: Union[acme_crypto_util.Format, int] = acme_crypto_util.Format.PEM
) -> List[str]:
    """Get a list of domains from a cert, including the CN if it is set.

    :param str cert: Certificate (encoded).
    :param Format typ: Which format the `cert` bytes are in.

    :returns: A list of domain names.
    :rtype: list

    """
    typ = acme_crypto_util.Format(typ)
    if typ == acme_crypto_util.Format.PEM:
        x509_cert = x509.load_pem_x509_certificate(cert)
    else:
        assert typ == acme_crypto_util.Format.DER
        x509_cert = x509.load_der_x509_certificate(cert)
    return acme_crypto_util.get_names_from_subject_and_extensions(
        x509_cert.subject, x509_cert.extensions
    )


def get_names_from_req(
    csr: bytes, typ: Union[acme_crypto_util.Format, int] = acme_crypto_util.Format.PEM
) -> List[str]:
    """Get a list of domains from a CSR, including the CN if it is set.

    :param str csr: CSR (encoded).
    :param acme_crypto_util.Format typ: Which format the `csr` bytes are in.
    :returns: A list of domain names.
    :rtype: list

    """
    typ = acme_crypto_util.Format(typ)
    if typ == acme_crypto_util.Format.PEM:
        x509_req = x509.load_pem_x509_csr(csr)
    else:
        assert typ == acme_crypto_util.Format.DER
        x509_req = x509.load_der_x509_csr(csr)
    return acme_crypto_util.get_names_from_subject_and_extensions(
        x509_req.subject, x509_req.extensions
    )


def dump_pyopenssl_chain(
    chain: Union[List[crypto.X509], List[josepy.ComparableX509]],
    filetype: Union[acme_crypto_util.Format, int] = acme_crypto_util.Format.PEM,
) -> bytes:
    """Dump certificate chain into a bundle.

    :param list chain: List of `crypto.X509` (or wrapped in
        :class:`josepy.util.ComparableX509`).

    """
    # XXX: returns empty string when no chain is available, which
    # shuts up RenewableCert, but might not be the best solution...
    return acme_crypto_util.dump_pyopenssl_chain(chain, filetype)


def notBefore(cert_path: str) -> datetime.datetime:
    """When does the cert at cert_path start being valid?

    :param str cert_path: path to a cert in PEM format

    :returns: the notBefore value from the cert at cert_path
    :rtype: :class:`datetime.datetime`

    """
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert.not_valid_before_utc


def notAfter(cert_path: str) -> datetime.datetime:
    """When does the cert at cert_path stop being valid?

    :param str cert_path: path to a cert in PEM format

    :returns: the notAfter value from the cert at cert_path
    :rtype: :class:`datetime.datetime`

    """
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert.not_valid_after_utc


def sha256sum(filename: str) -> str:
    """Compute a sha256sum of a file.

    NB: In given file, platform specific newlines characters will be converted
    into their equivalent unicode counterparts before calculating the hash.

    :param str filename: path to the file whose hash will be computed

    :returns: sha256 digest of the file in hexadecimal
    :rtype: str
    """
    sha256 = hashlib.sha256()
    with open(filename, 'r') as file_d:
        sha256.update(file_d.read().encode('UTF-8'))
    return sha256.hexdigest()

# Finds one CERTIFICATE stricttextualmsg according to rfc7468#section-3.
# Does not validate the base64text - use crypto.load_certificate.
CERT_PEM_REGEX = re.compile(
    b"""-----BEGIN CERTIFICATE-----\r?
.+?\r?
-----END CERTIFICATE-----\r?
""",
    re.DOTALL # DOTALL (/s) because the base64text may include newlines
)


def cert_and_chain_from_fullchain(fullchain_pem: str) -> Tuple[str, str]:
    """Split fullchain_pem into cert_pem and chain_pem

    :param str fullchain_pem: concatenated cert + chain

    :returns: tuple of string cert_pem and chain_pem
    :rtype: tuple

    :raises errors.Error: If there are less than 2 certificates in the chain.

    """
    # First pass: find the boundary of each certificate in the chain.
    # TODO: This will silently skip over any "explanatory text" in between boundaries,
    # which is prohibited by RFC8555.
    certs = CERT_PEM_REGEX.findall(fullchain_pem.encode())
    if len(certs) < 2:
        raise errors.Error("failed to parse fullchain into cert and chain: " +
                           "less than 2 certificates in chain")

    # Second pass: for each certificate found, parse it using cryptography and re-encode it,
    # with the effect of normalizing any encoding variations (e.g. CRLF, whitespace).
    certs_normalized: List[str] = []
    for cert_pem in certs:
        cert = x509.load_pem_x509_certificate(cert_pem)
        cert_pem = cert.public_bytes(Encoding.PEM)
        certs_normalized.append(cert_pem.decode())

    # Since each normalized cert has a newline suffix, no extra newlines are required.
    return (certs_normalized[0], "".join(certs_normalized[1:]))


def get_serial_from_cert(cert_path: str) -> int:
    """Retrieve the serial number of a certificate from certificate path

    :param str cert_path: path to a cert in PEM format

    :returns: serial number of the certificate
    :rtype: int
    """
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert.serial_number


def find_chain_with_issuer(fullchains: List[str], issuer_cn: str,
                           warn_on_no_match: bool = False) -> str:
    """Chooses the first certificate chain from fullchains whose topmost
    intermediate has an Issuer Common Name matching issuer_cn (in other words
    the first chain which chains to a root whose name matches issuer_cn).

    :param fullchains: The list of fullchains in PEM chain format.
    :type fullchains: `list` of `str`
    :param `str` issuer_cn: The exact Subject Common Name to match against any
        issuer in the certificate chain.

    :returns: The best-matching fullchain, PEM-encoded, or the first if none match.
    :rtype: `str`
    """
    for chain in fullchains:
        certs = CERT_PEM_REGEX.findall(chain.encode())
        top_cert = x509.load_pem_x509_certificate(certs[-1], default_backend())
        top_issuer_cn = top_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if top_issuer_cn and top_issuer_cn[0].value == issuer_cn:
            return chain

    # Nothing matched, return whatever was first in the list.
    if warn_on_no_match:
        logger.warning("Certbot has been configured to prefer certificate chains with "
                    "issuer '%s', but no chain from the CA matched this issuer. Using "
                    "the default certificate chain instead.", issuer_cn)
    return fullchains[0]
