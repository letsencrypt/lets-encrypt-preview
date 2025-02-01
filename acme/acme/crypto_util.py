"""Crypto utilities."""
import binascii
import contextlib
import enum
from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import os
import socket
import typing
from typing import Any
from typing import Callable
from typing import List
from typing import Literal
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec, ed25519, ed448, types
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import crypto
from OpenSSL import SSL

from acme import errors
import warnings

logger = logging.getLogger(__name__)

# Default SSL method selected here is the most compatible, while secure
# SSL method: TLSv1_METHOD is only compatible with
# TLSv1_METHOD, while SSLv23_METHOD is compatible with all other
# methods, including TLSv2_METHOD (read more at
# https://www.openssl.org/docs/ssl/SSLv23_method.html). _serve_sni
# should be changed to use "set_options" to disable SSLv2 and SSLv3,
# in case it's used for things other than probing/serving!
_DEFAULT_SSL_METHOD = SSL.SSLv23_METHOD


class Format(enum.IntEnum):
    """File format to be used when parsing or serializing X.509 structures.

    Backwards compatible with the `FILETYPE_ASN1` and `FILETYPE_PEM` constants
    from pyOpenSSL.
    """
    DER = crypto.FILETYPE_ASN1
    PEM = crypto.FILETYPE_PEM

    def to_cryptography_encoding(self) -> Encoding:
        """Converts the Format to the corresponding cryptography `Encoding`.
        """
        if self == Format.DER:
            return Encoding.DER
        else:
            return Encoding.PEM


_KeyAndCert = Union[
    Tuple[crypto.PKey, crypto.X509],
    Tuple[types.CertificateIssuerPrivateKeyTypes, x509.Certificate],
]


class _DefaultCertSelection:
    def __init__(self, certs: Mapping[bytes, _KeyAndCert]):
        self.certs = certs

    def __call__(self, connection: SSL.Connection) -> Optional[_KeyAndCert]:
        server_name = connection.get_servername()
        if server_name:
            return self.certs.get(server_name, None)
        return None # pragma: no cover

class SSLSocket:  # pylint: disable=too-few-public-methods
    """SSL wrapper for sockets.

    :ivar socket sock: Original wrapped socket.
    :ivar dict certs: Mapping from domain names (`bytes`) to
        `OpenSSL.crypto.X509`.
    :ivar method: See `OpenSSL.SSL.Context` for allowed values.
    :ivar alpn_selection: Hook to select negotiated ALPN protocol for
        connection.
    :ivar cert_selection: Hook to select certificate for connection. If given,
        `certs` parameter would be ignored, and therefore must be empty.

    """
    def __init__(
        self,
        sock: socket.socket,
        certs: Optional[Mapping[bytes, _KeyAndCert]] = None,
        method: int = _DEFAULT_SSL_METHOD,
        alpn_selection: Optional[Callable[[SSL.Connection, List[bytes]], bytes]] = None,
        cert_selection: Optional[
            Callable[
                [SSL.Connection],
                Optional[_KeyAndCert],
            ]
        ] = None,
    ) -> None:
        self.sock = sock
        self.alpn_selection = alpn_selection
        self.method = method
        if not cert_selection and not certs:
            raise ValueError("Neither cert_selection or certs specified.")
        if cert_selection and certs:
            raise ValueError("Both cert_selection and certs specified.")
        if cert_selection is None:
            cert_selection = _DefaultCertSelection(certs if certs else {})
        self.cert_selection = cert_selection

    def __getattr__(self, name: str) -> Any:
        return getattr(self.sock, name)

    def _pick_certificate_cb(self, connection: SSL.Connection) -> None:
        """SNI certificate callback.

        This method will set a new OpenSSL context object for this
        connection when an incoming connection provides an SNI name
        (in order to serve the appropriate certificate, if any).

        :param connection: The TLS connection object on which the SNI
            extension was received.
        :type connection: :class:`OpenSSL.Connection`

        """
        pair = self.cert_selection(connection)
        if pair is None:
            logger.debug("Certificate selection for server name %s failed, dropping SSL",
                         connection.get_servername())
            return
        key, cert = pair
        new_context = SSL.Context(self.method)
        new_context.set_options(SSL.OP_NO_SSLv2)
        new_context.set_options(SSL.OP_NO_SSLv3)
        new_context.use_privatekey(key)
        if isinstance(cert, x509.Certificate):
            cert = crypto.X509.from_cryptography(cert)
        new_context.use_certificate(cert)
        if self.alpn_selection is not None:
            new_context.set_alpn_select_callback(self.alpn_selection)
        connection.set_context(new_context)

    class FakeConnection:
        """Fake OpenSSL.SSL.Connection."""

        # pylint: disable=missing-function-docstring

        def __init__(self, connection: SSL.Connection) -> None:
            self._wrapped = connection

        def __getattr__(self, name: str) -> Any:
            return getattr(self._wrapped, name)

        def shutdown(self, *unused_args: Any) -> bool:
            # OpenSSL.SSL.Connection.shutdown doesn't accept any args
            try:
                return self._wrapped.shutdown()
            except SSL.Error as error:
                # We wrap the error so we raise the same error type as sockets
                # in the standard library. This is useful when this object is
                # used by code which expects a standard socket such as
                # socketserver in the standard library.
                raise OSError(error)

    def accept(self) -> Tuple[FakeConnection, Any]:  # pylint: disable=missing-function-docstring
        sock, addr = self.sock.accept()

        try:
            context = SSL.Context(self.method)
            context.set_options(SSL.OP_NO_SSLv2)
            context.set_options(SSL.OP_NO_SSLv3)
            context.set_tlsext_servername_callback(self._pick_certificate_cb)
            if self.alpn_selection is not None:
                context.set_alpn_select_callback(self.alpn_selection)

            ssl_sock = self.FakeConnection(SSL.Connection(context, sock))
            ssl_sock.set_accept_state()

            # This log line is especially desirable because without it requests to
            # our standalone TLSALPN server would not be logged.
            logger.debug("Performing handshake with %s", addr)
            try:
                ssl_sock.do_handshake()
            except SSL.Error as error:
                # _pick_certificate_cb might have returned without
                # creating SSL context (wrong server name)
                raise OSError(error)

            return ssl_sock, addr
        except:
            # If we encounter any error, close the new socket before reraising
            # the exception.
            sock.close()
            raise


def probe_sni(name: bytes, host: bytes, port: int = 443, timeout: int = 300,  # pylint: disable=too-many-arguments
              method: int = _DEFAULT_SSL_METHOD, source_address: Tuple[str, int] = ('', 0),
              alpn_protocols: Optional[Sequence[bytes]] = None) -> x509.Certificate:
    """Probe SNI server for SSL certificate.

    :param bytes name: Byte string to send as the server name in the
        client hello message.
    :param bytes host: Host to connect to.
    :param int port: Port to connect to.
    :param int timeout: Timeout in seconds.
    :param method: See `OpenSSL.SSL.Context` for allowed values.
    :param tuple source_address: Enables multi-path probing (selection
        of source interface). See `socket.creation_connection` for more
        info. Available only in Python 2.7+.
    :param alpn_protocols: Protocols to request using ALPN.
    :type alpn_protocols: `Sequence` of `bytes`

    :raises acme.errors.Error: In case of any problems.

    :returns: SSL certificate presented by the server.
    :rtype: cryptography.x509.Certificate

    """
    context = SSL.Context(method)
    context.set_timeout(timeout)

    socket_kwargs = {'source_address': source_address}

    try:
        logger.debug(
            "Attempting to connect to %s:%d%s.", host, port,
            " from {0}:{1}".format(
                source_address[0],
                source_address[1]
            ) if any(source_address) else ""
        )
        socket_tuple: Tuple[bytes, int] = (host, port)
        sock = socket.create_connection(socket_tuple, **socket_kwargs)  # type: ignore[arg-type]
    except OSError as error:
        raise errors.Error(error)

    with contextlib.closing(sock) as client:
        client_ssl = SSL.Connection(context, client)
        client_ssl.set_connect_state()
        client_ssl.set_tlsext_host_name(name)  # pyOpenSSL>=0.13
        if alpn_protocols is not None:
            client_ssl.set_alpn_protos(list(alpn_protocols))
        try:
            client_ssl.do_handshake()
            client_ssl.shutdown()
        except SSL.Error as error:
            raise errors.Error(error)
    cert = client_ssl.get_peer_certificate()
    assert cert # Appease mypy. We would have crashed out by now if there was no certificate.
    return cert.to_cryptography()


# Annoyingly, we can't directly use cryptography's equivalent Union[] type for
# our type signatures since they're only public API in 40.0.x+, which is too new
# for some Certbot # distribution channels. Once we bump our oldest cryptography
# version past 40.0.x, usage of this type can be replaced with:
# cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPrivateKeyTypes
CertificateIssuerPrivateKeyTypes = Union[
    dsa.DSAPrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
]
# Even *more* annoyingly, due to a mypy bug, we can't use Union[] types in
# isinstance expressions without causing false mypy errors. So we have to
# recreate the type collection as a tuple here. And no, typing.get_args doesn't
# work due to another mypy bug.
#
# mypy issues:
#  * https://github.com/python/mypy/issues/17680
#  * https://github.com/python/mypy/issues/15106
CertificateIssuerPrivateKeyTypesTpl = (
    dsa.DSAPrivateKey,
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
)


def make_csr(
    private_key_pem: bytes,
    domains: Optional[Union[Set[str], List[str]]] = None,
    must_staple: bool = False,
    ipaddrs: Optional[List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = None,
) -> bytes:
    """Generate a CSR containing domains or IPs as subjectAltNames.

    Parameters are ordered this way for backwards compatibility when called using positional
    arguments.

    :param buffer private_key_pem: Private key, in PEM PKCS#8 format.
    :param list domains: List of DNS names to include in subjectAltNames of CSR.
    :param bool must_staple: Whether to include the TLS Feature extension (aka
        OCSP Must Staple: https://tools.ietf.org/html/rfc7633).
    :param list ipaddrs: List of IPaddress(type ipaddress.IPv4Address or ipaddress.IPv6Address)
        names to include in subbjectAltNames of CSR.

    :returns: buffer PEM-encoded Certificate Signing Request.

    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, CertificateIssuerPrivateKeyTypesTpl):
        raise ValueError(f"Invalid private key type: {type(private_key)}")
    if domains is None:
        domains = []
    if ipaddrs is None:
        ipaddrs = []
    if len(domains) + len(ipaddrs) == 0:
        raise ValueError(
            "At least one of domains or ipaddrs parameter need to be not empty"
        )

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(d) for d in domains]
                + [x509.IPAddress(i) for i in ipaddrs]
            ),
            critical=False,
        )
    )
    if must_staple:
        builder = builder.add_extension(
            # "status_request" is the feature commonly known as OCSP
            # Must-Staple
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )

    csr = builder.sign(private_key, hashes.SHA256())
    return csr.public_bytes(Encoding.PEM)


def get_names_from_subject_and_extensions(
    subject: x509.Name, exts: x509.Extensions
) -> List[str]:
    """Gets all DNS SAN names as well as the first Common Name from subject.

    :param subject: Name of the x509 object, which may include Common Name
    :type subject: `cryptography.x509.Name`
    :param exts: Extensions of the x509 object, which may include SANs
    :type exts: `cryptography.x509.Extensions`

    :returns: List of DNS Subject Alternative Names and first Common Name
    :rtype: `list` of `str`
    """
    # We know these are always `str` because `bytes` is only possible for
    # other OIDs.
    cns = [
        typing.cast(str, c.value)
        for c in subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    ]
    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        dns_names = []
    else:
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)

    if not cns:
        return dns_names
    else:
        # We only include the first CN, if there are multiple. This matches
        # the behavior of the previously implementation using pyOpenSSL.
        return [cns[0]] + [d for d in dns_names if d != cns[0]]


def _pyopenssl_cert_or_req_all_names(loaded_cert_or_req: Union[crypto.X509, crypto.X509Req]
                                     ) -> List[str]:
    """
    Deprecated
    .. deprecated: 3.x.x
    """
    warnings.warn(
        "_pyopenssl_cert_or_req_all_names is deprecated and will be removed in the "
        "next major release of Certbot. Please use "
        "acme.crypto_util.get_names_from_subject_and_extensions instead.", DeprecationWarning,
        stacklevel=2
    )
    cert_or_req = loaded_cert_or_req.to_cryptography()
    return get_names_from_subject_and_extensions(
        cert_or_req.subject, cert_or_req.extensions
    )


def _cryptography_cert_or_req_san(cert_or_req: Union[x509.Certificate, x509.CertificateSigningRequest]) -> List[str]:
    """Get Subject Alternative Names from certificate or CSR using pyOpenSSL.

    .. note:: Although this is `acme` internal API, it is used by
        `letsencrypt`.

    :param cert_or_req: Certificate or CSR.
    :type cert_or_req: `x509.Certificate` or `x509.CertificateSigningRequest`.

    :returns: A list of Subject Alternative Names that is DNS.
    :rtype: `list` of `str`

    """
    # ???: is this translation needed?
    exts = cert_or_req.extensions
    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []

    return san_ext.value.get_values_for_type(x509.DNSName)


def _pyopenssl_cert_or_req_san(cert_or_req: Union[crypto.X509, crypto.X509Req]) -> List[str]:
    """
    DEPRECATED
    """
    exts = cert_or_req.to_cryptography().extensions
    try:
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []

    return san_ext.value.get_values_for_type(x509.DNSName)


# Helper function that can be mocked in unit tests
def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def make_self_signed_cert(private_key: CertificateIssuerPrivateKeyTypes,
                          domains: Optional[List[str]] = None,
                          not_before: Optional[datetime] = None,
                          validity: Optional[timedelta] = None, force_san: bool = True,
                          extensions: Optional[List[x509.Extension]] = None,
                          ips: Optional[List[Union[ipaddress.IPv4Address,
                                                   ipaddress.IPv6Address]]] = None
                          ) -> x509.Certificate:
    """Generate new self-signed certificate.
    :param buffer private_key_pem: Private key, in PEM PKCS#8 format.
    :type domains: `list` of `str`
    :param int not_before: A datetime after which the cert is valid. If no
    timezone is specified, UTC is assumed
    :type not_before: `datetime.datetime`
    :param validity: Duration for which the cert will be valid. Defaults to 1
    week
    :type validity: `datetime.timedelta`
    :param buffer private_key_pem: One of `CertificateIssuerPrivateKeyTypes`
    :param bool force_san:
    :param extensions: List of additional extensions to include in the cert.
    :type extensions: `list` of `x509.Extension[x509.ExtensionType]`
    :type ips: `list` of (`ipaddress.IPv4Address` or `ipaddress.IPv6Address`)
    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.
    """
    assert domains or ips, "Must provide one or more hostnames or IPs for the cert."

    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())

    if extensions is not None:
        for ext in extensions:
            builder = builder.add_extension(ext.value, ext.critical)
    if domains is None:
        domains = []
    if ips is None:
        ips = []
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)

    name_attrs = []
    if len(domains) > 0:
        name_attrs.append(x509.NameAttribute(
            x509.OID_COMMON_NAME,
            domains[0]
        ))

    builder = builder.subject_name(x509.Name(name_attrs))
    builder = builder.issuer_name(x509.Name(name_attrs))

    sanlist: List[x509.GeneralName] = []
    for address in domains:
        sanlist.append(x509.DNSName(address))
    for ip in ips:
        sanlist.append(x509.IPAddress(ip))
    if force_san or len(domains) > 1 or len(ips) > 0:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sanlist),
            critical=False
        )

    if not_before is None:
        not_before = _now()
    if validity is None:
        validity = timedelta(seconds=7 * 24 * 60 * 60)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_before + validity)

    public_key = private_key.public_key()
    builder = builder.public_key(public_key)
    return builder.sign(private_key, hashes.SHA256())


def gen_ss_cert(key: crypto.PKey, domains: Optional[List[str]] = None,
                not_before: Optional[int] = None,
                validity: int = (7 * 24 * 60 * 60), force_san: bool = True,
                extensions: Optional[List[crypto.X509Extension]] = None,
                ips: Optional[List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = None
                ) -> crypto.X509:
    """Generate new self-signed certificate.

    :type domains: `list` of `str`
    :param OpenSSL.crypto.PKey key:
    :param bool force_san:
    :param extensions: List of additional extensions to include in the cert.
    :type extensions: `list` of `OpenSSL.crypto.X509Extension`
    :type ips: `list` of (`ipaddress.IPv4Address` or `ipaddress.IPv6Address`)

    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.

    .. deprecated: 2.10.0
    """
    warnings.warn(
        "acme.crypto_util.gen_ss_cert is deprecated and will be removed in the "
        "next major release of Certbot. Please use "
        "acme.crypto_util.make_self_signed_cert instead.", DeprecationWarning,
        stacklevel=2
    )
    assert domains or ips, "Must provide one or more hostnames or IPs for the cert."

    cert = crypto.X509()
    cert.set_serial_number(int(binascii.hexlify(os.urandom(16)), 16))
    cert.set_version(2)

    if extensions is None:
        extensions = []
    if domains is None:
        domains = []
    if ips is None:
        ips = []
    extensions.append(
        crypto.X509Extension(
            b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
    )

    if len(domains) > 0:
        cert.get_subject().CN = domains[0]
    # TODO: what to put into cert.get_subject()?
    cert.set_issuer(cert.get_subject())

    sanlist = []
    for address in domains:
        sanlist.append('DNS:' + address)
    for ip in ips:
        sanlist.append('IP:' + ip.exploded)
    san_string = ', '.join(sanlist).encode('ascii')
    if force_san or len(domains) > 1 or len(ips) > 0:
        extensions.append(crypto.X509Extension(
            b"subjectAltName",
            critical=False,
            value=san_string
        ))

    cert.add_extensions(extensions)

    cert.gmtime_adj_notBefore(0 if not_before is None else not_before)
    cert.gmtime_adj_notAfter(validity)

    cert.set_pubkey(key)
    cert.sign(key, "sha256")
    return cert


def dump_cryptography_chain(
    chain: List[x509.Certificate],
    encoding: Literal[Encoding.PEM, Encoding.DER] = Encoding.PEM,
) -> bytes:
    """Dump certificate chain into a bundle.

    :param list chain: List of `cryptography.x509.Certificate`.

    :returns: certificate chain bundle
    :rtype: bytes

    """
    # XXX: returns empty string when no chain is available, which
    # shuts up RenewableCert, but might not be the best solution...

    def _dump_cert(cert: x509.Certificate) -> bytes:
        return cert.public_bytes(encoding)

    # assumes that x509.Certificate.public_bytes includes ending
    # newline character
    return b"".join(_dump_cert(cert) for cert in chain)
