"""Certbot client API."""
import datetime
import logging
import platform
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import IO
from typing import List
from typing import Optional
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
import josepy as jose
from josepy import ES256
from josepy import ES384
from josepy import ES512
from josepy import RS256

from acme import client as acme_client
from acme import crypto_util as acme_crypto_util
from acme import errors as acme_errors
from acme import messages
import certbot
from certbot import configuration
from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import util
from certbot._internal import account
from certbot._internal import auth_handler
from certbot._internal import cli
from certbot._internal import constants
from certbot._internal import eff
from certbot._internal import error_handler
from certbot._internal import storage
from certbot._internal.plugins import disco as plugin_disco
from certbot._internal.plugins import selection as plugin_selection
from certbot.compat import os
from certbot.display import ops as display_ops
from certbot.display import util as display_util
from certbot.interfaces import AccountStorage

logger = logging.getLogger(__name__)


def acme_from_config_key(config: configuration.NamespaceConfig, key: jose.JWK,
                         regr: Optional[messages.RegistrationResource] = None
                         ) -> acme_client.ClientV2:
    """Wrangle ACME client construction"""
    if key.typ == 'EC':
        public_key = key.key
        if public_key.key_size == 256:
            alg = ES256
        elif public_key.key_size == 384:
            alg = ES384
        elif public_key.key_size == 521:
            alg = ES512
        else:
            raise errors.NotSupportedError(
                "No matching signing algorithm can be found for the key"
            )
    else:
        alg = RS256
    net = acme_client.ClientNetwork(key, alg=alg, account=regr,
                                    verify_ssl=(not config.no_verify_ssl),
                                    user_agent=determine_user_agent(config))

    directory = acme_client.ClientV2.get_directory(config.server, net)
    return acme_client.ClientV2(directory, net)


def determine_user_agent(config: configuration.NamespaceConfig) -> str:
    """
    Set a user_agent string in the config based on the choice of plugins.
    (this wasn't knowable at construction time)

    :returns: the client's User-Agent string
    :rtype: `str`
    """

    # WARNING: To ensure changes are in line with Certbot's privacy
    # policy, talk to a core Certbot team member before making any
    # changes here.
    if config.user_agent is None:
        ua = ("CertbotACMEClient/{0} ({1}; {2}{8}) Authenticator/{3} Installer/{4} "
              "({5}; flags: {6}) Py/{7}")
        if os.environ.get("CERTBOT_DOCS") == "1":
            cli_command = "certbot"
            os_info = "OS_NAME OS_VERSION"
            python_version = "major.minor.patchlevel"
        else:
            cli_command = cli.cli_command
            os_info = util.get_os_info_ua()
            python_version = platform.python_version()
        ua = ua.format(certbot.__version__, cli_command, os_info,
                       config.authenticator, config.installer, config.verb,
                       ua_flags(config), python_version,
                       "; " + config.user_agent_comment if config.user_agent_comment else "")
    else:
        ua = config.user_agent
    return ua


def ua_flags(config: configuration.NamespaceConfig) -> str:
    """Turn some very important CLI flags into clues in the user agent."""
    if isinstance(config, DummyConfig):
        return "FLAGS"
    flags = []
    if config.duplicate:
        flags.append("dup")
    if config.renew_by_default:
        flags.append("frn")
    if config.allow_subset_of_names:
        flags.append("asn")
    if config.noninteractive_mode:
        flags.append("n")
    hook_names = ("pre", "post", "renew", "manual_auth", "manual_cleanup")
    hooks = [getattr(config, h + "_hook") for h in hook_names]
    if any(hooks):
        flags.append("hook")
    return " ".join(flags)


class DummyConfig:
    """Shim for computing a sample user agent."""
    def __init__(self) -> None:
        self.authenticator = "XXX"
        self.installer = "YYY"
        self.user_agent = None
        self.verb = "SUBCOMMAND"

    def __getattr__(self, name: str) -> Any:
        """Any config properties we might have are None."""
        return None


def sample_user_agent() -> str:
    """Document what this Certbot's user agent string will be like."""
    # DummyConfig is designed to mock certbot.configuration.NamespaceConfig.
    # Let mypy accept that.
    return determine_user_agent(cast(configuration.NamespaceConfig, DummyConfig()))


def register(config: configuration.NamespaceConfig, account_storage: AccountStorage,
             tos_cb: Optional[Callable[[str], None]] = None
             ) -> Tuple[account.Account, acme_client.ClientV2]:
    """Register new account with an ACME CA.

    This function takes care of generating fresh private key,
    registering the account, optionally accepting CA Terms of Service
    and finally saving the account. It should be called prior to
    initialization of `Client`, unless account has already been created.

    :param certbot.configuration.NamespaceConfig config: Client configuration.

    :param .AccountStorage account_storage: Account storage where newly
        registered account will be saved to. Save happens only after TOS
        acceptance step, so any account private keys or
        `.RegistrationResource` will not be persisted if `tos_cb`
        returns ``False``.

    :param tos_cb: If ACME CA requires the user to accept a Terms of
        Service before registering account, client action is
        necessary. For example, a CLI tool would prompt the user
        acceptance. `tos_cb` must be a callable that should accept
        a Term of Service URL as a string, and raise an exception
        if the TOS is not accepted by the client. ``tos_cb`` will be
        called only if the client action is necessary, i.e. when
        ``terms_of_service is not None``. This argument is optional,
        if not supplied it will default to automatic acceptance!

    :raises certbot.errors.Error: In case of any client problems, in
        particular registration failure, or unaccepted Terms of Service.
    :raises acme.errors.Error: In case of any protocol problems.

    :returns: Newly registered and saved account, as well as protocol
        API handle (should be used in `Client` initialization).
    :rtype: `tuple` of `.Account` and `acme.client.Client`

    """
    # Log non-standard actions, potentially wrong API calls
    if account_storage.find_all():
        logger.info("There are already existing accounts for %s", config.server)
    if config.email is None:
        if not config.register_unsafely_without_email:
            msg = ("No email was provided and "
                   "--register-unsafely-without-email was not present.")
            logger.error(msg)
            raise errors.Error(msg)
        if not config.dry_run:
            logger.debug("Registering without email!")

    # If --dry-run is used, and there is no staging account, create one with no email.
    if config.dry_run:
        config.email = None

    # Each new registration shall use a fresh new key
    rsa_key = generate_private_key(
            public_exponent=65537,
            key_size=config.rsa_key_size,
            backend=default_backend())
    key = jose.JWKRSA(key=jose.ComparableRSAKey(rsa_key))
    acme = acme_from_config_key(config, key)
    # TODO: add phone?
    regr = perform_registration(acme, config, tos_cb)

    acc = account.Account(regr, key)
    account_storage.save(acc, acme)

    eff.prepare_subscription(config, acc)

    return acc, acme


def perform_registration(acme: acme_client.ClientV2, config: configuration.NamespaceConfig,
                         tos_cb: Optional[Callable[[str], None]]) -> messages.RegistrationResource:
    """
    Actually register new account, trying repeatedly if there are email
    problems

    :param acme.client.Client acme: ACME client object.
    :param certbot.configuration.NamespaceConfig config: Client configuration.
    :param Callable tos_cb: a callback to handle Term of Service agreement.

    :returns: Registration Resource.
    :rtype: `acme.messages.RegistrationResource`
    """

    eab_credentials_supplied = config.eab_kid and config.eab_hmac_key
    eab: Optional[Dict[str, Any]]
    if eab_credentials_supplied:
        account_public_key = acme.net.key.public_key()
        eab = messages.ExternalAccountBinding.from_data(account_public_key=account_public_key,
                                                        kid=config.eab_kid,
                                                        hmac_key=config.eab_hmac_key,
                                                        directory=acme.directory)
    else:
        eab = None

    if acme.external_account_required():
        if not eab_credentials_supplied:
            msg = ("Server requires external account binding."
                   " Please use --eab-kid and --eab-hmac-key.")
            raise errors.Error(msg)

    tos = acme.directory.meta.terms_of_service
    if tos_cb and tos:
        tos_cb(tos)

    try:
        return acme.new_account(messages.NewRegistration.from_data(
                email=config.email, terms_of_service_agreed=True, external_account_binding=eab))
    except messages.Error as e:
        if e.code in ("invalidEmail", "invalidContact"):
            if config.noninteractive_mode:
                msg = (f"The ACME server believes {config.email} is an invalid email address. "
                       "Please ensure it is a valid email and attempt "
                       "registration again.")
                raise errors.Error(msg)
            config.email = display_ops.get_email(invalid=True)
            return perform_registration(acme, config, tos_cb)
        raise


class Client:
    """Certbot's client.

    :ivar certbot.configuration.NamespaceConfig config: Client configuration.
    :ivar .Account account: Account registered with `register`.
    :ivar .AuthHandler auth_handler: Authorizations handler that will
        dispatch DV challenges to appropriate authenticators
        (providing `.Authenticator` interface).
    :ivar .Authenticator auth: Prepared (`.Authenticator.prepare`)
        authenticator that can solve ACME challenges.
    :ivar .Installer installer: Installer.
    :ivar acme.client.ClientV2 acme: Optional ACME client API handle. You might
        already have one from `register`.

    """

    def __init__(self, config: configuration.NamespaceConfig, account_: Optional[account.Account],
                 auth: Optional[interfaces.Authenticator],
                 installer: Optional[interfaces.Installer],
                 acme: Optional[acme_client.ClientV2] = None) -> None:
        """Initialize a client."""
        self.config = config
        self.account = account_
        self.auth = auth
        self.installer = installer

        # Initialize ACME if account is provided
        if acme is None and self.account is not None:
            acme = acme_from_config_key(config, self.account.key, self.account.regr)
        self.acme = acme

        self.auth_handler: Optional[auth_handler.AuthHandler]
        if auth is not None:
            self.auth_handler = auth_handler.AuthHandler(
                auth, self.acme, self.account, self.config.pref_challs)
        else:
            self.auth_handler = None

    def obtain_certificate_from_csr(self, csr: util.CSR,
                                    orderr: Optional[messages.OrderResource] = None
                                    ) -> Tuple[bytes, bytes]:
        """Obtain certificate.

        :param .util.CSR csr: PEM-encoded Certificate Signing
            Request. The key used to generate this CSR can be different
            than `authkey`.
        :param acme.messages.OrderResource orderr: contains authzrs

        :returns: certificate and chain as PEM byte strings
        :rtype: tuple

        """
        if self.auth_handler is None:
            msg = ("Unable to obtain certificate because authenticator is "
                   "not set.")
            logger.error(msg)
            raise errors.Error(msg)
        if self.account is None or self.account.regr is None:
            raise errors.Error("Please register with the ACME server first.")
        if self.acme is None:
            raise errors.Error("ACME client is not set.")

        logger.debug("CSR: %s", csr)

        if orderr is None:
            orderr = self._get_order_and_authorizations(csr.data, best_effort=False)

        deadline = datetime.datetime.now() + datetime.timedelta(
            seconds=self.config.issuance_timeout)

        logger.debug("Will poll for certificate issuance until %s", deadline)

        orderr = self.acme.finalize_order(
            orderr, deadline, fetch_alternative_chains=self.config.preferred_chain is not None)

        fullchain = orderr.fullchain_pem
        if self.config.preferred_chain and orderr.alternative_fullchains_pem:
            fullchain = crypto_util.find_chain_with_issuer(
                [fullchain] + orderr.alternative_fullchains_pem,
                self.config.preferred_chain, not self.config.dry_run)
        cert, chain = crypto_util.cert_and_chain_from_fullchain(fullchain)
        return cert.encode(), chain.encode()

    def obtain_certificate(self, domains: List[str], old_keypath: Optional[str] = None,
                           ari_hint: str = '') -> Tuple[bytes, bytes, util.Key, util.CSR]:
        """Obtains a certificate from the ACME server.

        `.register` must be called before `.obtain_certificate`

        :param list domains: domains to get a certificate
        :param str ari_hint: draft-ietf-acme-ari identifier for cert replaced

        :returns: certificate as PEM string, chain as PEM string,
            newly generated private key (`.util.Key`), and DER-encoded
            Certificate Signing Request (`.util.CSR`).
        :rtype: tuple

        """
        # We need to determine the key path, key PEM data, CSR path,
        # and CSR PEM data.  For a dry run, the paths are None because
        # they aren't permanently saved to disk.  For a lineage with
        # --reuse-key, the key path and PEM data are derived from an
        # existing file.

        if old_keypath is not None:
            # We've been asked to reuse a specific existing private key.
            # Therefore, we'll read it now and not generate a new one in
            # either case below.
            #
            # We read in bytes here because the type of `key.pem`
            # created below is also bytes.
            with open(old_keypath, "rb") as f:
                keypath = old_keypath
                keypem = f.read()
            key: Optional[util.Key] = util.Key(file=keypath, pem=keypem)
            logger.info("Reusing existing private key from %s.", old_keypath)
        else:
            # The key is set to None here but will be created below.
            key = None

        key_size = self.config.rsa_key_size
        elliptic_curve = "secp256r1"

        # key-type defaults to a list, but we are only handling 1 currently
        if isinstance(self.config.key_type, list):
            self.config.key_type = self.config.key_type[0]
        if self.config.elliptic_curve and self.config.key_type == 'ecdsa':
            elliptic_curve = self.config.elliptic_curve
            self.config.auth_chain_path = "./chain-ecdsa.pem"
            self.config.auth_cert_path = "./cert-ecdsa.pem"
            self.config.key_path = "./key-ecdsa.pem"
        elif self.config.rsa_key_size and self.config.key_type.lower() == 'rsa':
            key_size = self.config.rsa_key_size

        # Create CSR from names
        if self.config.dry_run:
            key = key or util.Key(
                file=None,
                pem=crypto_util.make_key(
                    bits=key_size,
                    elliptic_curve=elliptic_curve,
                    key_type=self.config.key_type,

                ),
            )
            csr = util.CSR(file=None, form="pem",
                           data=acme_crypto_util.make_csr(
                               key.pem, domains, self.config.must_staple))
        else:
            key = key or crypto_util.generate_key(
                key_size=key_size,
                key_dir=None,
                key_type=self.config.key_type,
                elliptic_curve=elliptic_curve,
                strict_permissions=self.config.strict_permissions,
            )
            csr = crypto_util.generate_csr(
                key, domains, None, self.config.must_staple, self.config.strict_permissions)

        try:
            orderr = self._get_order_and_authorizations(csr.data,
                                                        self.config.allow_subset_of_names, ari_hint)
        except messages.Error as error:
            # Some domains may be rejected during order creation.
            # Certbot can retry the operation without the rejected
            # domains contained within subproblems.
            if self.config.allow_subset_of_names:
                successful_domains = self._successful_domains_from_error(error, domains)
                if successful_domains != domains and len(successful_domains) != 0:
                    return self._retry_obtain_certificate(domains, successful_domains, old_keypath)
            raise
        authzr = orderr.authorizations
        auth_domains = {a.body.identifier.value for a in authzr}
        successful_domains = [d for d in domains if d in auth_domains]

        # allow_subset_of_names is currently disabled for wildcard
        # certificates. The reason for this and checking allow_subset_of_names
        # below is because successful_domains == domains is never true if
        # domains contains a wildcard because the ACME spec forbids identifiers
        # in authzs from containing a wildcard character.
        if self.config.allow_subset_of_names and successful_domains != domains:
            return self._retry_obtain_certificate(domains, successful_domains, old_keypath)
        else:
            try:
                cert, chain = self.obtain_certificate_from_csr(csr, orderr)
                return cert, chain, key, csr
            except messages.Error as error:
                # Some domains may be rejected during the very late stage of
                # order finalization. Certbot can retry the operation without
                # the rejected domains contained within subproblems.
                if self.config.allow_subset_of_names:
                    successful_domains = self._successful_domains_from_error(error, domains)
                    if successful_domains != domains and len(successful_domains) != 0:
                        return self._retry_obtain_certificate(
                            domains, successful_domains, old_keypath)
                raise

    def _get_order_and_authorizations(self, csr_pem: bytes,
                                      best_effort: bool,
                                      ari_hint: str = '') -> messages.OrderResource:
        """Request a new order and complete its authorizations.

        :param bytes csr_pem: A CSR in PEM format.
        :param bool best_effort: True if failing to complete all
            authorizations should not raise an exception

        :returns: order resource containing its completed authorizations
        :rtype: acme.messages.OrderResource

        """
        if not self.acme:
            raise errors.Error("ACME client is not set.")
        try:
            orderr = self.acme.new_order(csr_pem, ari_hint = ari_hint)
        except acme_errors.WildcardUnsupportedError:
            raise errors.Error("The currently selected ACME CA endpoint does"
                               " not support issuing wildcard certificates.")

        if not self.auth_handler:
            raise errors.Error("No authorization handler has been set.")

        # For a dry run, ensure we have an order with fresh authorizations
        if orderr and self.config.dry_run:
            deactivated, failed = self.auth_handler.deactivate_valid_authorizations(orderr)
            if deactivated:
                logger.debug("Recreating order after authz deactivations")
                orderr = self.acme.new_order(csr_pem)
            if failed:
                logger.warning("Certbot was unable to obtain fresh authorizations for every domain"
                               ". The dry run will continue, but results may not be accurate.")

        authzr = self.auth_handler.handle_authorizations(orderr, self.config, best_effort)
        return orderr.update(authorizations=authzr)

    def obtain_and_enroll_certificate(self, domains: List[str], certname: Optional[str]
                                      ) -> Optional[storage.RenewableCert]:
        """Obtain and enroll certificate.

        Get a new certificate for the specified domains using the specified
        authenticator and installer, and then create a new renewable lineage
        containing it.

        :param domains: domains to request a certificate for
        :type domains: `list` of `str`
        :param certname: requested name of lineage
        :type certname: `str` or `None`

        :returns: A new :class:`certbot._internal.storage.RenewableCert` instance
            referred to the enrolled cert lineage, or None if doing a successful dry run.

        """
        new_name = self._choose_lineagename(domains, certname)
        cert, chain, key, _ = self.obtain_certificate(domains)

        if (self.config.config_dir != constants.CLI_DEFAULTS["config_dir"] or
                self.config.work_dir != constants.CLI_DEFAULTS["work_dir"]):
            logger.info(
                "Non-standard path(s), might not work with crontab installed "
                "by your operating system package manager")

        if self.config.dry_run:
            logger.debug("Dry run: Skipping creating new lineage for %s", new_name)
            return None
        return storage.RenewableCert.new_lineage(
            new_name, cert,
            key.pem, chain,
            self.config)

    def _successful_domains_from_error(self, error: messages.Error, domains: List[str],
                                ) -> List[str]:
        if error.subproblems is not None:
            failed_domains = [problem.identifier.value for problem in error.subproblems
                                if problem.identifier is not None]
            successful_domains = [x for x in domains if x not in failed_domains]
            return successful_domains
        return []

    def _retry_obtain_certificate(self, domains: List[str], successful_domains: List[str],
                                old_keypath: Optional[str]
                                ) -> Tuple[bytes, bytes, util.Key, util.CSR]:
        failed_domains = [d for d in domains if d not in successful_domains]
        domains_list = ", ".join(failed_domains)
        display_util.notify("Unable to obtain a certificate with every requested "
            f"domain. Retrying without: {domains_list}")
        return self.obtain_certificate(successful_domains, old_keypath)

    def _choose_lineagename(self, domains: List[str], certname: Optional[str]) -> str:
        """Chooses a name for the new lineage.

        :param domains: domains in certificate request
        :type domains: `list` of `str`
        :param certname: requested name of lineage
        :type certname: `str` or `None`

        :returns: lineage name that should be used
        :rtype: str

        :raises errors.Error: If the chosen lineage name is invalid.

        """
        # Remember chosen name for new lineage
        lineagename = None
        if certname:
            lineagename = certname
        elif util.is_wildcard_domain(domains[0]):
            # Don't make files and directories starting with *.
            lineagename = domains[0][2:]
        else:
            lineagename = domains[0]
        # Verify whether chosen lineage is valid
        if self._is_valid_lineagename(lineagename):
            return lineagename
        else:
            raise errors.Error(
                "The provided certname cannot be used as a lineage name because it contains "
                "an illegal character (i.e. filepath separator)." if certname else
                "Cannot use domain name as lineage name because it contains an illegal "
                "character (i.e. filepath separator). Specify an explicit lineage name "
                "with --cert-name.")

    def _is_valid_lineagename(self, name: str) -> bool:
        """Determines whether the provided name is a valid lineagename. A lineagename
        is invalid when it contains filepath separators.

        :param name: the lineage name to determine validity for
        :type name: `str`

        :returns: Whether the provided string constitutes a valid lineage name.
        :rtype: bool

        """
        return os.path.sep not in name

    def save_certificate(self, cert_pem: bytes, chain_pem: bytes,
                         cert_path: str, chain_path: str, fullchain_path: str
                         ) -> Tuple[str, str, str]:
        """Saves the certificate received from the ACME server.

        :param bytes cert_pem:
        :param bytes chain_pem:
        :param str cert_path: Candidate path to a certificate.
        :param str chain_path: Candidate path to a certificate chain.
        :param str fullchain_path: Candidate path to a full cert chain.

        :returns: cert_path, chain_path, and fullchain_path as absolute
            paths to the actual files
        :rtype: `tuple` of `str`

        :raises IOError: If unable to find room to write the cert files

        """
        for path in cert_path, chain_path, fullchain_path:
            util.make_or_verify_dir(os.path.dirname(path), 0o755, self.config.strict_permissions)

        cert_file, abs_cert_path = _open_pem_file(self.config, 'cert_path', cert_path)

        try:
            cert_file.write(cert_pem)
        finally:
            cert_file.close()

        chain_file, abs_chain_path = _open_pem_file(self.config, 'chain_path', chain_path)
        fullchain_file, abs_fullchain_path = _open_pem_file(
            self.config, 'fullchain_path', fullchain_path)

        _save_chain(chain_pem, chain_file)
        _save_chain(cert_pem + chain_pem, fullchain_file)

        return abs_cert_path, abs_chain_path, abs_fullchain_path

    def deploy_certificate(self, domains: List[str], privkey_path: str, cert_path: str,
                           chain_path: str, fullchain_path: str) -> None:
        """Install certificate

        :param list domains: list of domains to install the certificate
        :param str privkey_path: path to certificate private key
        :param str cert_path: certificate file path (optional)
        :param str fullchain_path: path to the full chain of the certificate
        :param str chain_path: chain file path

        """
        if self.installer is None:
            logger.error("No installer specified, client is unable to deploy"
                           "the certificate")
            raise errors.Error("No installer available")

        chain_path = None if chain_path is None else os.path.abspath(chain_path)

        display_util.notify("Deploying certificate")

        msg = "Could not install certificate"
        with error_handler.ErrorHandler(self._recovery_routine_with_msg, msg):
            for dom in domains:
                self.installer.deploy_cert(
                    domain=dom, cert_path=os.path.abspath(cert_path),
                    key_path=os.path.abspath(privkey_path),
                    chain_path=chain_path,
                    fullchain_path=fullchain_path)
                self.installer.save()  # needed by the Apache plugin

            self.installer.save("Deployed ACME Certificate")

        msg = ("We were unable to install your certificate, "
               "however, we successfully restored your "
               "server to its prior configuration.")
        with error_handler.ErrorHandler(self._rollback_and_restart, msg):
            # sites may have been enabled / final cleanup
            self.installer.restart()

    def enhance_config(self, domains: List[str], chain_path: str,
                       redirect_default: bool = True) -> None:
        """Enhance the configuration.

        :param list domains: list of domains to configure
        :param chain_path: chain file path
        :type chain_path: `str` or `None`
        :param redirect_default: boolean value that the "redirect" flag should default to

        :raises .errors.Error: if no installer is specified in the
            client.

        """
        if self.installer is None:
            logger.error("No installer is specified, there isn't any "
                           "configuration to enhance.")
            raise errors.Error("No installer available")

        enhanced = False
        enhancement_info = (
            ("hsts", "ensure-http-header", "Strict-Transport-Security"),
            ("redirect", "redirect", None),
            ("staple", "staple-ocsp", chain_path),
            ("uir", "ensure-http-header", "Upgrade-Insecure-Requests"),)
        supported = self.installer.supported_enhancements()

        for config_name, enhancement_name, option in enhancement_info:
            config_value = getattr(self.config, config_name)
            if enhancement_name in supported:
                if config_name == "redirect" and config_value is None:
                    config_value = redirect_default
                if config_value:
                    self.apply_enhancement(domains, enhancement_name, option)
                    enhanced = True
            elif config_value:
                logger.error(
                    "Option %s is not supported by the selected installer. "
                    "Skipping enhancement.", config_name)

        msg = "We were unable to restart web server"
        if enhanced:
            with error_handler.ErrorHandler(self._rollback_and_restart, msg):
                self.installer.restart()

    def apply_enhancement(self, domains: List[str], enhancement: str,
                          options: Optional[str] = None) -> None:
        """Applies an enhancement on all domains.

        :param list domains: list of ssl_vhosts (as strings)
        :param str enhancement: name of enhancement, e.g. ensure-http-header
        :param str options: options to enhancement, e.g. Strict-Transport-Security

            .. note:: When more `options` are needed, make options a list.

        :raises .errors.PluginError: If Enhancement is not supported, or if
            there is any other problem with the enhancement.


        """
        if not self.installer:
            raise errors.Error("No installer plugin has been set.")
        enh_label = options if enhancement == "ensure-http-header" else enhancement
        with error_handler.ErrorHandler(self._recovery_routine_with_msg, None):
            for dom in domains:
                try:
                    self.installer.enhance(dom, enhancement, options)
                except errors.PluginEnhancementAlreadyPresent:
                    logger.info("Enhancement %s was already set.", enh_label)
                except errors.PluginError:
                    logger.error("Unable to set the %s enhancement for %s.", enh_label, dom)
                    raise

            self.installer.save(f"Add enhancement {enh_label}")

    def _recovery_routine_with_msg(self, success_msg: Optional[str]) -> None:
        """Calls the installer's recovery routine and prints success_msg

        :param str success_msg: message to show on successful recovery

        """
        if self.installer:
            self.installer.recovery_routine()
            if success_msg:
                display_util.notify(success_msg)

    def _rollback_and_restart(self, success_msg: str) -> None:
        """Rollback the most recent checkpoint and restart the webserver

        :param str success_msg: message to show on successful rollback

        """
        if self.installer:
            logger.info("Rolling back to previous server configuration...")
            try:
                self.installer.rollback_checkpoints()
                self.installer.restart()
            except:
                logger.error(
                    "An error occurred and we failed to restore your config and "
                    "restart your server. Please post to "
                    "https://community.letsencrypt.org/c/help "
                    "with details about your configuration and this error you received."
                )
                raise
            display_util.notify(success_msg)


def validate_key_csr(privkey: util.Key, csr: Optional[util.CSR] = None) -> None:
    """Validate Key and CSR files.

    Verifies that the client key and csr arguments are valid and correspond to
    one another. This does not currently check the names in the CSR due to
    the inability to read SANs from CSRs in python crypto libraries.

    If csr is left as None, only the key will be validated.

    :param privkey: Key associated with CSR
    :type privkey: :class:`certbot.util.Key`

    :param .util.CSR csr: CSR

    :raises .errors.Error: when validation fails

    """
    # TODO: Handle all of these problems appropriately
    # The client can eventually do things like prompt the user
    # and allow the user to take more appropriate actions

    # Key must be readable and valid.
    if privkey.pem and not crypto_util.valid_privkey(privkey.pem):
        raise errors.Error("The provided key is not a valid key")

    if csr:
        if csr.form == "der":
            csr_obj = x509.load_der_x509_csr(csr.data)
            csr_pem = csr_obj.public_bytes(serialization.Encoding.PEM)
            csr = util.CSR(csr.file, csr_pem, "pem")

        # If CSR is provided, it must be readable and valid.
        if csr.data and not crypto_util.valid_csr(csr.data):
            raise errors.Error("The provided CSR is not a valid CSR")

        # If both CSR and key are provided, the key must be the same key used
        # in the CSR.
        if csr.data and privkey.pem:
            if not crypto_util.csr_matches_pubkey(
                    csr.data, privkey.pem):
                raise errors.Error("The key and CSR do not match")


def rollback(default_installer: str, checkpoints: int,
             config: configuration.NamespaceConfig, plugins: plugin_disco.PluginsRegistry) -> None:
    """Revert configuration the specified number of checkpoints.

    :param str default_installer: Default installer name to use for the rollback
    :param int checkpoints: Number of checkpoints to revert.
    :param config: Configuration.
    :type config: :class:`certbot.configuration.NamespaceConfiguration`
    :param plugins: Plugins available
    :type plugins: :class:`certbot._internal.plugins.disco.PluginsRegistry`

    """
    # Misconfigurations are only a slight problems... allow the user to rollback
    installer = plugin_selection.pick_installer(
        config, default_installer, plugins, question="Which installer "
        "should be used for rollback?")

    # No Errors occurred during init... proceed normally
    # If installer is None... couldn't find an installer... there shouldn't be
    # anything to rollback
    if installer is not None:
        installer.rollback_checkpoints(checkpoints)
        installer.restart()


def _open_pem_file(config: configuration.NamespaceConfig,
                   cli_arg_path: str, pem_path: str) -> Tuple[IO, str]:
    """Open a pem file.

    If cli_arg_path was set by the client, open that.
    Otherwise, uniquify the file path.

    :param str cli_arg_path: the cli arg name, e.g. cert_path
    :param str pem_path: the pem file path to open

    :returns: a tuple of file object and its absolute file path

    """
    if config.set_by_user(cli_arg_path):
        return util.safe_open(pem_path, chmod=0o644, mode="wb"),\
            os.path.abspath(pem_path)
    uniq = util.unique_file(pem_path, 0o644, "wb")
    return uniq[0], os.path.abspath(uniq[1])


def _save_chain(chain_pem: bytes, chain_file: IO) -> None:
    """Saves chain_pem at a unique path based on chain_path.

    :param bytes chain_pem: certificate chain in PEM format
    :param str chain_file: chain file object

    """
    try:
        chain_file.write(chain_pem)
    finally:
        chain_file.close()
