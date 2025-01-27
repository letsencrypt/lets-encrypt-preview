# Certbot change log

Certbot adheres to [Semantic Versioning](https://semver.org/).

## 3.2.0 - main

### Added

*

### Changed

* certbot-nginx now requires pyparsing>=2.4.7.
* certbot and its acme library now require cryptography>=42.0.0.
* certbot-nginx and our acme library now require pyOpenSSL>=25.0.0.
* Deprecated `gen_ss_cert` in `acme.crypto_util` as it uses deprecated
  pyOpenSSL API.
* Add `make_self_signed_cert` to `acme.crypto_util` to replace `gen_ss_cert.

### Fixed

* Private keys are now saved in PKCS#8 format instead of PKCS#1. Using PKCS#1
  was a regression introduced in Certbot 3.1.0.
* Allow nginx plugin to parse non-breaking spaces in nginx configuration files.
* Honor --reuse-key when --allow-subset-of-names is set
* Fixed regression in symlink parsing on Windows that was introduced in Certbot
  3.1.0.
* Nginx `server_name` directives with internal comments now ignore commented names

More details about these changes can be found on our GitHub repo.

## 3.1.0 - 2025-01-07

### Added

*

### Changed

* Python 3.8 support was removed.
* certbot-dns-rfc2136's minimum required version of dnspython is now 2.6.1.
* Updated our Docker images to be based on Alpine Linux 3.20.
* Our runtime dependency on setuptools has been dropped from all Certbot
  components.
* Certbot's packages no longer depend on library importlib_resources.

### Fixed

* Included an OpenSSL library that was missing in our Certbot snap fixing
  crashes affecting 32-bit ARM users.

More details about these changes can be found on our GitHub repo.

## 3.0.1 - 2024-11-14

### Fixed

* Removed a CryptographyDeprecationWarning that was being displayed to users
  when checking OCSP status.

More details about these changes can be found on our GitHub repo.

## 3.0.0 - 2024-11-05

### Added

*

### Changed

* The update_symlinks command was removed.
* The `csr_dir` and `key_dir` attributes on
  `certbot.configuration.NamespaceConfig` were removed.
* The `--manual-public-ip-logging-ok` command line flag was removed.
* The `--dns-route53-propagation-seconds` command line flag was removed.
* The `certbot_dns_route53.authenticator` module has been removed. This should
  not affect any users of the plugin and instead would only affect developers
  trying to develop on top of the old code.
* Support for Python 3.8 was deprecated and will be removed in our next planned
  release.

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 2.11.0 - 2024-06-05

### Added

*

### Changed

* In anticipation of backwards incompatible changes, certbot-dns-cloudflare now
  requires less than version 2.20 of Cloudflare's python library.

### Fixed

* Fixed a bug in Certbot where a CSR's SANs did not always follow the order of
  the domain names that the user requested interactively. In some cases, the
  resulting cert's common name might seem picked up randomly from the SANs
  when it should be the first item the user had in mind.

More details about these changes can be found on our GitHub repo.

## 2.10.0 - 2024-04-02

### Added

* The Python source packages which we upload to [PyPI](https://pypi.org/) are
  now also being uploaded to
  [our releases on GitHub](https://github.com/certbot/certbot/releases) where
  we now also include a SHA256SUMS checksum file and a PGP signature for that
  file.

### Changed

* We no longer publish our beta Windows installer as was originally announced
  [here](https://community.letsencrypt.org/t/certbot-discontinuing-windows-beta-support-in-2024/208101).

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 2.9.0 - 2024-02-08

### Added

* Support for Python 3.12 was added.

### Changed

*

### Fixed

* Updates `joinpath` syntax to only use one addition per call, because the multiple inputs
  version was causing mypy errors on Python 3.10.
* Makes the `reconfigure` verb actually use the staging server for the dry run to check the new
  configuration.

More details about these changes can be found on our GitHub repo.

## 2.8.0 - 2023-12-05

### Added

* Added support for [Alpine Linux](https://www.alpinelinux.org) distribution when is used the apache plugin

### Changed

* Support for Python 3.7 was removed.

### Fixed

* Stop using the deprecated `pkg_resources` API included in `setuptools`.

More details about these changes can be found on our GitHub repo.

## 2.7.4 - 2023-11-01

### Fixed

* Fixed a bug introduced in version 2.7.0 that caused interactively entered
  webroot plugin values to not be saved for renewal.
* Fixed a bug introduced in version 2.7.0 of our Lexicon based DNS plugins that
  caused them to fail to find the DNS zone that needs to be modified in some
  cases.

More details about these changes can be found on our GitHub repo.

## 2.7.3 - 2023-10-24

### Fixed

* Fixed a bug where arguments with contained spaces weren't being handled correctly
* Fixed a bug that caused the ACME account to not be properly restored on
  renewal causing problems in setups where the user had multiple accounts with
  the same ACME server.

More details about these changes can be found on our GitHub repo.

## 2.7.2 - 2023-10-19

### Fixed

* `certbot-dns-ovh` plugin now requires `lexicon>=3.15.1` to ensure a consistent behavior with OVH APIs.
* Fixed a bug where argument sources weren't correctly detected in abbreviated
  arguments, short arguments, and some other circumstances

More details about these changes can be found on our GitHub repo.

## 2.7.1 - 2023-10-10

### Fixed

* Fixed a bug that broke the DNS plugin for DNSimple that was introduced in
  version 2.7.0 of the plugin.
* Correctly specified the new minimum version of the ConfigArgParse package
  that Certbot requires which is 1.5.3.

More details about these changes can be found on our GitHub repo.

## 2.7.0 - 2023-10-03

### Added

* Add `certbot.util.LooseVersion` class. See [GH #9489](https://github.com/certbot/certbot/issues/9489).
* Add a new base class `certbot.plugins.dns_common_lexicon.LexiconDNSAuthenticator` to implement a DNS
  authenticator plugin backed by Lexicon to communicate with the provider DNS API. This approach relies
  heavily on conventions to reduce the implementation complexity of a new plugin.
* Add a new test base class `certbot.plugins.dns_test_common_lexicon.BaseLexiconDNSAuthenticatorTest` to
  help testing DNS plugins implemented on top of `LexiconDNSAuthenticator`.

### Changed

* `NamespaceConfig` now tracks how its arguments were set via a dictionary, allowing us to remove a bunch
  of global state previously needed to inspect whether a user set an argument or not.
* Support for Python 3.7 was deprecated and will be removed in our next planned release.
* Added `RENEWED_DOMAINS` and `FAILED_DOMAINS` environment variables for consumption by post renewal hooks.
* Deprecates `LexiconClient` base class and `build_lexicon_config` function in
  `certbot.plugins.dns_common_lexicon` module in favor of `LexiconDNSAuthenticator`.
* Deprecates `BaseLexiconAuthenticatorTest` and `BaseLexiconClientTest` test base classes of
  `certbot.plugins.dns_test_common_lexicon` module in favor of `BaseLexiconDNSAuthenticatorTest`.

### Fixed

* Do not call deprecated datetime.utcnow() and datetime.utcfromtimestamp()
* Filter zones in `certbot-dns-google` to avoid usage of private DNS zones to create records

More details about these changes can be found on our GitHub repo.

## 2.6.0 - 2023-05-09

### Added

* `--dns-google-project` optionally allows for specifying the project that the DNS zone(s) reside in,
  which allows for Certbot usage in scenarios where the auth credentials reside in a different
  project to the zone(s) that are being managed.
* There is now a new `Other` annotated challenge object to allow plugins to support entirely novel challenges.

### Changed

* Optionally sign the SOA query for dns-rfc2136, to help resolve problems with split-view
  DNS setups and hidden primary setups.
  * Certbot versions prior to v1.32.0 did not sign queries with the specified TSIG key
    resulting in difficulty with split-horizon implementations.
  * Certbot v1.32.0 through v2.5.0 signed queries by default, potentially causing
    incompatibility with hidden primary setups with `allow-update-forwarding` enabled
    if the secondary did not also have the TSIG key within its config.
  * Certbot v2.6.0 and later no longer signs queries by default, but allows
    the user to optionally sign these queries by explicit configuration using the
    `dns_rfc2136_sign_query` option in the credentials .ini file.
* Lineage name validity is performed for new lineages. `--cert-name` may no longer contain
  filepath separators (i.e. `/` or `\`, depending on the platform).
* `certbot-dns-google` now loads credentials using the standard [Application Default
  Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) strategy,
  rather than explicitly requiring the Google Compute metadata server to be present if a service account
  is not provided using `--dns-google-credentials`.
* `--dns-google-credentials` now supports additional types of file-based credential, such as
  [External Account Credentials](https://google.aip.dev/auth/4117) created by Workload Identity
  Federation. All file-based credentials implemented by the Google Auth library are supported.

### Fixed

* `certbot-dns-google` no longer requires deprecated `oauth2client` library.
* Certbot will no longer try to invoke plugins which do not subclass from the proper
  `certbot.interfaces.{Installer,Authenticator}` interface (e.g. `certbot -i standalone`
  will now be ignored). See [GH-9664](https://github.com/certbot/certbot/issues/9664).

More details about these changes can be found on our GitHub repo.

## 2.5.0 - 2023-04-04

### Added

* `acme.messages.OrderResource` now supports being round-tripped
  through JSON
* acme.client.ClientV2 now provides separate `begin_finalization`
  and `poll_finalization` methods, in addition to the existing
  `finalize_order` method.

### Changed

* `--dns-route53-propagation-seconds` is now deprecated. The Route53 plugin relies on the
  [GetChange API](https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetChange.html)
  to determine if a DNS update is complete. The flag has never had any effect and will be
  removed in a future version of Certbot.
* Packaged tests for all Certbot components besides josepy were moved inside
  the `_internal/tests` module.

### Fixed

* Fixed `renew` sometimes not preserving the key type of RSA certificates.
  * Users who upgraded from Certbot <v1.25.0 to Certbot >=v2.0.0 may
    have had their RSA certificates inadvertently changed to ECDSA certificates. If desired,
    the key type may be changed back to RSA. See the [User Guide](https://eff-certbot.readthedocs.io/en/stable/using.html#changing-a-certificate-s-key-type).
* Deprecated flags were inadvertently not printing warnings since v1.16.0. This is now fixed.

More details about these changes can be found on our GitHub repo.

## 2.4.0 - 2023-03-07

### Added

* We deprecated support for the update_symlinks command. Support will be removed in a following
  version of Certbot.

### Changed

* Docker build and deploy scripts now generate multiarch manifests for non-architecture-specific tags, instead of defaulting to amd64 images.

### Fixed

* Reverted [#9475](https://github.com/certbot/certbot/pull/9475) due to a performance regression in large nginx deployments.

More details about these changes can be found on our GitHub repo.

## 2.3.0 - 2023-02-14

### Added

* Allow a user to modify the configuration of a certificate without renewing it using the new `reconfigure` subcommand. See `certbot help reconfigure` for details.
* `certbot show_account` now displays the [ACME Account Thumbprint](https://datatracker.ietf.org/doc/html/rfc8555#section-8.1).

### Changed

* Certbot will no longer save previous CSRs and certificate private keys to `/etc/letsencrypt/csr` and `/etc/letsencrypt/keys`, respectively. These directories may be safely deleted.
* Certbot will now only keep the current and 5 previous certificates in the `/etc/letsencrypt/archive` directory for each certificate lineage. Any prior certificates will be automatically deleted upon renewal. This number may be further lowered in future releases.
  * As always, users should only reference the certificate files within `/etc/letsencrypt/live` and never use `/etc/letsencrypt/archive` directly. See [Where are my certificates?](https://eff-certbot.readthedocs.io/en/stable/using.html#where-are-my-certificates) in the Certbot User Guide.
* `certbot.configuration.NamespaceConfig.key_dir` and `.csr_dir` are now deprecated.
* All Certbot components now require `pytest` to run tests.

### Fixed

* Fixed a crash when registering an account with BuyPass' ACME server.
* Fixed a bug where Certbot would crash with `AttributeError: can't set attribute` on ACME server errors in Python 3.11. See [GH #9539](https://github.com/certbot/certbot/issues/9539).

More details about these changes can be found on our GitHub repo.

## 2.2.0 - 2023-01-11

### Added

*

### Changed

* Certbot will no longer respect very long challenge polling intervals, which may be suggested
  by some ACME servers. Certbot will continue to wait up to 90 seconds by default, or up to a
  total of 30 minutes if requested by the server via `Retry-After`.

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 1.32.2 - 2022-12-16

### Fixed

* Our snaps and Docker images were rebuilt to include updated versions of our dependencies.

This release was not pushed to PyPI since those packages were unaffected.

More details about these changes can be found on our GitHub repo.

## 2.1.1 - 2022-12-15

### Fixed

* Our snaps, Docker images, and Windows installer were rebuilt to include updated versions of our dependencies.

This release was not pushed to PyPI since those packages were unaffected.

More details about these changes can be found on our GitHub repo.

## 2.1.0 - 2022-12-07

### Added

*

### Changed

*

### Fixed

* Interfaces which plugins register themselves as implementing without inheriting from them now show up in `certbot plugins` output.
* `IPluginFactory`, `IPlugin`, `IAuthenticator` and `IInstaller` have been re-added to
  `certbot.interfaces`.
    - This is to fix compatibility with a number of third-party DNS plugins which may
      have started erroring with `AttributeError` in Certbot v2.0.0.
    - Plugin authors can find more information about Certbot 2.x compatibility
      [here](https://github.com/certbot/certbot/wiki/Certbot-v2.x-Plugin-Compatibility).
* A bug causing our certbot-apache tests to crash on some systems has been resolved.

More details about these changes can be found on our GitHub repo.

## 1.32.1 - 2022-12-05

### Fixed

* Our snaps and docker images were rebuilt to include updated versions of our dependencies.

This release was not pushed to PyPI since those packages were unaffected.

More details about these changes can be found on our GitHub repo.

## 2.0.0 - 2022-11-21

### Added

* Support for Python 3.11 was added to Certbot and all of its components.
* `acme.challenges.HTTP01Response.simple_verify` now accepts a timeout argument which defaults to 30 that causes the verification request to timeout after that many seconds.

### Changed

* The default key type for new certificates is now ECDSA `secp256r1` (P-256). It was previously RSA 2048-bit. Existing certificates are not affected.
* The Apache plugin no longer supports Apache 2.2.
* `acme` and Certbot no longer support versions of ACME from before the RFC 8555 standard.
* `acme` and Certbot no longer support the old `urn:acme:error:` ACME error prefix.
* Removed the deprecated `certbot-dns-cloudxns` plugin.
* Certbot will now error if a certificate has `--reuse-key` set and a conflicting `--key-type`, `--key-size` or `--elliptic-curve` is requested on the CLI. Use `--new-key` to change the key while preserving `--reuse-key`.
* 3rd party plugins no longer support the `dist_name:plugin_name` format on the CLI and in configuration files. Use the shorter `plugin_name` format.
* `acme.client.Client`, `acme.client.ClientBase`, `acme.client.BackwardsCompatibleClientV2`, `acme.mixins`, `acme.client.DER_CONTENT_TYPE`, `acme.fields.Resource`, `acme.fields.resource`, `acme.magic_typing`, `acme.messages.OLD_ERROR_PREFIX`, `acme.messages.Directory.register`, `acme.messages.Authorization.resolved_combinations`, `acme.messages.Authorization.combinations` have been removed.
* `acme.messages.Directory` now only supports lookups by the exact resource name string in the ACME directory (e.g. `directory['newOrder']`).
* Removed the deprecated `source_address` argument for `acme.client.ClientNetwork`.
* The `zope` based interfaces in `certbot.interfaces` have been removed in favor of the `abc` based interfaces found in the same module.
* Certbot no longer depends on `zope`.
* Removed deprecated function `certbot.util.get_strict_version`.
* Removed deprecated functions `certbot.crypto_util.init_save_csr`, `certbot.crypto_util.init_save_key`,
  and `certbot.compat.misc.execute_command`
* The attributes `FileDisplay`, `NoninteractiveDisplay`, `SIDE_FRAME`, `input_with_timeout`, `separate_list_input`, `summarize_domain_list`, `HELP`, and `ESC` from `certbot.display.util` have been removed.
* Removed deprecated functions `certbot.tests.util.patch_get_utility*`. Plugins should now
  patch `certbot.display.util` themselves in their tests or use
  `certbot.tests.util.patch_display_util` as a temporary workaround.
* Certbot's test API under `certbot.tests` now uses `unittest.mock` instead of the 3rd party `mock` library.

### Fixed

* Fixes a bug where the certbot working directory has unusably restrictive permissions on systems with stricter default umasks.
* Requests to subscribe to the EFF mailing list now time out after 60 seconds.

We plan to slowly roll out Certbot 2.0 to all of our snap users in the coming months. If you want to use the Certbot 2.0 snap now, please follow the instructions at https://community.letsencrypt.org/t/certbot-2-0-beta-call-for-testing/185945.

More details about these changes can be found on our GitHub repo.

## 1.32.0 - 2022-11-08

### Added

*

### Changed

* DNS RFC2136 module now uses the TSIG key to check for an authoritative SOA record. Helps the use of split-horizon and multiple views in BIND9 using the key in an ACL to determine which view to use.

### Fixed

* CentOS 9 and other RHEL-derived OSes now correctly use httpd instead of apachectl for
  various Apache-related commands

More details about these changes can be found on our GitHub repo.

## 1.31.0 - 2022-10-04

### Added

*

### Changed

* If Certbot exits before setting up its usual log files, the temporary directory created to save logging information will begin with the name `certbot-log-` rather than a generic name. This should not be considered a [stable aspect of Certbot](https://certbot.eff.org/docs/compatibility.html) and may change again in the future.

### Fixed

* Fixed an incompatibility in the certbot-dns-cloudflare plugin and the Cloudflare library
  which was introduced in the Cloudflare library version 2.10.1. The library would raise
  an error if a token was specified in the Certbot `--dns-cloudflare-credentials` file as
  well as the `cloudflare.cfg` configuration file of the Cloudflare library.

More details about these changes can be found on our GitHub repo.

## 1.30.0 - 2022-09-07

### Added

*

### Changed

* `acme.client.ClientBase`, `acme.messages.Authorization.resolved_combinations`,
  `acme.messages.Authorization.combinations`, `acme.mixins`, `acme.fields.resource`,
  and `acme.fields.Resource` are deprecated and will be removed in a future release.
* `acme.messages.OLD_ERROR_PREFIX` (`urn:acme:error:`) is deprecated and support for
  the old ACME error prefix in Certbot will be removed in the next major release of
  Certbot.
* `acme.messages.Directory.register` is deprecated and will be removed in the next
  major release of Certbot. Furthermore, `.Directory` will only support lookups
  by the exact resource name string in the ACME directory  (e.g. `directory['newOrder']`).
* The `certbot-dns-cloudxns` plugin is now deprecated and will be removed in the
  next major release of Certbot.
* The `source_address` argument for `acme.client.ClientNetwork` is deprecated
  and support for it will be removed in the next major release.
* Add UI text suggesting users create certs for multiple domains, when possible

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 1.29.0 - 2022-07-05

### Added

* Updated Windows installer to be signed and trusted in Windows

### Changed

* `--allow-subset-of-names` will now additionally retry in cases where domains are rejected while creating or finalizing orders. This requires subproblem support from the ACME server.

### Fixed

* The `show_account` subcommand now uses the "newAccount" ACME endpoint to fetch the account
  data, so it doesn't rely on the locally stored account URL. This fixes situations where Certbot
  would use old ACMEv1 registration info with non-functional account URLs.

* The generated Certificate Signing Requests are now generated as version 1 instead of version 3. This resolves situations in where strict enforcement of PKCS#10 meant that CSRs that were generated as version 3 were rejected.

More details about these changes can be found on our GitHub repo.

## 1.28.0 - 2022-06-07

### Added

* Updated Apache/NGINX TLS configs to document contents are based on ssl-config.mozilla.org


### Changed

* A change to order finalization has been made to the `acme` module and Certbot:
  - An order's `certificate` field will only be processed if the order's `status` is `valid`.
  - An order's `error` field will only be processed if the order's `status` is `invalid`.

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 1.27.0 - 2022-05-03

### Added

* Added support for RFC8555 subproblems to our acme library.

### Changed

* The PGP key `F2871B4152AE13C49519111F447BF683AA3B26C3` was added as an
  additional trusted key to sign our PyPI packages
* When `certonly` is run with an installer specified (e.g.  `--nginx`),
  `certonly` will now also run `restart` for that installer

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 1.26.0 - 2022-04-05

### Added

* Added `--new-key`. When renewing or replacing a certificate that has `--reuse-key`
  set, it will force a new private key to be generated, one time.

  As before, `--reuse-key` and `--no-reuse-key` can be used to enable and disable key
  reuse.

### Changed

* The default propagation timeout for the OVH DNS plugin (`--dns-ovh-propagation-seconds`)
  has been increased from 30 seconds to 120 seconds, based on user feedback.

### Fixed

* Certbot for Windows has been upgraded to use Python 3.9.11, in response to
  https://www.openssl.org/news/secadv/20220315.txt.
* Previously, when Certbot was in the process of registering a new ACME account
  and the ACME server did not present any Terms of Service, the user was asked to
  agree with a non-existent Terms of Service ("None"). This bug is now fixed, so
  that if an ACME server does not provide any Terms of Service to agree with, the
  user is not asked to agree to a non-existent Terms of Service any longer.
* If account registration fails, Certbot did not relay the error from the ACME server
  back to the user. This is now fixed: the error message from the ACME server is now
  presented to the user when account registration fails.

More details about these changes can be found on our GitHub repo.

## 1.25.0 - 2022-03-16

### Added

*

### Changed

* Dropped 32 bit support for the Windows beta installer
* Windows beta installer is now distributed as "certbot-beta-installer-win_amd64.exe".
  Users of the Windows beta should uninstall the old version before running this.
* Added a check whether OCSP stapling is supported by the installer when requesting a
  certificate with the `run` subcommand in combination with the `--must-staple` option.
  If the installer does not support OCSP and the `--must-staple` option is used, Certbot
  will raise an error and quit.
* Certbot and its acme module now depend on josepy>=1.13.0 due to better type annotation
  support.

### Fixed

* Updated dependencies to use new version of cryptography that uses OpenSSL 1.1.1n, in
  response to https://www.openssl.org/news/secadv/20220315.txt.

More details about these changes can be found on our GitHub repo.

## 1.24.0 - 2022-03-01

### Added

* When the `--debug-challenges` option is used in combination with `-v`, Certbot
  now displays the challenge URLs (for `http-01` challenges) or FQDNs (for
  `dns-01` challenges) and their expected return values.
*

### Changed

* Support for Python 3.6 was removed.
* All Certbot components now require setuptools>=41.6.0.
* The acme library now requires requests>=2.20.0.
* Certbot and its acme library now require pytz>=2019.3.
* certbot-nginx now requires pyparsing>=2.2.1.
* certbot-dns-route53 now requires boto3>=1.15.15.

### Fixed

* Nginx plugin now checks included files for the singleton server_names_hash_bucket_size directive.
*

More details about these changes can be found on our GitHub repo.

## 1.23.0 - 2022-02-08

### Added

* Added `show_account` subcommand, which will fetch the account information
  from the ACME server and show the account details (account URL and, if
  applicable, email address or addresses)
* We deprecated support for Python 3.6 in Certbot and its ACME library.
  Support for Python 3.6 will be removed in the next major release of Certbot.

### Changed

*

### Fixed

* GCP Permission list for certbot-dns-google in plugin documentation
* dns-digitalocean used the SOA TTL for newly created records, rather than 30 seconds.
* Revoking a certificate based on an ECDSA key can now be done with `--key-path`.
  See [GH #8569](https://github.com/certbot/certbot/issues/8569).

More details about these changes can be found on our GitHub repo.

## 1.22.0 - 2021-12-07

### Added

* Support for Python 3.10 was added to Certbot and all of its components.
* The function certbot.util.parse_loose_version was added to parse version
  strings in the same way as the now deprecated distutils.version.LooseVersion
  class from the Python standard library.
* Added `--issuance-timeout`. This option specifies how long (in seconds) Certbot will wait
  for the server to issue a certificate.

### Changed

* The function certbot.util.get_strict_version was deprecated and will be
  removed in a future release.

### Fixed

* Fixed an issue on Windows where the `web.config` created by Certbot would sometimes
  conflict with preexisting configurations (#9088).
* Fixed an issue on Windows where the `webroot` plugin would crash when multiple domains
  had the same webroot. This affected Certbot 1.21.0.

More details about these changes can be found on our GitHub repo.

## 1.21.0 - 2021-11-02

### Added

* Certbot will generate a `web.config` file on Windows in the challenge path
  when the `webroot` plugin is used, if one does not exist. This `web.config` file
  lets IIS serve challenge files while they do not have an extension.

### Changed

* We changed the PGP key used to sign the packages we upload to PyPI. Going
  forward, releases will be signed with one of three different keys. All of
  these keys are available on major key servers and signed by our previous PGP
  key. The fingerprints of these new keys are:
    * BF6BCFC89E90747B9A680FD7B6029E8500F7DB16
    * 86379B4F0AF371B50CD9E5FF3402831161D1D280
    * 20F201346BF8F3F455A73F9A780CC99432A28621

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 1.20.0 - 2021-10-05

### Added

* Added `--no-reuse-key`. This remains the default behavior, but the flag may be
  useful to unset the `--reuse-key` option on existing certificates.

### Changed

*

### Fixed

* The certbot-dns-rfc2136 plugin in Certbot 1.19.0 inadvertently had an implicit
  dependency on `dnspython>=2.0`. This has been relaxed to `dnspython>=1.15.0`.

More details about these changes can be found on our GitHub repo.

## 1.19.0 - 2021-09-07

### Added

* The certbot-dns-rfc2136 plugin always assumed the use of an IP address as the
  target server, but this was never checked. Until now. The plugin raises an error
  if the configured target server is not a valid IPv4 or IPv6 address.
* Our acme library now supports requesting certificates for IP addresses.
  This feature is still unsupported by Certbot and Let's Encrypt.

### Changed

* Several attributes in `certbot.display.util` module are deprecated and will
  be removed in a future release of Certbot. Any import of these attributes will
  emit a warning to prepare the transition for developers.
* `zope` based interfaces in `certbot.interfaces` module are deprecated and will
  be removed in a future release of Certbot. Any import of these interfaces will
  emit a warning to prepare the transition for developers.
* We removed the dependency on `chardet` from our acme library. Except for when
  downloading a certificate in an alternate format, our acme library now
  assumes all server responses are UTF-8 encoded which is required by RFC 8555.

### Fixed

* Fixed parsing of `Define`d values in the Apache plugin to allow for `=` in the value.
* Fixed a relatively harmless crash when issuing a certificate with `--quiet`/`-q`.

More details about these changes can be found on our GitHub repo.

## 1.18.0 - 2021-08-03

### Added

* New functions that Certbot plugins can use to interact with the user have
  been added to `certbot.display.util`. We plan to deprecate using `IDisplay`
  with `zope` in favor of these new functions in the future.
* The `Plugin`, `Authenticator` and `Installer` classes are added to
  `certbot.interfaces` module as alternatives to Certbot's current `zope` based
  plugin interfaces. The API of these interfaces is identical, but they are
  based on Python's `abc` module instead of `zope`. Certbot will continue to
  detect plugins that implement either interface, but we plan to drop support
  for `zope` based interfaces in a future version of Certbot.
* The class `certbot.configuration.NamespaceConfig` is added to the Certbot's
  public API.

### Changed

* When self-validating HTTP-01 challenges using
  acme.challenges.HTTP01Response.simple_verify, we now assume that the response
  is composed of only ASCII characters. Previously we were relying on the
  default behavior of the requests library which tries to guess the encoding of
  the response which was error prone.
* `acme`: the `.client.Client` and `.client.BackwardsCompatibleClientV2` classes
  are now deprecated in favor of `.client.ClientV2`.
* The `certbot.tests.patch_get_utility*` functions have been deprecated.
  Plugins should now patch `certbot.display.util` themselves in their tests or
  use `certbot.tests.util.patch_display_util` as a temporary workaround.
* In order to simplify the transition to Certbot's new plugin interfaces, the
  classes `Plugin` and `Installer` in `certbot.plugins.common` module and
  `certbot.plugins.dns_common.DNSAuthenticator` now implement Certbot's new
  plugin interfaces. The Certbot plugins based on these classes are now
  automatically detected as implementing these interfaces.
* We added a dependency on `chardet` to our acme library so that it will be
  used over `charset_normalizer` in newer versions of `requests`.

### Fixed

* The Apache authenticator no longer crashes with "Unable to insert label"
  when encountering a completely empty vhost. This issue affected Certbot 1.17.0.
* Users of the Certbot snap on Debian 9 (Stretch) should no longer encounter an
  "access denied" error when installing DNS plugins.

More details about these changes can be found on our GitHub repo.

## 1.17.0 - 2021-07-06

### Added

* Add Void Linux overrides for certbot-apache.

### Changed

* We changed how dependencies are specified between Certbot packages. For this
  and future releases, higher level Certbot components will require that lower
  level components are the same version or newer. More specifically, version X
  of the Certbot package will now always require acme>=X and version Y of a
  plugin package will always require acme>=Y and certbot=>Y. Specifying
  dependencies in this way simplifies testing and development.
* The Apache authenticator now always configures virtual hosts which do not have
  an explicit `ServerName`. This should make it work more reliably with the
  default Apache configuration in Debian-based environments.

### Fixed

* When we increased the logging level on our nginx "Could not parse file" message,
  it caused a previously-existing inability to parse empty files to become more
  visible. We have now added the ability to correctly parse empty files, so that
  message should only show for more significant errors.

More details about these changes can be found on our GitHub repo.

## 1.16.0 - 2021-06-01

### Added

*

### Changed

* DNS plugins based on lexicon now require dns-lexicon >= v3.1.0
* Use UTF-8 encoding for renewal configuration files
* Windows installer now cleans up old Certbot dependency packages
  before installing the new ones to avoid version conflicts.
* This release contains a substantial command-line UX overhaul,
  based on previous user research. The main goal was to streamline
  and clarify output. If you would like to see more verbose output, use
  the -v or -vv flags. UX improvements are an iterative process and
  the Certbot team welcomes constructive feedback.
* Functions `certbot.crypto_util.init_save_key` and `certbot.crypto_util.init_save_csr`,
  whose behaviors rely on the global Certbot `config` singleton, are deprecated and will
  be removed in a future release. Please use `certbot.crypto_util.generate_key` and
  `certbot.crypto_util.generate_csr` instead.

### Fixed

* Fix TypeError due to incompatibility with lexicon >= v3.6.0
* Installers (e.g. nginx, Apache) were being restarted unnecessarily after dry-run renewals.
* Colors and bold text should properly render in all supported versions of Windows.

More details about these changes can be found on our GitHub repo.

## 1.15.0 - 2021-05-04

### Added

*

### Changed

*

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 1.14.0 - 2021-04-06

### Added

*

### Changed

* certbot-auto no longer checks for updates on any operating system.
* The module `acme.magic_typing` is deprecated and will be removed in a future release.
  Please use the built-in module `typing` instead.
* The DigitalOcean plugin now creates TXT records for the DNS-01 challenge with a lower 30s TTL.

### Fixed

* Don't output an empty line for a hidden certificate when `certbot certificates` is being used
  in combination with `--cert-name` or `-d`.

More details about these changes can be found on our GitHub repo.

## 1.13.0 - 2021-03-02

### Added

*

### Changed

* CLI flags `--os-packages-only`, `--no-self-upgrade`, `--no-bootstrap` and `--no-permissions-check`,
  which are related to certbot-auto, are deprecated and will be removed in a future release.
* Certbot no longer conditionally depends on an external mock module. Certbot's
  test API will continue to use it if it is available for backwards
  compatibility, however, this behavior has been deprecated and will be removed
  in a future release.
* The acme library no longer depends on the `security` extras from `requests`
  which was needed to support SNI in TLS requests when using old versions of
  Python 2.
* Certbot and all of its components no longer depend on the library `six`.
* The update of certbot-auto itself is now disabled on all RHEL-like systems.
* When revoking a certificate by `--cert-name`, it is no longer necessary to specify the `--server`
  if the certificate was obtained from a non-default ACME server.
* The nginx authenticator now configures all matching HTTP and HTTPS vhosts for the HTTP-01
  challenge. It is now compatible with external HTTPS redirection by a CDN or load balancer.

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 1.12.0 - 2021-02-02

### Added

*

### Changed

* The `--preferred-chain` flag now only checks the Issuer Common Name of the
  topmost (closest to the root) certificate in the chain, instead of checking
  every certificate in the chain.
  See [#8577](https://github.com/certbot/certbot/issues/8577).
* Support for Python 2 has been removed.
* In previous releases, we caused certbot-auto to stop updating its Certbot
  installation. In this release, we are beginning to disable updates to the
  certbot-auto script itself. This release includes Amazon Linux users, and all
  other systems that are not based on Debian or RHEL. We plan to make this
  change to the certbot-auto script for all users in the coming months.

### Fixed

* Fixed the apache component on openSUSE Tumbleweed which no longer provides
  an apache2ctl symlink and uses apachectl instead.
* Fixed a typo in `certbot/crypto_util.py` causing an error upon attempting `secp521r1` key generation

More details about these changes can be found on our GitHub repo.

## 1.11.0 - 2021-01-05

### Added

*

### Changed

* We deprecated support for Python 2 in Certbot and its ACME library.
  Support for Python 2 will be removed in the next planned release of Certbot.
* certbot-auto was deprecated on all systems. For more information about this
  change, see
  https://community.letsencrypt.org/t/certbot-auto-no-longer-works-on-debian-based-systems/139702/7.
* We deprecated support for Apache 2.2 in the certbot-apache plugin and it will
  be removed in a future release of Certbot.

### Fixed

* The Certbot snap no longer loads packages installed via `pip install --user`. This
  was unintended and DNS plugins should be installed via `snap` instead.
* `certbot-dns-google` would sometimes crash with HTTP 409/412 errors when used with very large zones. See [#6036](https://github.com/certbot/certbot/issues/6036).
* `certbot-dns-google` would sometimes crash with an HTTP 412 error if preexisting records had an unexpected TTL, i.e.: different than Certbot's default TTL for this plugin. See [#8551](https://github.com/certbot/certbot/issues/8551).

More details about these changes can be found on our GitHub repo.

## 1.10.1 - 2020-12-03

### Fixed

* Fixed a bug in `certbot.util.add_deprecated_argument` that caused the
  deprecated `--manual-public-ip-logging-ok` flag to crash Certbot in some
  scenarios.

More details about these changes can be found on our GitHub repo.

## 1.10.0 - 2020-12-01

### Added

* Added timeout to DNS query function calls for dns-rfc2136 plugin.
* Confirmation when deleting certificates
* CLI flag `--key-type` has been added to specify 'rsa' or 'ecdsa' (default 'rsa').
* CLI flag `--elliptic-curve` has been added which takes an NIST/SECG elliptic curve. Any of
  `secp256r1`, `secp384r1` and `secp521r1` are accepted values.
* The command `certbot certficates` lists the which type of the private key that was used
  for the private key.
* Support for Python 3.9 was added to Certbot and all of its components.

### Changed

* certbot-auto was deprecated on Debian based systems.
* CLI flag `--manual-public-ip-logging-ok` is now a no-op, generates a
  deprecation warning, and will be removed in a future release.

### Fixed

* Fixed a Unicode-related crash in the nginx plugin when running under Python 2.

More details about these changes can be found on our GitHub repo.

## 1.9.0 - 2020-10-06

### Added

* `--preconfigured-renewal` flag, for packager use only.
  See the [packaging guide](https://certbot.eff.org/docs/packaging.html).

### Changed

* certbot-auto was deprecated on all systems except for those based on Debian or RHEL.
* Update the packaging instructions to promote usage of `python -m pytest` to test Certbot
  instead of the deprecated `python setup.py test` setuptools approach.
* Reduced CLI logging when reloading nginx, if it is not running.
* Reduced CLI logging when handling some kinds of errors.

### Fixed

* Fixed `server_name` case-sensitivity in the nginx plugin.
* The minimum version of the `acme` library required by Certbot was corrected.
  In the previous release, Certbot said it required `acme>=1.6.0` when it
  actually required `acme>=1.8.0` to properly support removing contact
  information from an ACME account.
* Upgraded the version of httplib2 used in our snaps and Docker images to add
  support for proxy environment variables and fix the plugin for Google Cloud
  DNS.

More details about these changes can be found on our GitHub repo.

## 1.8.0 - 2020-09-08

### Added

* Added the ability to remove email and phone contact information from an account
  using `update_account --register-unsafely-without-email`

### Changed

* Support for Python 3.5 has been removed.

### Fixed

* The problem causing the Apache plugin in the Certbot snap on ARM systems to
  fail to load the Augeas library it depends on has been fixed.
* The `acme` library can now tell the ACME server to clear contact information by passing an empty
  `tuple` to the `contact` field of a `Registration` message.
* Fixed the `*** stack smashing detected ***` error in the Certbot snap on some systems.

More details about these changes can be found on our GitHub repo.

## 1.7.0 - 2020-08-04

### Added

* Third-party plugins can be used without prefix (`plugin_name` instead of `dist_name:plugin_name`):
  this concerns the plugin name, CLI flags, and keys in credential files.
  The prefixed form is still supported but is deprecated, and will be removed in a future release.
* Added `--nginx-sleep-seconds` (default `1`) for environments where nginx takes a long time to reload.

### Changed

* The Linode DNS plugin now waits 120 seconds for DNS propagation, instead of 1200,
  due to https://www.linode.com/blog/linode/linode-turns-17/
* We deprecated support for Python 3.5 in Certbot and its ACME library.
  Support for Python 3.5 will be removed in the next major release of Certbot.

### Fixed


More details about these changes can be found on our GitHub repo.

## 1.6.0 - 2020-07-07

### Added

* Certbot snaps are now available for the arm64 and armhf architectures.
* Add minimal code to run Nginx plugin on NetBSD.
* Make Certbot snap find externally snapped plugins
* Function `certbot.compat.filesystem.umask` is a drop-in replacement for `os.umask`
  implementing umask for both UNIX and Windows systems.
* Support for alternative certificate chains in the `acme` module.
* Added `--preferred-chain <issuer CN>`. If a CA offers multiple certificate chains,
  it may be  used to indicate to Certbot which chain should be preferred.
  * e.g. `--preferred-chain "DST Root CA X3"`

### Changed

* Allow session tickets to be disabled in Apache when mod_ssl is statically linked.
* Generalize UI warning message on renewal rate limits
* Certbot behaves similarly on Windows to on UNIX systems regarding umask, and
  the umask `022` is applied by default: all files/directories are not writable by anyone
  other than the user running Certbot and the system/admin users.
* Read acmev1 Let's Encrypt server URL from renewal config as acmev2 URL to prepare
  for impending acmev1 deprecation.

### Fixed

* Cloudflare API Tokens may now be restricted to individual zones.
* Don't use `StrictVersion`, but `LooseVersion` to check version requirements with setuptools,
  to fix some packaging issues with libraries respecting PEP404 for version string,
  with doesn't match `StrictVersion` requirements.
* Certbot output doesn't refer to SSL Labs due to confusing scoring behavior.
* Fix paths when calling to programs outside of the Certbot Snap, fixing the apache and nginx
  plugins on, e.g., CentOS 7.

More details about these changes can be found on our GitHub repo.

## 1.5.0 - 2020-06-02

### Added

* Require explicit confirmation of snap plugin permissions before connecting.

### Changed

* Improved error message in apache installer when mod_ssl is not available.

### Fixed

* Add support for OCSP responses which use a public key hash ResponderID, fixing
  interoperability with Sectigo CAs.
* Fix TLS-ALPN test that fails when run with newer versions of OpenSSL.

More details about these changes can be found on our GitHub repo.

## 1.4.0 - 2020-05-05

### Added

* Turn off session tickets for apache plugin by default when appropriate.
* Added serial number of certificate to the output of `certbot certificates`
* Expose two new environment variables in the authenticator and cleanup scripts used by
  the `manual` plugin: `CERTBOT_REMAINING_CHALLENGES` is equal to the number of challenges
  remaining after the current challenge, `CERTBOT_ALL_DOMAINS` is a comma-separated list
  of all domains challenged for the current certificate.
* Added TLS-ALPN-01 challenge support in the `acme` library. Support of this
  challenge in the Certbot client is planned to be added in a future release.
* Added minimal proxy support for OCSP verification.
* On Windows, hooks are now executed in a Powershell shell instead of a CMD shell,
  allowing both `*.ps1` and `*.bat` as valid scripts for Certbot.

### Changed

* Reorganized error message when a user entered an invalid email address.
* Stop asking interactively if the user would like to add a redirect.
* `mock` dependency is now conditional on Python 2 in all of our packages.
* Deprecate certbot-auto on Gentoo, macOS, and FreeBSD.
* Allow existing but empty archive and live dir to be used when creating new lineage.

### Fixed

* When using an RFC 8555 compliant endpoint, the `acme` library no longer sends the
  `resource` field in any requests or the `type` field when responding to challenges.
* Fix nginx plugin crash when non-ASCII configuration file is being read (instead,
  the user will be warned that UTF-8 must be used).
* Fix hanging OCSP queries during revocation checking - added a 10 second timeout.
* Standalone servers now have a default socket timeout of 30 seconds, fixing
  cases where an idle connection can cause the standalone plugin to hang.
* Parsing of the RFC 8555 application/pem-certificate-chain now tolerates CRLF line
  endings. This should fix interoperability with Buypass' services.

More details about these changes can be found on our GitHub repo.

## 1.3.0 - 2020-03-03

### Added

* Added certbot.ocsp Certbot's API. The certbot.ocsp module can be used to
  determine the OCSP status of certificates.
* Don't verify the existing certificate in HTTP01Response.simple_verify, for
  compatibility with the real-world ACME challenge checks.
* Added support for `$hostname` in nginx `server_name` directive

### Changed

* Certbot will now renew certificates early if they have been revoked according
  to OCSP.
* Fix acme module warnings when response Content-Type includes params (e.g. charset).
* Fixed issue where webroot plugin would incorrectly raise `Read-only file system`
  error when creating challenge directories (issue #7165).

### Fixed

* Fix Apache plugin to use less restrictive umask for making the challenge directory when a restrictive umask was set when certbot was started.

More details about these changes can be found on our GitHub repo.

## 1.2.0 - 2020-02-04

### Added

* Added support for Cloudflare's limited-scope API Tokens

### Changed

* Add directory field to error message when field is missing.
* If MD5 hasher is not available, try it in non-security mode (fix for FIPS systems) -- [#1948](https://github.com/certbot/certbot/issues/1948)
* Disable old SSL versions and ciphersuites and remove `SSLCompression off` setting to follow Mozilla recommendations in Apache.
* Remove ECDHE-RSA-AES128-SHA from NGINX ciphers list now that Windows 2008 R2 and Windows 7 are EOLed
* Support for Python 3.4 has been removed.

### Fixed

* Fix collections.abc imports for Python 3.9.

More details about these changes can be found on our GitHub repo.

## 1.1.0 - 2020-01-14

### Added

*

### Changed

* Removed the fallback introduced with 0.34.0 in `acme` to retry a POST-as-GET
  request as a GET request when the targeted ACME CA server seems to not support
  POST-as-GET requests.
* certbot-auto no longer supports architectures other than x86_64 on RHEL 6
  based systems. Existing certbot-auto installations affected by this will
  continue to work, but they will no longer receive updates. To install a
  newer version of Certbot on these systems, you should update your OS.
* Support for Python 3.4 in Certbot and its ACME library is deprecated and will be
  removed in the next release of Certbot. certbot-auto users on x86_64 systems running
  RHEL 6 or derivatives will be asked to enable Software Collections (SCL) repository
  so Python 3.6 can be installed. certbot-auto can enable the SCL repo for you on CentOS 6
  while users on other RHEL 6 based systems will be asked to do this manually.

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 1.0.0 - 2019-12-03

### Added

*

### Removed

* The `docs` extras for the `certbot-apache` and `certbot-nginx` packages
  have been removed.

### Changed

* certbot-auto has deprecated support for systems using OpenSSL 1.0.1 that are
  not running on x86-64. This primarily affects RHEL 6 based systems.
* Certbot's `config_changes` subcommand has been removed
* `certbot.plugins.common.TLSSNI01` has been removed.
* Deprecated attributes related to the TLS-SNI-01 challenge in
  `acme.challenges` and `acme.standalone`
  have been removed.
* The functions `certbot.client.view_config_changes`,
  `certbot.main.config_changes`,
  `certbot.plugins.common.Installer.view_config_changes`,
  `certbot.reverter.Reverter.view_config_changes`, and
  `certbot.util.get_systemd_os_info` have been removed
* Certbot's `register --update-registration` subcommand has been removed
* When possible, default to automatically configuring the webserver so all requests
  redirect to secure HTTPS access. This is mostly relevant when running Certbot
  in non-interactive mode. Previously, the default was to not redirect all requests.

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 0.40.1 - 2019-11-05

### Changed

* Added back support for Python 3.4 to Certbot components and certbot-auto due
  to a bug when requiring Python 2.7 or 3.5+ on RHEL 6 based systems.

More details about these changes can be found on our GitHub repo.

## 0.40.0 - 2019-11-05

### Added

*

### Changed

* We deprecated support for Python 3.4 in Certbot and its ACME library. Support
  for Python 3.4 will be removed in the next major release of Certbot.
  certbot-auto users on RHEL 6 based systems will be asked to enable Software
  Collections (SCL) repository so Python 3.6 can be installed. certbot-auto can
  enable the SCL repo for you on CentOS 6 while users on other RHEL 6 based
  systems will be asked to do this manually.
* `--server` may now be combined with `--dry-run`. Certbot will, as before, use the
  staging server instead of the live server when `--dry-run` is used.
* `--dry-run` now requests fresh authorizations every time, fixing the issue
  where it was prone to falsely reporting success.
* Updated certbot-dns-google to depend on newer versions of
  google-api-python-client and oauth2client.
* The OS detection logic again uses distro library for Linux OSes
* certbot.plugins.common.TLSSNI01 has been deprecated and will be removed in a
  future release.
* CLI flags --tls-sni-01-port and --tls-sni-01-address have been removed.
* The values tls-sni and tls-sni-01 for the --preferred-challenges flag are no
  longer accepted.
* Removed the flags: `--agree-dev-preview`, `--dialog`, and `--apache-init-script`
* acme.standalone.BaseRequestHandlerWithLogging and
  acme.standalone.simple_tls_sni_01_server have been deprecated and will be
  removed in a future release of the library.
* certbot-dns-rfc2136 now use TCP to query SOA records.

### Fixed

*

More details about these changes can be found on our GitHub repo.

## 0.39.0 - 2019-10-01

### Added

* Support for Python 3.8 was added to Certbot and all of its components.
* Support for CentOS 8 was added to certbot-auto.

### Changed

* Don't send OCSP requests for expired certificates
* Return to using platform.linux_distribution instead of distro.linux_distribution in OS fingerprinting for Python < 3.8
* Updated the Nginx plugin's TLS configuration to keep support for some versions of IE11.

### Fixed

* Fixed OS detection in the Apache plugin on RHEL 6.

More details about these changes can be found on our GitHub repo.

## 0.38.0 - 2019-09-03

### Added

* Disable session tickets for Nginx users when appropriate.

### Changed

* If Certbot fails to rollback your server configuration, the error message
  links to the Let's Encrypt forum. Change the link to the Help category now
  that the Server category has been closed.
* Replace platform.linux_distribution with distro.linux_distribution as a step
  towards Python 3.8 support in Certbot.

### Fixed

* Fixed OS detection in the Apache plugin on Scientific Linux.

More details about these changes can be found on our GitHub repo.

## 0.37.2 - 2019-08-21

* Stop disabling TLS session tickets in Nginx as it caused TLS failures on
  some systems.

More details about these changes can be found on our GitHub repo.

## 0.37.1 - 2019-08-08

### Fixed

* Stop disabling TLS session tickets in Apache as it caused TLS failures on
  some systems.

More details about these changes can be found on our GitHub repo.

## 0.37.0 - 2019-08-07

### Added

* Turn off session tickets for apache plugin by default
* acme: Authz deactivation added to `acme` module.

### Changed

* Follow updated Mozilla recommendations for Nginx ssl_protocols, ssl_ciphers,
  and ssl_prefer_server_ciphers

### Fixed

* Fix certbot-auto failures on RHEL 8.

More details about these changes can be found on our GitHub repo.

## 0.36.0 - 2019-07-11

### Added

* Turn off session tickets for nginx plugin by default
* Added missing error types from RFC8555 to acme

### Changed

* Support for Ubuntu 14.04 Trusty has been removed.
* Update the 'manage your account' help to be more generic.
* The error message when Certbot's Apache plugin is unable to modify your
  Apache configuration has been improved.
* Certbot's config_changes subcommand has been deprecated and will be
  removed in a future release.
* `certbot config_changes` no longer accepts a --num parameter.
* The functions `certbot.plugins.common.Installer.view_config_changes` and
  `certbot.reverter.Reverter.view_config_changes` have been deprecated and will
  be removed in a future release.

### Fixed

* Replace some unnecessary platform-specific line separation.

More details about these changes can be found on our GitHub repo.

## 0.35.1 - 2019-06-10

### Fixed

* Support for specifying an authoritative base domain in our dns-rfc2136 plugin
  has been removed. This feature was added in our last release but had a bug
  which caused the plugin to fail so the feature has been removed until it can
  be added properly.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* certbot-dns-rfc2136

More details about these changes can be found on our GitHub repo.

## 0.35.0 - 2019-06-05

### Added

* dns_rfc2136 plugin now supports explicitly specifying an authoritative
  base domain for cases when the automatic method does not work (e.g.
  Split horizon DNS)

### Changed

*

### Fixed

* Renewal parameter `webroot_path` is always saved, avoiding some regressions
  when `webroot` authenticator plugin is invoked with no challenge to perform.
* Certbot now accepts OCSP responses when an explicit authorized
  responder, different from the issuer, is used to sign OCSP
  responses.
* Scripts in Certbot hook directories are no longer executed when their
  filenames end in a tilde.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* certbot
* certbot-dns-rfc2136

More details about these changes can be found on our GitHub repo.

## 0.34.2 - 2019-05-07

### Fixed

* certbot-auto no longer writes a check_permissions.py script at the root
  of the filesystem.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
changes in this release were to certbot-auto.

More details about these changes can be found on our GitHub repo.

## 0.34.1 - 2019-05-06

### Fixed

* certbot-auto no longer prints a blank line when there are no permissions
  problems.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
changes in this release were to certbot-auto.

More details about these changes can be found on our GitHub repo.

## 0.34.0 - 2019-05-01

### Changed

* Apache plugin now tries to restart httpd on Fedora using systemctl if a
  configuration test error is detected. This has to be done due to the way
  Fedora now generates the self signed certificate files upon first
  restart.
* Updated Certbot and its plugins to improve the handling of file system permissions
  on Windows as a step towards adding proper Windows support to Certbot.
* Updated urllib3 to 1.24.2 in certbot-auto.
* Removed the fallback introduced with 0.32.0 in `acme` to retry a challenge response
  with a `keyAuthorization` if sending the response without this field caused a
  `malformed` error to be received from the ACME server.
* Linode DNS plugin now supports api keys created from their new panel
  at [cloud.linode.com](https://cloud.linode.com)

### Fixed

* Fixed Google DNS Challenge issues when private zones exist
* Adding a warning noting that future versions of Certbot will automatically configure the
  webserver so that all requests redirect to secure HTTPS access. You can control this
  behavior and disable this warning with the --redirect and --no-redirect flags.
* certbot-auto now prints warnings when run as root with insecure file system
  permissions. If you see these messages, you should fix the problem by
  following the instructions at
  https://community.letsencrypt.org/t/certbot-auto-deployment-best-practices/91979/,
  however, these warnings can be disabled as necessary with the flag
  --no-permissions-check.
* `acme` module uses now a POST-as-GET request to retrieve the registration
  from an ACME v2 server
* Convert the tsig algorithm specified in the certbot_dns_rfc2136 configuration file to
  all uppercase letters before validating. This makes the value in the config case
  insensitive.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* acme
* certbot
* certbot-apache
* certbot-dns-cloudflare
* certbot-dns-cloudxns
* certbot-dns-digitalocean
* certbot-dns-dnsimple
* certbot-dns-dnsmadeeasy
* certbot-dns-gehirn
* certbot-dns-google
* certbot-dns-linode
* certbot-dns-luadns
* certbot-dns-nsone
* certbot-dns-ovh
* certbot-dns-rfc2136
* certbot-dns-route53
* certbot-dns-sakuracloud
* certbot-nginx

More details about these changes can be found on our GitHub repo.

## 0.33.1 - 2019-04-04

### Fixed

* A bug causing certbot-auto to print warnings or crash on some RHEL based
  systems has been resolved.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
changes in this release were to certbot-auto.

More details about these changes can be found on our GitHub repo.

## 0.33.0 - 2019-04-03

### Added

* Fedora 29+ is now supported by certbot-auto. Since Python 2.x is on a deprecation
  path in Fedora, certbot-auto will install and use Python 3.x on Fedora 29+.
* CLI flag `--https-port` has been added for Nginx plugin exclusively, and replaces
  `--tls-sni-01-port`. It defines the HTTPS port the Nginx plugin will use while
  setting up a new SSL vhost. By default the HTTPS port is 443.

### Changed

* Support for TLS-SNI-01 has been removed from all official Certbot plugins.
* Attributes related to the TLS-SNI-01 challenge in `acme.challenges` and `acme.standalone`
  modules are deprecated and will be removed soon.
* CLI flags `--tls-sni-01-port` and `--tls-sni-01-address` are now no-op, will
  generate a deprecation warning if used, and will be removed soon.
* Options `tls-sni` and `tls-sni-01` in `--preferred-challenges` flag are now no-op,
  will generate a deprecation warning if used, and will be removed soon.
* CLI flag `--standalone-supported-challenges` has been removed.

### Fixed

* Certbot uses the Python library cryptography for OCSP when cryptography>=2.5
  is installed. We fixed a bug in Certbot causing it to interpret timestamps in
  the OCSP response as being in the local timezone rather than UTC.
* Issue causing the default CentOS 6 TLS configuration to ignore some of the
  HTTPS VirtualHosts created by Certbot. mod_ssl loading is now moved to main
  http.conf for this environment where possible.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* acme
* certbot
* certbot-apache
* certbot-nginx

More details about these changes can be found on our GitHub repo.

## 0.32.0 - 2019-03-06

### Added

* If possible, Certbot uses built-in support for OCSP from recent cryptography
  versions instead of the OpenSSL binary: as a consequence Certbot does not need
  the OpenSSL binary to be installed anymore if cryptography>=2.5 is installed.

### Changed

* Certbot and its acme module now depend on josepy>=1.1.0 to avoid printing the
  warnings described at https://github.com/certbot/josepy/issues/13.
* Apache plugin now respects CERTBOT_DOCS environment variable when adding
  command line defaults.
* The running of manual plugin hooks is now always included in Certbot's log
  output.
* Tests execution for certbot, certbot-apache and certbot-nginx packages now relies on pytest.
* An ACME CA server may return a "Retry-After" HTTP header on authorization polling, as
  specified in the ACME protocol, to indicate when the next polling should occur. Certbot now
  reads this header if set and respect its value.
* The `acme` module avoids sending the `keyAuthorization` field in the JWS
  payload when responding to a challenge as the field is not included in the
  current ACME protocol. To ease the migration path for ACME CA servers,
  Certbot and its `acme` module will first try the request without the
  `keyAuthorization` field but will temporarily retry the request with the
  field included if a `malformed` error is received. This fallback will be
  removed in version 0.34.0.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* acme
* certbot
* certbot-apache
* certbot-nginx

More details about these changes can be found on our GitHub repo.

## 0.31.0 - 2019-02-07

### Added

* Avoid reprocessing challenges that are already validated
  when a certificate is issued.
* Support for initiating (but not solving end-to-end) TLS-ALPN-01 challenges
  with the `acme` module.

### Changed

* Certbot's official Docker images are now based on Alpine Linux 3.9 rather
  than 3.7. The new version comes with OpenSSL 1.1.1.
* Lexicon-based DNS plugins are now fully compatible with Lexicon 3.x (support
  on 2.x branch is maintained).
* Apache plugin now attempts to configure all VirtualHosts matching requested
  domain name instead of only a single one when answering the HTTP-01 challenge.

### Fixed

* Fixed accessing josepy contents through acme.jose when the full acme.jose
  path is used.
* Clarify behavior for deleting certs as part of revocation.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* acme
* certbot
* certbot-apache
* certbot-dns-cloudxns
* certbot-dns-dnsimple
* certbot-dns-dnsmadeeasy
* certbot-dns-gehirn
* certbot-dns-linode
* certbot-dns-luadns
* certbot-dns-nsone
* certbot-dns-ovh
* certbot-dns-sakuracloud

More details about these changes can be found on our GitHub repo.

## 0.30.2 - 2019-01-25

### Fixed

* Update the version of setuptools pinned in certbot-auto to 40.6.3 to
  solve installation problems on newer OSes.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, this
release only affects certbot-auto.

More details about these changes can be found on our GitHub repo.

## 0.30.1 - 2019-01-24

### Fixed

* Always download the pinned version of pip in pipstrap to address breakages
* Rename old,default.conf to old-and-default.conf to address commas in filenames
  breaking recent versions of pip.
* Add VIRTUALENV_NO_DOWNLOAD=1 to all calls to virtualenv to address breakages
  from venv downloading the latest pip

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* certbot-apache

More details about these changes can be found on our GitHub repo.

## 0.30.0 - 2019-01-02

### Added

* Added the `update_account` subcommand for account management commands.

### Changed

* Copied account management functionality from the `register` subcommand
  to the `update_account` subcommand.
* Marked usage `register --update-registration` for deprecation and
  removal in a future release.

### Fixed

* Older modules in the josepy library can now be accessed through acme.jose
  like it could in previous versions of acme. This is only done to preserve
  backwards compatibility and support for doing this with new modules in josepy
  will not be added. Users of the acme library should switch to using josepy
  directly if they haven't done so already.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* acme

More details about these changes can be found on our GitHub repo.

## 0.29.1 - 2018-12-05

### Added

*

### Changed

*

### Fixed

* The default work and log directories have been changed back to
  /var/lib/letsencrypt and /var/log/letsencrypt respectively.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* certbot

More details about these changes can be found on our GitHub repo.

## 0.29.0 - 2018-12-05

### Added

* Noninteractive renewals with `certbot renew` (those not started from a
  terminal) now randomly sleep 1-480 seconds before beginning work in
  order to spread out load spikes on the server side.
* Added External Account Binding support in cli and acme library.
  Command line arguments --eab-kid and --eab-hmac-key added.

### Changed

* Private key permissioning changes: Renewal preserves existing group mode
  & gid of previous private key material. Private keys for new
  lineages (i.e. new certs, not renewed) default to 0o600.

### Fixed

* Update code and dependencies to clean up Resource and Deprecation Warnings.
* Only depend on imgconverter extension for Sphinx >= 1.6

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* acme
* certbot
* certbot-apache
* certbot-dns-cloudflare
* certbot-dns-digitalocean
* certbot-dns-google
* certbot-nginx

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/62?closed=1

## 0.28.0 - 2018-11-7

### Added

* `revoke` accepts `--cert-name`, and doesn't accept both `--cert-name` and `--cert-path`.
* Use the ACMEv2 newNonce endpoint when a new nonce is needed, and newNonce is available in the directory.

### Changed

* Removed documentation mentions of `#letsencrypt` IRC on Freenode.
* Write README to the base of (config-dir)/live directory
* `--manual` will explicitly warn users that earlier challenges should remain in place when setting up subsequent challenges.
* Warn when using deprecated acme.challenges.TLSSNI01
* Log warning about TLS-SNI deprecation in Certbot
* Stop preferring TLS-SNI in the Apache, Nginx, and standalone plugins
* OVH DNS plugin now relies on Lexicon>=2.7.14 to support HTTP proxies
* Default time the Linode plugin waits for DNS changes to propagate is now 1200 seconds.

### Fixed

* Match Nginx parser update in allowing variable names to start with `${`.
* Fix ranking of vhosts in Nginx so that all port-matching vhosts come first
* Correct OVH integration tests on machines without internet access.
* Stop caching the results of ipv6_info in http01.py
* Test fix for Route53 plugin to prevent boto3 making outgoing connections.
* The grammar used by Augeas parser in Apache plugin was updated to fix various parsing errors.
* The CloudXNS, DNSimple, DNS Made Easy, Gehirn, Linode, LuaDNS, NS1, OVH, and
  Sakura Cloud DNS plugins are now compatible with Lexicon 3.0+.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* acme
* certbot
* certbot-apache
* certbot-dns-cloudxns
* certbot-dns-dnsimple
* certbot-dns-dnsmadeeasy
* certbot-dns-gehirn
* certbot-dns-linode
* certbot-dns-luadns
* certbot-dns-nsone
* certbot-dns-ovh
* certbot-dns-route53
* certbot-dns-sakuracloud
* certbot-nginx

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/59?closed=1

## 0.27.1 - 2018-09-06

### Fixed

* Fixed parameter name in OpenSUSE overrides for default parameters in the
  Apache plugin. Certbot on OpenSUSE works again.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* certbot-apache

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/60?closed=1

## 0.27.0 - 2018-09-05

### Added

* The Apache plugin now accepts the parameter --apache-ctl which can be
  used to configure the path to the Apache control script.

### Changed

* When using `acme.client.ClientV2` (or
 `acme.client.BackwardsCompatibleClientV2` with an ACME server that supports a
 newer version of the ACME protocol), an `acme.errors.ConflictError` will be
 raised if you try to create an ACME account with a key that has already been
 used. Previously, a JSON parsing error was raised in this scenario when using
 the library with Let's Encrypt's ACMEv2 endpoint.

### Fixed

* When Apache is not installed, Certbot's Apache plugin no longer prints
  messages about being unable to find apachectl to the terminal when the plugin
  is not selected.
* If you're using the Apache plugin with the --apache-vhost-root flag set to a
  directory containing a disabled virtual host for the domain you're requesting
  a certificate for, the virtual host will now be temporarily enabled if
  necessary to pass the HTTP challenge.
* The documentation for the Certbot package can now be built using Sphinx 1.6+.
* You can now call `query_registration` without having to first call
  `new_account` on `acme.client.ClientV2` objects.
* The requirement of `setuptools>=1.0` has been removed from `certbot-dns-ovh`.
* Names in certbot-dns-sakuracloud's tests have been updated to refer to Sakura
  Cloud rather than NS1 whose plugin certbot-dns-sakuracloud was based on.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:

* acme
* certbot
* certbot-apache
* certbot-dns-ovh
* certbot-dns-sakuracloud

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/57?closed=1

## 0.26.1 - 2018-07-17

### Fixed

* Fix a bug that was triggered when users who had previously manually set `--server` to get ACMEv2 certs tried to renew ACMEv1 certs.

Despite us having broken lockstep, we are continuing to release new versions of all Certbot components during releases for the time being, however, the only package with changes other than its version number was:

* certbot

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/58?closed=1

## 0.26.0 - 2018-07-11

### Added

* A new security enhancement which we're calling AutoHSTS has been added to
  Certbot's Apache plugin. This enhancement configures your webserver to send a
  HTTP Strict Transport Security header with a low max-age value that is slowly
  increased over time. The max-age value is not increased to a large value
  until you've successfully managed to renew your certificate. This enhancement
  can be requested with the --auto-hsts flag.
* New official DNS plugins have been created for Gehirn Infrastructure Service,
  Linode, OVH, and Sakura Cloud. These plugins can be found on our Docker Hub
  page at https://hub.docker.com/u/certbot and on PyPI.
* The ability to reuse ACME accounts from Let's Encrypt's ACMEv1 endpoint on
  Let's Encrypt's ACMEv2 endpoint has been added.
* Certbot and its components now support Python 3.7.
* Certbot's install subcommand now allows you to interactively choose which
  certificate to install from the list of certificates managed by Certbot.
* Certbot now accepts the flag `--no-autorenew` which causes any obtained
  certificates to not be automatically renewed when it approaches expiration.
* Support for parsing the TLS-ALPN-01 challenge has been added back to the acme
  library.

### Changed

* Certbot's default ACME server has been changed to Let's Encrypt's ACMEv2
  endpoint. By default, this server will now be used for both new certificate
  lineages and renewals.
* The Nginx plugin is no longer marked labeled as an "Alpha" version.
* The `prepare` method of Certbot's plugins is no longer called before running
  "Updater" enhancements that are run on every invocation of `certbot renew`.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with functional changes were:

* acme
* certbot
* certbot-apache
* certbot-dns-gehirn
* certbot-dns-linode
* certbot-dns-ovh
* certbot-dns-sakuracloud
* certbot-nginx

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/55?closed=1

## 0.25.1 - 2018-06-13

### Fixed

* TLS-ALPN-01 support has been removed from our acme library. Using our current
  dependencies, we are unable to provide a correct implementation of this
  challenge so we decided to remove it from the library until we can provide
  proper support.
* Issues causing test failures when running the tests in the acme package with
  pytest<3.0 has been resolved.
* certbot-nginx now correctly depends on acme>=0.25.0.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* acme
* certbot-nginx

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/56?closed=1

## 0.25.0 - 2018-06-06

### Added

* Support for the ready status type was added to acme. Without this change,
  Certbot and acme users will begin encountering errors when using Let's
  Encrypt's ACMEv2 API starting on June 19th for the staging environment and
  July 5th for production. See
  https://community.letsencrypt.org/t/acmev2-order-ready-status/62866 for more
  information.
* Certbot now accepts the flag --reuse-key which will cause the same key to be
  used in the certificate when the lineage is renewed rather than generating a
  new key.
* You can now add multiple email addresses to your ACME account with Certbot by
  providing a comma separated list of emails to the --email flag.
* Support for Let's Encrypt's upcoming TLS-ALPN-01 challenge was added to acme.
  For more information, see
  https://community.letsencrypt.org/t/tls-alpn-validation-method/63814/1.
* acme now supports specifying the source address to bind to when sending
  outgoing connections. You still cannot specify this address using Certbot.
* If you run Certbot against Let's Encrypt's ACMEv2 staging server but don't
  already have an account registered at that server URL, Certbot will
  automatically reuse your staging account from Let's Encrypt's ACMEv1 endpoint
  if it exists.
* Interfaces were added to Certbot allowing plugins to be called at additional
  points. The `GenericUpdater` interface allows plugins to perform actions
  every time `certbot renew` is run, regardless of whether any certificates are
  due for renewal, and the `RenewDeployer` interface allows plugins to perform
  actions when a certificate is renewed. See `certbot.interfaces` for more
  information.

### Changed

* When running Certbot with --dry-run and you don't already have a staging
  account, the created account does not contain an email address even if one
  was provided to avoid expiration emails from Let's Encrypt's staging server.
* certbot-nginx does a better job of automatically detecting the location of
  Nginx's configuration files when run on BSD based systems.
* acme now requires and uses pytest when running tests with setuptools with
  `python setup.py test`.
* `certbot config_changes` no longer waits for user input before exiting.

### Fixed

* Misleading log output that caused users to think that Certbot's standalone
  plugin failed to bind to a port when performing a challenge has been
  corrected.
* An issue where certbot-nginx would fail to enable HSTS if the server block
  already had an `add_header` directive has been resolved.
* certbot-nginx now does a better job detecting the server block to base the
  configuration for TLS-SNI challenges on.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with functional changes were:

* acme
* certbot
* certbot-apache
* certbot-nginx

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/54?closed=1

## 0.24.0 - 2018-05-02

### Added

* certbot now has an enhance subcommand which allows you to configure security
  enhancements like HTTP to HTTPS redirects, OCSP stapling, and HSTS without
  reinstalling a certificate.
* certbot-dns-rfc2136 now allows the user to specify the port to use to reach
  the DNS server in its credentials file.
* acme now parses the wildcard field included in authorizations so it can be
  used by users of the library.

### Changed

* certbot-dns-route53 used to wait for each DNS update to propagate before
  sending the next one, but now it sends all updates before waiting which
  speeds up issuance for multiple domains dramatically.
* Certbot's official Docker images are now based on Alpine Linux 3.7 rather
  than 3.4 because 3.4 has reached its end-of-life.
* We've doubled the time Certbot will spend polling authorizations before
  timing out.
* The level of the message logged when Certbot is being used with
  non-standard paths warning that crontabs for renewal included in Certbot
  packages from OS package managers may not work has been reduced. This stops
  the message from being written to stderr every time `certbot renew` runs.

### Fixed

* certbot-auto now works with Python 3.6.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* acme
* certbot
* certbot-apache
* certbot-dns-digitalocean (only style improvements to tests)
* certbot-dns-rfc2136

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/52?closed=1

## 0.23.0 - 2018-04-04

### Added

* Support for OpenResty was added to the Nginx plugin.

### Changed

* The timestamps in Certbot's logfiles now use the system's local time zone
  rather than UTC.
* Certbot's DNS plugins that use Lexicon now rely on Lexicon>=2.2.1 to be able
  to create and delete multiple TXT records on a single domain.
* certbot-dns-google's test suite now works without an internet connection.

### Fixed

* Removed a small window that if during which an error occurred, Certbot
  wouldn't clean up performed challenges.
* The parameters `default` and `ipv6only` are now removed from `listen`
  directives when creating a new server block in the Nginx plugin.
* `server_name` directives enclosed in quotation marks in Nginx are now properly
  supported.
* Resolved an issue preventing the Apache plugin from starting Apache when it's
  not currently running on RHEL and Gentoo based systems.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* certbot
* certbot-apache
* certbot-dns-cloudxns
* certbot-dns-dnsimple
* certbot-dns-dnsmadeeasy
* certbot-dns-google
* certbot-dns-luadns
* certbot-dns-nsone
* certbot-dns-rfc2136
* certbot-nginx

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/50?closed=1

## 0.22.2 - 2018-03-19

### Fixed

* A type error introduced in 0.22.1 that would occur during challenge cleanup
  when a Certbot plugin raises an exception while trying to complete the
  challenge was fixed.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* certbot

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/53?closed=1

## 0.22.1 - 2018-03-19

### Changed

* The ACME server used with Certbot's --dry-run and --staging flags is now
  Let's Encrypt's ACMEv2 staging server which allows people to also test ACMEv2
  features with these flags.

### Fixed

* The HTTP Content-Type header is now set to the correct value during
  certificate revocation with new versions of the ACME protocol.
* When using Certbot with Let's Encrypt's ACMEv2 server, it would add a blank
  line to the top of chain.pem and between the certificates in fullchain.pem
  for each lineage. These blank lines have been removed.
* Resolved a bug that caused Certbot's --allow-subset-of-names flag not to
  work.
* Fixed a regression in acme.client.Client that caused the class to not work
  when it was initialized without a ClientNetwork which is done by some of the
  other projects using our ACME library.

Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
packages with changes other than their version number were:

* acme
* certbot

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/51?closed=1

## 0.22.0 - 2018-03-07

### Added

* Support for obtaining wildcard certificates and a newer version of the ACME
  protocol such as the one implemented by Let's Encrypt's upcoming ACMEv2
  endpoint was added to Certbot and its ACME library. Certbot still works with
  older ACME versions and will automatically change the version of the protocol
  used based on the version the ACME CA implements.
* The Apache and Nginx plugins are now able to automatically install a wildcard
  certificate to multiple virtual hosts that you select from your server
  configuration.
* The `certbot install` command now accepts the `--cert-name` flag for
  selecting a certificate.
* `acme.client.BackwardsCompatibleClientV2` was added to Certbot's ACME library
  which automatically handles most of the differences between new and old ACME
  versions. `acme.client.ClientV2` is also available for people who only want
  to support one version of the protocol or want to handle the differences
  between versions themselves.
* certbot-auto now supports the flag --install-only which has the script
  install Certbot and its dependencies and exit without invoking Certbot.
* Support for issuing a single certificate for a wildcard and base domain was
  added to our Google Cloud DNS plugin. To do this, we now require your API
  credentials have additional permissions, however, your credentials will
  already have these permissions unless you defined a custom role with fewer
  permissions than the standard DNS administrator role provided by Google.
  These permissions are also only needed for the case described above so it
  will continue to work for existing users. For more information about the
  permissions changes, see the documentation in the plugin.

### Changed

* We have broken lockstep between our ACME library, Certbot, and its plugins.
  This means that the different components do not need to be the same version
  to work together like they did previously. This makes packaging easier
  because not every piece of Certbot needs to be repackaged to ship a change to
  a subset of its components.
* Support for Python 2.6 and Python 3.3 has been removed from ACME, Certbot,
  Certbot's plugins, and certbot-auto. If you are using certbot-auto on a RHEL
  6 based system, it will walk you through the process of installing Certbot
  with Python 3 and refuse to upgrade to a newer version of Certbot until you
  have done so.
* Certbot's components now work with older versions of setuptools to simplify
  packaging for EPEL 7.

### Fixed

* Issues caused by Certbot's Nginx plugin adding multiple ipv6only directives
  has been resolved.
* A problem where Certbot's Apache plugin would add redundant include
  directives for the TLS configuration managed by Certbot has been fixed.
* Certbot's webroot plugin now properly deletes any directories it creates.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/48?closed=1

## 0.21.1 - 2018-01-25

### Fixed

* When creating an HTTP to HTTPS redirect in Nginx, we now ensure the Host
  header of the request is set to an expected value before redirecting users to
  the domain found in the header. The previous way Certbot configured Nginx
  redirects was a potential security issue which you can read more about at
  https://community.letsencrypt.org/t/security-issue-with-redirects-added-by-certbots-nginx-plugin/51493.
* Fixed a problem where Certbot's Apache plugin could fail HTTP-01 challenges
  if basic authentication is configured for the domain you request a
  certificate for.
* certbot-auto --no-bootstrap now properly tries to use Python 3.4 on RHEL 6
  based systems rather than Python 2.6.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/49?closed=1

## 0.21.0 - 2018-01-17

### Added

* Support for the HTTP-01 challenge type was added to our Apache and Nginx
  plugins. For those not aware, Let's Encrypt disabled the TLS-SNI-01 challenge
  type which was what was previously being used by our Apache and Nginx plugins
  last week due to a security issue. For more information about Let's Encrypt's
  change, click
  [here](https://community.letsencrypt.org/t/2018-01-11-update-regarding-acme-tls-sni-and-shared-hosting-infrastructure/50188).
  Our Apache and Nginx plugins will automatically switch to use HTTP-01 so no
  changes need to be made to your Certbot configuration, however, you should
  make sure your server is accessible on port 80 and isn't behind an external
  proxy doing things like redirecting all traffic from HTTP to HTTPS. HTTP to
  HTTPS redirects inside Apache and Nginx are fine.
* IPv6 support was added to the Nginx plugin.
* Support for automatically creating server blocks based on the default server
  block was added to the Nginx plugin.
* The flags --delete-after-revoke and --no-delete-after-revoke were added
  allowing users to control whether the revoke subcommand also deletes the
  certificates it is revoking.

### Changed

* We deprecated support for Python 2.6 and Python 3.3 in Certbot and its ACME
  library. Support for these versions of Python will be removed in the next
  major release of Certbot. If you are using certbot-auto on a RHEL 6 based
  system, it will guide you through the process of installing Python 3.
* We split our implementation of JOSE (Javascript Object Signing and
  Encryption) out of our ACME library and into a separate package named josepy.
  This package is available on [PyPI](https://pypi.python.org/pypi/josepy) and
  on [GitHub](https://github.com/certbot/josepy).
* We updated the ciphersuites used in Apache to the new [values recommended by
  Mozilla](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29).
  The major change here is adding ChaCha20 to the list of supported
  ciphersuites.

### Fixed

* An issue with our Apache plugin on Gentoo due to differences in their
  apache2ctl command have been resolved.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/47?closed=1

## 0.20.0 - 2017-12-06

### Added

* Certbot's ACME library now recognizes URL fields in challenge objects in
  preparation for Let's Encrypt's new ACME endpoint. The value is still
  accessible in our ACME library through the name "uri".

### Changed

* The Apache plugin now parses some distro specific Apache configuration files
  on non-Debian systems allowing it to get a clearer picture on the running
  configuration. Internally, these changes were structured so that external
  contributors can easily write patches to make the plugin work in new Apache
  configurations.
* Certbot better reports network failures by removing information about
  connection retries from the error output.
* An unnecessary question when using Certbot's webroot plugin interactively has
  been removed.

### Fixed

* Certbot's NGINX plugin no longer sometimes incorrectly reports that it was
  unable to deploy a HTTP->HTTPS redirect when requesting Certbot to enable a
  redirect for multiple domains.
* Problems where the Apache plugin was failing to find directives and
  duplicating existing directives on openSUSE have been resolved.
* An issue running the test shipped with Certbot and some our DNS plugins with
  older versions of mock have been resolved.
* On some systems, users reported strangely interleaved output depending on
  when stdout and stderr were flushed. This problem was resolved by having
  Certbot regularly flush these streams.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/44?closed=1

## 0.19.0 - 2017-10-04

### Added

* Certbot now has renewal hook directories where executable files can be placed
  for Certbot to run with the renew subcommand. Pre-hooks, deploy-hooks, and
  post-hooks can be specified in the renewal-hooks/pre, renewal-hooks/deploy,
  and renewal-hooks/post directories respectively in Certbot's configuration
  directory (which is /etc/letsencrypt by default). Certbot will automatically
  create these directories when it is run if they do not already exist.
* After revoking a certificate with the revoke subcommand, Certbot will offer
  to delete the lineage associated with the certificate. When Certbot is run
  with --non-interactive, it will automatically try to delete the associated
  lineage.
* When using Certbot's Google Cloud DNS plugin on Google Compute Engine, you no
  longer have to provide a credential file to Certbot if you have configured
  sufficient permissions for the instance which Certbot can automatically
  obtain using Google's metadata service.

### Changed

* When deleting certificates interactively using the delete subcommand, Certbot
  will now allow you to select multiple lineages to be deleted at once.
* Certbot's Apache plugin no longer always parses Apache's sites-available on
  Debian based systems and instead only parses virtual hosts included in your
  Apache configuration. You can provide an additional directory for Certbot to
  parse using the command line flag --apache-vhost-root.

### Fixed

* The plugins subcommand can now be run without root access.
* certbot-auto now includes a timeout when updating itself so it no longer
  hangs indefinitely when it is unable to connect to the external server.
* An issue where Certbot's Apache plugin would sometimes fail to deploy a
  certificate on Debian based systems if mod_ssl wasn't already enabled has
  been resolved.
* A bug in our Docker image where the certificates subcommand could not report
  if certificates maintained by Certbot had been revoked has been fixed.
* Certbot's RFC 2136 DNS plugin (for use with software like BIND) now properly
  performs DNS challenges when the domain being verified contains a CNAME
  record.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/43?closed=1

## 0.18.2 - 2017-09-20

### Fixed

* An issue where Certbot's ACME module would raise an AttributeError trying to
  create self-signed certificates when used with pyOpenSSL 17.3.0 has been
  resolved. For Certbot users with this version of pyOpenSSL, this caused
  Certbot to crash when performing a TLS SNI challenge or when the Nginx plugin
  tried to create an SSL server block.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/46?closed=1

## 0.18.1 - 2017-09-08

### Fixed

* If certbot-auto was running as an unprivileged user and it upgraded from
  0.17.0 to 0.18.0, it would crash with a permissions error and would need to
  be run again to successfully complete the upgrade. This has been fixed and
  certbot-auto should upgrade cleanly to 0.18.1.
* Certbot usually uses "certbot-auto" or "letsencrypt-auto" in error messages
  and the User-Agent string instead of "certbot" when you are using one of
  these wrapper scripts. Proper detection of this was broken with Certbot's new
  installation path in /opt in 0.18.0 but this problem has been resolved.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/45?closed=1

## 0.18.0 - 2017-09-06

### Added

* The Nginx plugin now configures Nginx to use 2048-bit Diffie-Hellman
  parameters. Java 6 clients do not support Diffie-Hellman parameters larger
  than 1024 bits, so if you need to support these clients you will need to
  manually modify your Nginx configuration after using the Nginx installer.

### Changed

* certbot-auto now installs Certbot in directories under `/opt/eff.org`. If you
  had an existing installation from certbot-auto, a symlink is created to the
  new directory. You can configure certbot-auto to use a different path by
  setting the environment variable VENV_PATH.
* The Nginx plugin can now be selected in Certbot's interactive output.
* Output verbosity of renewal failures when running with `--quiet` has been
  reduced.
* The default revocation reason shown in Certbot help output now is a human
  readable string instead of a numerical code.
* Plugin selection is now included in normal terminal output.

### Fixed

* A newer version of ConfigArgParse is now installed when using certbot-auto
  causing values set to false in a Certbot INI configuration file to be handled
  intuitively. Setting a boolean command line flag to false is equivalent to
  not including it in the configuration file at all.
* New naming conventions preventing certbot-auto from installing OS
  dependencies on Fedora 26 have been resolved.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/42?closed=1

## 0.17.0 - 2017-08-02

### Added

* Support in our nginx plugin for modifying SSL server blocks that do
  not contain certificate or key directives.
* A `--max-log-backups` flag to allow users to configure or even completely
  disable Certbot's built in log rotation.
* A `--user-agent-comment` flag to allow people who build tools around Certbot
  to differentiate their user agent string by adding a comment to its default
  value.

### Changed

* Due to some awesome work by
  [cryptography project](https://github.com/pyca/cryptography), compilation can
  now be avoided on most systems when using certbot-auto. This eliminates many
  problems people have had in the past such as running out of memory, having
  invalid headers/libraries, and changes to the OS packages on their system
  after compilation breaking Certbot.
* The `--renew-hook` flag has been hidden in favor of `--deploy-hook`. This new
  flag works exactly the same way except it is always run when a certificate is
  issued rather than just when it is renewed.
* We have started printing deprecation warnings in certbot-auto for
  experimentally supported systems with OS packages available.
* A certificate lineage's name is included in error messages during renewal.

### Fixed

* Encoding errors that could occur when parsing error messages from the ACME
  server containing Unicode have been resolved.
* certbot-auto no longer prints misleading messages about there being a newer
  pip version available when installation fails.
* Certbot's ACME library now properly extracts domains from critical SAN
  extensions.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.17.0+is%3Aclosed

## 0.16.0 - 2017-07-05

### Added

* A plugin for performing DNS challenges using dynamic DNS updates as defined
  in RFC 2316. This plugin is packaged separately from Certbot and is available
  at https://pypi.python.org/pypi/certbot-dns-rfc2136. It supports Python 2.6,
  2.7, and 3.3+. At this time, there isn't a good way to install this plugin
  when using certbot-auto, but this should change in the near future.
* Plugins for performing DNS challenges for the providers
  [DNS Made Easy](https://pypi.python.org/pypi/certbot-dns-dnsmadeeasy) and
  [LuaDNS](https://pypi.python.org/pypi/certbot-dns-luadns). These plugins are
  packaged separately from Certbot and support Python 2.7 and 3.3+. Currently,
  there isn't a good way to install these plugins when using certbot-auto,
  but that should change soon.
* Support for performing TLS-SNI-01 challenges when using the manual plugin.
* Automatic detection of Arch Linux in the Apache plugin providing better
  default settings for the plugin.

### Changed

* The text of the interactive question about whether a redirect from HTTP to
  HTTPS should be added by Certbot has been rewritten to better explain the
  choices to the user.
* Simplified HTTP challenge instructions in the manual plugin.

### Fixed

* Problems performing a dry run when using the Nginx plugin have been fixed.
* Resolved an issue where certbot-dns-digitalocean's test suite would sometimes
  fail when ran using Python 3.
* On some systems, previous versions of certbot-auto would error out with a
  message about a missing hash for setuptools. This has been fixed.
* A bug where Certbot would sometimes not print a space at the end of an
  interactive prompt has been resolved.
* Nonfatal tracebacks are no longer shown in rare cases where Certbot
  encounters an exception trying to close its TCP connection with the ACME
  server.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.16.0+is%3Aclosed

## 0.15.0 - 2017-06-08

### Added

* Plugins for performing DNS challenges for popular providers. Like the Apache
  and Nginx plugins, these plugins are packaged separately and not included in
  Certbot by default. So far, we have plugins for
  [Amazon Route 53](https://pypi.python.org/pypi/certbot-dns-route53),
  [Cloudflare](https://pypi.python.org/pypi/certbot-dns-cloudflare),
  [DigitalOcean](https://pypi.python.org/pypi/certbot-dns-digitalocean), and
  [Google Cloud](https://pypi.python.org/pypi/certbot-dns-google) which all
  work on Python 2.6, 2.7, and 3.3+. Additionally, we have plugins for
  [CloudXNS](https://pypi.python.org/pypi/certbot-dns-cloudxns),
  [DNSimple](https://pypi.python.org/pypi/certbot-dns-dnsimple),
  [NS1](https://pypi.python.org/pypi/certbot-dns-nsone) which work on Python
  2.7 and 3.3+ (and not 2.6). Currently, there isn't a good way to install
  these plugins when using `certbot-auto`, but that should change soon.
* IPv6 support in the standalone plugin. When performing a challenge, the
  standalone plugin automatically handles listening for IPv4/IPv6 traffic based
  on the configuration of your system.
* A mechanism for keeping your Apache and Nginx SSL/TLS configuration up to
  date. When the Apache or Nginx plugins are used, they place SSL/TLS
  configuration options in the root of Certbot's config directory
  (`/etc/letsencrypt` by default). Now when a new version of these plugins run
  on your system, they will automatically update the file to the newest
  version if it is unmodified. If you manually modified the file, Certbot will
  display a warning giving you a path to the updated file which you can use as
  a reference to manually update your modified copy.
* `--http-01-address` and `--tls-sni-01-address` flags for controlling the
  address Certbot listens on when using the standalone plugin.
* The command `certbot certificates` that lists certificates managed by Certbot
  now performs additional validity checks to notify you if your files have
  become corrupted.

### Changed

* Messages custom hooks print to `stdout` are now displayed by Certbot when not
  running in `--quiet` mode.
* `jwk` and `alg` fields in JWS objects have been moved into the protected
  header causing Certbot to more closely follow the latest version of the ACME
  spec.

### Fixed

* Permissions on renewal configuration files are now properly preserved when
  they are updated.
* A bug causing Certbot to display strange defaults in its help output when
  using Python <= 2.7.4 has been fixed.
* Certbot now properly handles mixed case domain names found in custom CSRs.
* A number of poorly worded prompts and error messages.

### Removed

* Support for OpenSSL 1.0.0 in `certbot-auto` has been removed as we now pin a
  newer version of `cryptography` which dropped support for this version.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.15.0+is%3Aclosed

## 0.14.2 - 2017-05-25

### Fixed

* Certbot 0.14.0 included a bug where Certbot would create a temporary log file
(usually in /tmp) if the program exited during argument parsing. If a user
provided -h/--help/help, --version, or an invalid command line argument,
Certbot would create this temporary log file. This was especially bothersome to
certbot-auto users as certbot-auto runs `certbot --version` internally to see
if the script needs to upgrade causing it to create at least one of these files
on every run. This problem has been resolved.

More details about this change can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.14.2+is%3Aclosed

## 0.14.1 - 2017-05-16

### Fixed

* Certbot now works with configargparse 0.12.0.
* Issues with the Apache plugin and Augeas 1.7+ have been resolved.
* A problem where the Nginx plugin would fail to install certificates on
systems that had the plugin's SSL/TLS options file from 7+ months ago has been
fixed.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.14.1+is%3Aclosed

## 0.14.0 - 2017-05-04

### Added

* Python 3.3+ support for all Certbot packages. `certbot-auto` still currently
only supports Python 2, but the `acme`, `certbot`, `certbot-apache`, and
`certbot-nginx` packages on PyPI now fully support Python 2.6, 2.7, and 3.3+.
* Certbot's Apache plugin now handles multiple virtual hosts per file.
* Lockfiles to prevent multiple versions of Certbot running simultaneously.

### Changed

* When converting an HTTP virtual host to HTTPS in Apache, Certbot only copies
the virtual host rather than the entire contents of the file it's contained
in.
* The Nginx plugin now includes SSL/TLS directives in a separate file located
in Certbot's configuration directory rather than copying the contents of the
file into every modified `server` block.

### Fixed

* Ensure logging is configured before parts of Certbot attempt to log any
messages.
* Support for the `--quiet` flag in `certbot-auto`.
* Reverted a change made in a previous release to make the `acme` and `certbot`
packages always depend on `argparse`. This dependency is conditional again on
the user's Python version.
* Small bugs in the Nginx plugin such as properly handling empty `server`
blocks and setting `server_names_hash_bucket_size` during challenges.

As always, a more complete list of changes can be found on GitHub:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.14.0+is%3Aclosed

## 0.13.0 - 2017-04-06

### Added

* `--debug-challenges` now pauses Certbot after setting up challenges for debugging.
* The Nginx parser can now handle all valid directives in configuration files.
* Nginx ciphersuites have changed to Mozilla Intermediate.
* `certbot-auto --no-bootstrap` provides the option to not install OS dependencies.

### Fixed

* `--register-unsafely-without-email` now respects `--quiet`.
* Hyphenated renewal parameters are now saved in renewal config files.
* `--dry-run` no longer persists keys and csrs.
* Certbot no longer hangs when trying to start Nginx in Arch Linux.
* Apache rewrite rules no longer double-encode characters.

A full list of changes is available on GitHub:
https://github.com/certbot/certbot/issues?q=is%3Aissue%20milestone%3A0.13.0%20is%3Aclosed%20

## 0.12.0 - 2017-03-02

### Added

* Certbot now allows non-camelcase Apache VirtualHost names.
* Certbot now allows more log messages to be silenced.

### Fixed

* Fixed a regression around using `--cert-name` when getting new certificates

More information about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue%20milestone%3A0.12.0

## 0.11.1 - 2017-02-01

### Fixed

* Resolved a problem where Certbot would crash while parsing command line
arguments in some cases.
* Fixed a typo.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/pulls?q=is%3Apr%20milestone%3A0.11.1%20is%3Aclosed

## 0.11.0 - 2017-02-01

### Added

* When using the standalone plugin while running Certbot interactively
and a required port is bound by another process, Certbot will give you
the option to retry to grab the port rather than immediately exiting.
* You are now able to deactivate your account with the Let's Encrypt
server using the `unregister` subcommand.
* When revoking a certificate using the `revoke` subcommand, you now
have the option to provide the reason the certificate is being revoked
to Let's Encrypt with `--reason`.

### Changed

* Providing `--quiet` to `certbot-auto` now silences package manager output.

### Removed

* Removed the optional `dnspython` dependency in our `acme` package.
Now the library does not support client side verification of the DNS
challenge.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.11.0+is%3Aclosed

## 0.10.2 - 2017-01-25

### Added

* If Certbot receives a request with a `badNonce` error, it now
automatically retries the request. Since nonces from Let's Encrypt expire,
this helps people performing the DNS challenge with the `manual` plugin
who may have to wait an extended period of time for their DNS changes to
propagate.

### Fixed

* Certbot now saves the `--preferred-challenges` values for renewal. Previously
these values were discarded causing a different challenge type to be used when
renewing certs in some cases.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.2+is%3Aclosed

## 0.10.1 - 2017-01-13

### Fixed

* Resolve problems where when asking Certbot to update a certificate at
an existing path to include different domain names, the old names would
continue to be used.
* Fix issues successfully running our unit test suite on some systems.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.1+is%3Aclosed

## 0.10.0 - 2017-01-11

## Added

* Added the ability to customize and automatically complete DNS and HTTP
domain validation challenges with the manual plugin. The flags
`--manual-auth-hook` and `--manual-cleanup-hook` can now be provided
when using the manual plugin to execute commands provided by the user to
perform and clean up challenges provided by the CA. This is best used in
complicated setups where the DNS challenge must be used or Certbot's
existing plugins cannot be used to perform HTTP challenges. For more
information on how this works, see `certbot --help manual`.
* Added a `--cert-name` flag for specifying the name to use for the
certificate in Certbot's configuration directory. Using this flag in
combination with `-d/--domains`, a user can easily request a new
certificate with different domains and save it with the name provided by
`--cert-name`. Additionally, `--cert-name` can be used to select a
certificate with the `certonly` and `run` subcommands so a full list of
domains in the certificate does not have to be provided.
* Added subcommand `certificates` for listing the certificates managed by
Certbot and their properties.
* Added the `delete` subcommand for removing certificates managed by Certbot
from the configuration directory.
* Certbot now supports requesting internationalized domain names (IDNs).
* Hooks provided to Certbot are now saved to be reused during renewal.
If you run Certbot with `--pre-hook`, `--renew-hook`, or `--post-hook`
flags when obtaining a certificate, the provided commands will
automatically be saved and executed again when renewing the certificate.
A pre-hook and/or post-hook can also be given to the `certbot renew`
command either on the command line or in a [configuration
file](https://certbot.eff.org/docs/using.html#configuration-file) to run
an additional command before/after any certificate is renewed. Hooks
will only be run if a certificate is renewed.
* Support Busybox in certbot-auto.

### Changed

* Recategorized `-h/--help` output to improve documentation and
discoverability.

### Removed

* Removed the ncurses interface. This change solves problems people
were having on many systems, reduces the number of Certbot
dependencies, and simplifies our code. Certbot's only interface now is
the text interface which was available by providing `-t/--text` to
earlier versions of Certbot.

### Fixed

* Many small bug fixes.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.10.0is%3Aclosed

## 0.9.3 - 2016-10-13

### Added

* The Apache plugin uses information about your OS to help determine the
layout of your Apache configuration directory. We added a patch to
ensure this code behaves the same way when testing on different systems
as the tests were failing in some cases.

### Changed

* Certbot adopted more conservative behavior about reporting a needed port as
unavailable when using the standalone plugin.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/27?closed=1

## 0.9.2 - 2016-10-12

### Added

* Certbot stopped requiring that all possibly required ports are available when
using the standalone plugin. It now only verifies that the ports are available
when they are necessary.

### Fixed

* Certbot now verifies that our optional dependencies version matches what is
required by Certbot.
* Certnot now properly copies the `ssl on;` directives as necessary when
performing domain validation in the Nginx plugin.
* Fixed problem where symlinks were becoming files when they were
packaged, causing errors during testing and OS packaging.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/26?closed=1

## 0.9.1 - 2016-10-06

### Fixed

* Fixed a bug that was introduced in version 0.9.0 where the command
line flag -q/--quiet wasn't respected in some cases.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/milestone/25?closed=1

## 0.9.0 - 2016-10-05

### Added

* Added an alpha version of the Nginx plugin. This plugin fully automates the
process of obtaining and installing certificates with Nginx.
Additionally, it is able to automatically configure security
enhancements such as an HTTP to HTTPS redirect and OCSP stapling. To use
this plugin, you must have the `certbot-nginx` package installed (which
is installed automatically when using `certbot-auto`) and provide
`--nginx` on the command line. This plugin is still in its early stages
so we recommend you use it with some caution and make sure you have a
backup of your Nginx configuration.
* Added support for the `DNS` challenge in the `acme` library and `DNS` in
Certbot's `manual` plugin. This allows you to create DNS records to
prove to Let's Encrypt you control the requested domain name. To use
this feature, include `--manual --preferred-challenges dns` on the
command line.
* Certbot now helps with enabling Extra Packages for Enterprise Linux (EPEL) on
CentOS 6 when using `certbot-auto`. To use `certbot-auto` on CentOS 6,
the EPEL repository has to be enabled. `certbot-auto` will now prompt
users asking them if they would like the script to enable this for them
automatically. This is done without prompting users when using
`letsencrypt-auto` or if `-n/--non-interactive/--noninteractive` is
included on the command line.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.9.0+is%3Aclosed

## 0.8.1 - 2016-06-14

### Added

* Certbot now preserves a certificate's common name when using `renew`.
* Certbot now saves webroot values for renewal when they are entered interactively.
* Certbot now gracefully reports that the Apache plugin isn't usable when Augeas is not installed.
* Added experimental support for Mageia has been added to `certbot-auto`.

### Fixed

* Fixed problems with an invalid user-agent string on OS X.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.8.1+

## 0.8.0 - 2016-06-02

### Added

* Added the `register` subcommand which can be used to register an account
with the Let's Encrypt CA.
* You can now run `certbot register --update-registration` to
change the e-mail address associated with your registration.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue+milestone%3A0.8.0+

## 0.7.0 - 2016-05-27

### Added

* Added `--must-staple` to request certificates from Let's Encrypt
with the OCSP must staple extension.
* Certbot now automatically configures OSCP stapling for Apache.
* Certbot now allows requesting certificates for domains found in the common name
of a custom CSR.

### Fixed

* Fixed a number of miscellaneous bugs

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=milestone%3A0.7.0+is%3Aissue

## 0.6.0 - 2016-05-12

### Added

* Versioned the datetime dependency in setup.py.

### Changed

* Renamed the client from `letsencrypt` to `certbot`.

### Fixed

* Fixed a small json deserialization error.
* Certbot now preserves domain order in generated CSRs.
* Fixed some minor bugs.

More details about these changes can be found on our GitHub repo:
https://github.com/certbot/certbot/issues?q=is%3Aissue%20milestone%3A0.6.0%20is%3Aclosed%20

## 0.5.0 - 2016-04-05

### Added

* Added the ability to use the webroot plugin interactively.
* Added the flags --pre-hook, --post-hook, and --renew-hook which can be used with
the renew subcommand to register shell commands to run in response to
renewal events. Pre-hook commands will be run before any certs are
renewed, post-hook commands will be run after any certs are renewed,
and renew-hook commands will be run after each cert is renewed. If no
certs are due for renewal, no command is run.
* Added a -q/--quiet flag which silences all output except errors.
* Added an --allow-subset-of-domains flag which can be used with the renew
command to prevent renewal failures for a subset of the requested
domains from causing the client to exit.

### Changed

* Certbot now uses renewal configuration files. In /etc/letsencrypt/renewal
by default, these files can be used to control what parameters are
used when renewing a specific certificate.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=milestone%3A0.5.0+is%3Aissue

## 0.4.2 - 2016-03-03

### Fixed

* Resolved problems encountered when compiling letsencrypt
against the new OpenSSL release.
* Fixed problems encountered when using `letsencrypt renew` with configuration files
from the private beta.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.4.2

## 0.4.1 - 2016-02-29

### Fixed

* Fixed Apache parsing errors encountered with some configurations.
* Fixed Werkzeug dependency problems encountered on some Red Hat systems.
* Fixed bootstrapping failures when using letsencrypt-auto with --no-self-upgrade.
* Fixed problems with parsing renewal config files from private beta.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is:issue+milestone:0.4.1

## 0.4.0 - 2016-02-10

### Added

* Added the verb/subcommand `renew` which can be used to renew your existing
certificates as they approach expiration. Running `letsencrypt renew`
will examine all existing certificate lineages and determine if any are
less than 30 days from expiration. If so, the client will use the
settings provided when you previously obtained the certificate to renew
it. The subcommand finishes by printing a summary of which renewals were
successful, failed, or not yet due.
* Added a `--dry-run` flag to help with testing configuration
without affecting production rate limits. Currently supported by the
`renew` and `certonly` subcommands, providing `--dry-run` on the command
line will obtain certificates from the staging server without saving the
resulting certificates to disk.
* Added major improvements to letsencrypt-auto. This script
has been rewritten to include full support for Python 2.6, the ability
for letsencrypt-auto to update itself, and improvements to the
stability, security, and performance of the script.
* Added support for Apache 2.2 to the Apache plugin.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.4.0

## 0.3.0 - 2016-01-27

### Added

* Added a non-interactive mode which can be enabled by including `-n` or
`--non-interactive` on the command line. This can be used to guarantee
the client will not prompt when run automatically using cron/systemd.
* Added preparation for the new letsencrypt-auto script. Over the past
couple months, we've been working on increasing the reliability and
security of letsencrypt-auto. A number of changes landed in this
release to prepare for the new version of this script.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.3.0

## 0.2.0 - 2016-01-14

### Added

* Added Apache plugin support for non-Debian based systems. Support has been
added for modern Red Hat based systems such as Fedora 23, Red Hat 7,
and CentOS 7 running Apache 2.4. In theory, this plugin should be
able to be configured to run on any Unix-like OS running Apache 2.4.
* Relaxed PyOpenSSL version requirements. This adds support for systems
with PyOpenSSL versions 0.13 or 0.14.
* Improved error messages from the client.

### Fixed

* Resolved issues with the Apache plugin enabling an HTTP to HTTPS
redirect on some systems.

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=is%3Aissue+milestone%3A0.2.0

## 0.1.1 - 2015-12-15

### Added

* Added a check that avoids attempting to issue for unqualified domain names like
"localhost".

### Fixed

* Fixed a confusing UI path that caused some users to repeatedly renew
their certs while experimenting with the client, in some cases hitting
issuance rate limits.
* Fixed numerous Apache configuration parser problems
* Fixed --webroot permission handling for non-root users

More details about these changes can be found on our GitHub repo:
https://github.com/letsencrypt/letsencrypt/issues?q=milestone%3A0.1.1
