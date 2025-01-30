==========
User Guide
==========

.. contents:: Table of Contents
   :local:

Certbot Commands
================

Certbot uses a number of different commands (also referred
to as "subcommands") to request specific actions such as
obtaining, renewing, or revoking certificates. The most important
and commonly-used commands will be discussed throughout this
document; an exhaustive list also appears near the end of the document.

The ``certbot`` script on your web server might be named ``letsencrypt`` if your system uses an older package. Throughout the docs, whenever you see ``certbot``, swap in the correct name as needed.

.. _plugins:

Getting certificates (and choosing plugins)
===========================================

Certbot helps you achieve two tasks:

1. Obtaining a certificate: automatically performing the required authentication steps to prove that you control the domain(s),
   saving the certificate to ``/etc/letsencrypt/live/`` and renewing it on a regular schedule.
2. Optionally, installing that certificate to supported web servers (like Apache or nginx) and other kinds of servers. This is
   done by automatically modifying the configuration of your server in order to use the certificate.

To obtain a certificate and also install it, use the ``certbot run`` command (or ``certbot``, which is the same).

To just obtain the certificate without installing it anywhere, the ``certbot certonly`` ("certificate only") command can be used.

Some example ways to use Certbot::

    # Obtain and install a certificate:
    certbot

    # Obtain a certificate but don't install it:
    certbot certonly

    # You may specify multiple domains with -d and obtain and
    # install different certificates by running Certbot multiple times:
    certbot certonly -d example.com -d www.example.com
    certbot certonly -d app.example.com -d api.example.com

To perform these tasks, Certbot will ask you to choose from a selection of authenticator and installer plugins. The appropriate
choice of plugins will depend on what kind of server software you are running and plan to use your certificates with.

**Authenticators** are plugins which automatically perform the required steps to prove that you control the domain names you're trying
to request a certificate for. An authenticator is always required to obtain a certificate.

**Installers** are plugins which can automatically modify your web server's configuration to serve your website over HTTPS, using the
certificates obtained by Certbot. An installer is only required if you want Certbot to install the certificate to your web server.

Some plugins are both authenticators and installers and it is possible to specify a distinct combination_ of authenticator and plugin.

=========== ==== ==== =============================================================== =============================
Plugin      Auth Inst Notes                                                           Challenge types (and port)
=========== ==== ==== =============================================================== =============================
apache_     Y    Y    | Automates obtaining and installing a certificate with Apache. http-01_ (80)
nginx_      Y    Y    | Automates obtaining and installing a certificate with Nginx.  http-01_ (80)
webroot_    Y    N    | Obtains a certificate by writing to the webroot directory of  http-01_ (80)
                      | an already running webserver.
standalone_ Y    N    | Uses a "standalone" webserver to obtain a certificate.        http-01_ (80)
                      | Requires port 80 to be available. This is useful on
                      | systems with no webserver, or when direct integration with
                      | the local webserver is not supported or not desired.
|dns_plugs| Y    N    | This category of plugins automates obtaining a certificate by dns-01_ (53)
                      | modifying DNS records to prove you have control over a
                      | domain. Doing domain validation in this way is
                      | the only way to obtain wildcard certificates from Let's
                      | Encrypt.
manual_     Y    N    | Obtain a certificate by manually following instructions to    http-01_ (80) or
                      | perform domain validation yourself. Certificates created this dns-01_ (53)
                      | way do not support autorenewal.
                      | Autorenewal may be enabled by providing an authentication
                      | hook script to automate the domain validation steps.
=========== ==== ==== =============================================================== =============================

.. |dns_plugs| replace:: :ref:`DNS plugins <dns_plugins>`

Under the hood, plugins use one of several ACME protocol challenges_ to
prove you control a domain. The options are http-01_ (which uses port 80)
and dns-01_ (requiring configuration of a DNS server on
port 53, though that's often not the same machine as your webserver). A few
plugins support more than one challenge type, in which case you can choose one
with ``--preferred-challenges``.

There are also many third-party-plugins_ available. Below we describe in more detail
the circumstances in which each plugin can be used, and how to use it.

.. _challenges: https://datatracker.ietf.org/doc/html/rfc8555#section-8
.. _http-01: https://datatracker.ietf.org/doc/html/rfc8555#section-8.3
.. _dns-01: https://datatracker.ietf.org/doc/html/rfc8555#section-8.4

Apache
------

The Apache plugin currently `supports
<https://github.com/certbot/certbot/blob/main/certbot-apache/certbot_apache/_internal/entrypoint.py>`_
<https://github.com/certbot/certbot/blob/main/certbot-apache/certbot_apache/_internal/entrypoint.py>`_
modern OSes based on Debian, Fedora, SUSE, Gentoo, CentOS and Darwin.
This automates both obtaining *and* installing certificates on an Apache
webserver. To specify this plugin on the command line, simply include
``--apache``.

Webroot
-------

If you're running a local webserver for which you have the ability
to modify the content being served, and you'd prefer not to stop the
webserver during the certificate issuance process, you can use the webroot
plugin to obtain a certificate by including ``certonly`` and ``--webroot`` on
the command line. In addition, you'll need to specify ``--webroot-path``
or ``-w`` with the top-level directory ("web root") containing the files
served by your webserver. For example, ``--webroot-path /var/www/html``
or ``--webroot-path /usr/share/nginx/html`` are two common webroot paths.

If you're getting a certificate for many domains at once, the plugin
needs to know where each domain's files are served from, which could
potentially be a separate directory for each domain. When requesting a
certificate for multiple domains, each domain will use the most recently
specified ``--webroot-path``. So, for instance,

::

    certbot certonly --webroot -w /var/www/example -d www.example.com -d example.com -w /var/www/other -d other.example.net -d another.other.example.net

would obtain a single certificate for all of those names, using the
``/var/www/example`` webroot directory for the first two, and
``/var/www/other`` for the second two.

The webroot plugin works by creating a temporary file for each of your requested
domains in ``${webroot-path}/.well-known/acme-challenge``. Then the Let's Encrypt
validation server makes HTTP requests to validate that the DNS for each
requested domain resolves to the server running certbot. An example request
made to your web server would look like:

::

    66.133.109.36 - - [05/Jan/2016:20:11:24 -0500] "GET /.well-known/acme-challenge/HGr8U1IeTW4kY_Z6UIyaakzOkyQgPr_7ArlLgtZE8SX HTTP/1.1" 200 87 "-" "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)"

Note that to use the webroot plugin, your server must be configured to serve
files from hidden directories. If ``/.well-known`` is treated specially by
your webserver configuration, you might need to modify the configuration
to ensure that files inside ``/.well-known/acme-challenge`` are served by
the webserver.

Under Windows, Certbot will generate a ``web.config`` file, if one does not already exist,
in ``/.well-known/acme-challenge`` in order to let IIS serve the challenge files even if they
do not have an extension.

Nginx
-----

The Nginx plugin should work for most configurations. We recommend backing up
Nginx configurations before using it (though you can also revert changes to
configurations with ``certbot --nginx rollback``). You can use it by providing
the ``--nginx`` flag on the commandline.

::

   certbot --nginx

.. _standalone:

Standalone
----------

Use standalone mode to obtain a certificate if you don't want to use (or don't currently have)
existing server software. The standalone plugin does not rely on any other server
software running on the machine where you obtain the certificate.

To obtain a certificate using a "standalone" webserver, you can use the
standalone plugin by including ``certonly`` and ``--standalone``
on the command line. This plugin needs to bind to port 80 in
order to perform domain validation, so you may need to stop your
existing webserver.

It must still be possible for your machine to accept inbound connections from
the Internet on the specified port using each requested domain name.

By default, Certbot first attempts to bind to the port for all interfaces using
IPv6 and then bind to that port using IPv4; Certbot continues so long as at
least one bind succeeds. On most Linux systems, IPv4 traffic will be routed to
the bound IPv6 port and the failure during the second bind is expected.

Use ``--<challenge-type>-address`` to explicitly tell Certbot which interface
(and protocol) to bind.

.. _dns_plugins:

DNS Plugins
-----------

If you'd like to obtain a wildcard certificate from Let's Encrypt or run
``certbot`` on a machine other than your target webserver, you can use one of
Certbot's DNS plugins.

These plugins are not included in a default Certbot installation and must be
installed separately. They are available in many OS package managers, as Docker
images, and as snaps. Visit https://certbot.eff.org to learn the best way to
use the DNS plugins on your system.

Once installed, you can find documentation on how to use each plugin at:

* `certbot-dns-cloudflare <https://certbot-dns-cloudflare.readthedocs.io>`_
* `certbot-dns-digitalocean <https://certbot-dns-digitalocean.readthedocs.io>`_
* `certbot-dns-dnsimple <https://certbot-dns-dnsimple.readthedocs.io>`_
* `certbot-dns-dnsmadeeasy <https://certbot-dns-dnsmadeeasy.readthedocs.io>`_
* `certbot-dns-gehirn <https://certbot-dns-gehirn.readthedocs.io>`_
* `certbot-dns-google <https://certbot-dns-google.readthedocs.io>`_
* `certbot-dns-linode <https://certbot-dns-linode.readthedocs.io>`_
* `certbot-dns-luadns <https://certbot-dns-luadns.readthedocs.io>`_
* `certbot-dns-nsone <https://certbot-dns-nsone.readthedocs.io>`_
* `certbot-dns-ovh <https://certbot-dns-ovh.readthedocs.io>`_
* `certbot-dns-rfc2136 <https://certbot-dns-rfc2136.readthedocs.io>`_
* `certbot-dns-route53 <https://certbot-dns-route53.readthedocs.io>`_
* `certbot-dns-sakuracloud <https://certbot-dns-sakuracloud.readthedocs.io>`_

Manual
------

If you'd like to obtain a certificate running ``certbot`` on a machine
other than your target webserver or perform the steps for domain
validation yourself, you can use the manual plugin. While hidden from
the UI, you can use the plugin to obtain a certificate by specifying
``certonly`` and ``--manual`` on the command line. This requires you
to copy and paste commands into another terminal session, which may
be on a different computer.

The manual plugin can use either the ``http`` or the ``dns`` challenge. You can use the ``--preferred-challenges`` option
to choose the challenge of your preference.

The ``http`` challenge will ask you to place a file with a specific name and
specific content in the ``/.well-known/acme-challenge/`` directory directly
in the top-level directory (“web root”) containing the files served by your
webserver. In essence it's the same as the webroot_ plugin, but not automated.

When using the ``dns`` challenge, ``certbot`` will ask you to place a TXT DNS
record with specific contents under the domain name consisting of the hostname
for which you want a certificate issued, prepended by ``_acme-challenge``.

For example, for the domain ``example.com``, a zone file entry would look like:

::

        _acme-challenge.example.com. 300 IN TXT "gfj9Xq...Rg85nM"

.. _manual-renewal:

**Renewal with the manual plugin**

Certificates created using ``--manual`` **do not** support automatic renewal unless
combined with an `authentication hook script <#hooks>`_  via ``--manual-auth-hook``
to automatically set up the required HTTP and/or TXT challenges.

If you can use one of the other plugins_ which support autorenewal to create
your certificate, doing so is highly recommended.

To manually renew a certificate using ``--manual`` without hooks, repeat the same
``certbot --manual`` command you used to create the certificate originally. As this
will require you to copy and paste new HTTP files or DNS TXT records, the command
cannot be automated with a cron job.

.. _combination:

Combining plugins
-----------------

Sometimes you may want to specify a combination of distinct authenticator and
installer plugins. To do so, specify the authenticator plugin with
``--authenticator`` or ``-a`` and the installer plugin with ``--installer`` or
``-i``.

For instance, you could create a certificate using the webroot_ plugin
for authentication and the apache_ plugin for installation.

::

    certbot run -a webroot -i apache -w /var/www/html -d example.com

Or you could create a certificate using the manual_ plugin for authentication
and the nginx_ plugin for installation. (Note that this certificate cannot
be renewed automatically.)

::

    certbot run -a manual -i nginx -d example.com

.. _third-party-plugins:

Third-party plugins
-------------------

There are also a number of third-party plugins for the client, provided by
other developers. Many are beta/experimental, but some are already in
widespread use:

================== ==== ==== ===============================================================
Plugin             Auth Inst Notes
================== ==== ==== ===============================================================
haproxy_           Y    Y    Integration with the HAProxy load balancer
s3front_           Y    Y    Integration with Amazon CloudFront distribution of S3 buckets
gandi_             Y    N    Obtain certificates via the Gandi LiveDNS API
varnish_           Y    N    Obtain certificates via a Varnish server
external-auth_     Y    Y    A plugin for convenient scripting
pritunl_           N    Y    Install certificates in pritunl distributed OpenVPN servers
proxmox_           N    Y    Install certificates in Proxmox Virtualization servers
dns-standalone_    Y    N    Obtain certificates via an integrated DNS server
dns-ispconfig_     Y    N    DNS Authentication using ISPConfig as DNS server
dns-clouddns_      Y    N    DNS Authentication using CloudDNS API
dns-lightsail_     Y    N    DNS Authentication using Amazon Lightsail DNS API
dns-inwx_          Y    Y    DNS Authentication for INWX through the XML API
dns-azure_         Y    N    DNS Authentication using Azure DNS
dns-godaddy_       Y    N    DNS Authentication using Godaddy DNS
dns-yandexcloud_   Y    N    DNS Authentication using Yandex Cloud DNS
dns-bunny_         Y    N    DNS Authentication using BunnyDNS
njalla_            Y    N    DNS Authentication for njalla
DuckDNS_           Y    N    DNS Authentication for DuckDNS
Porkbun_           Y    N    DNS Authentication for Porkbun
Infomaniak_        Y    N    DNS Authentication using Infomaniak Domains API
dns-multi_         Y    N    DNS authentication of 100+ providers using go-acme/lego
dns-dnsmanager_    Y    N    DNS Authentication for dnsmanager.io
standalone-nfq_    Y    N    HTTP Authentication that works with any webserver (Linux only)
dns-solidserver_   Y    N    DNS Authentication using SOLIDserver (EfficientIP)
dns-stackit_       Y    N    DNS Authentication using STACKIT DNS
dns-ionos_         Y    N    DNS Authentication using IONOS Cloud DNS
dns-mijn-host_     Y    N    DNS Authentication using mijn.host DNS
================== ==== ==== ===============================================================

.. _haproxy: https://github.com/greenhost/certbot-haproxy
.. _s3front: https://github.com/dlapiduz/letsencrypt-s3front
.. _gandi: https://github.com/obynio/certbot-plugin-gandi
.. _varnish: https://git.sesse.net/?p=letsencrypt-varnish-plugin
.. _pritunl: https://github.com/kharkevich/letsencrypt-pritunl
.. _proxmox: https://github.com/kharkevich/letsencrypt-proxmox
.. _external-auth: https://github.com/EnigmaBridge/certbot-external-auth
.. _dns-standalone: https://github.com/siilike/certbot-dns-standalone
.. _dns-ispconfig: https://github.com/m42e/certbot-dns-ispconfig
.. _dns-clouddns: https://github.com/vshosting/certbot-dns-clouddns
.. _dns-lightsail: https://github.com/noi/certbot-dns-lightsail
.. _dns-inwx: https://github.com/oGGy990/certbot-dns-inwx/
.. _dns-azure: https://github.com/binkhq/certbot-dns-azure
.. _dns-godaddy: https://github.com/miigotu/certbot-dns-godaddy
.. _dns-yandexcloud: https://github.com/PykupeJIbc/certbot-dns-yandexcloud
.. _dns-bunny: https://github.com/mwt/certbot-dns-bunny
.. _njalla: https://github.com/chaptergy/certbot-dns-njalla
.. _DuckDNS: https://github.com/infinityofspace/certbot_dns_duckdns
.. _Porkbun: https://github.com/infinityofspace/certbot_dns_porkbun
.. _Infomaniak: https://github.com/Infomaniak/certbot-dns-infomaniak
.. _dns-multi: https://github.com/alexzorin/certbot-dns-multi
.. _dns-dnsmanager: https://github.com/stayallive/certbot-dns-dnsmanager
.. _standalone-nfq: https://github.com/alexzorin/certbot-standalone-nfq
.. _dns-solidserver: https://gitlab.com/charlyhong/certbot-dns-solidserver
.. _dns-stackit: https://github.com/stackitcloud/certbot-dns-stackit
.. _dns-ionos: https://github.com/ionos-cloud/certbot-dns-ionos-cloud
.. _dns-mijn-host: https://github.com/mijnhost/certbot-dns-mijn-host

If you're interested, you can also :ref:`write your own plugin <dev-plugin>`.

.. _managing-certs:

Managing certificates
=====================

To view a list of the certificates Certbot knows about, run
the ``certificates`` subcommand:

``certbot certificates``

This returns information in the following format::

  Found the following certificates:
    Certificate Name: example.com
      Domains: example.com, www.example.com
      Expiry Date: 2017-02-19 19:53:00+00:00 (VALID: 30 days)
      Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
      Key Type: RSA
      Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem

``Certificate Name`` shows the name of the certificate. Pass this name
using the ``--cert-name`` flag to specify a particular certificate for the ``run``,
``certonly``, ``certificates``, ``renew``, and ``delete`` commands. The certificate
name cannot contain filepath separators (i.e. '/' or '\\', depending on the platform).
Example::

  certbot certonly --cert-name example.com

.. _updating_certs:

Modifying and Updating Certificates
----------------------------------------------

You can use ``certonly`` or ``run`` subcommands to request
the creation of a single new certificate even if you already have an
existing certificate with some of the same domain names.

If a certificate is requested with ``run`` or ``certonly`` specifying a
certificate name that already exists, Certbot updates
the existing certificate. Otherwise a new certificate
is created and assigned the specified name.

The ``--force-renewal``, ``--duplicate``, and ``--expand`` options
control Certbot's behavior when re-creating
a certificate with the same name as an existing certificate.
If you don't specify a requested behavior, Certbot may ask you what you intended.

``--force-renewal`` tells Certbot to request a new certificate
with the same domains as an existing certificate. Each domain
must be explicitly specified via ``-d``. If successful, this certificate
is saved alongside the earlier one and symbolic links (the "``live``"
reference) will be updated to point to the new certificate. This is a
valid method of renewing a specific individual
certificate.

``--duplicate`` tells Certbot to create a separate, unrelated certificate
with the same domains as an existing certificate. This certificate is
saved completely separately from the prior one. Most users will not
need to issue this command in normal circumstances.

``--expand`` tells Certbot to update an existing certificate with a new
certificate that contains all of the old domains and one or more additional
new domains. With the ``--expand`` option, use the ``-d`` option to specify
all existing domains and one or more new domains.

Example:

.. code-block:: none

  certbot --expand -d existing.com,example.com,newdomain.com

If you prefer, you can specify the domains individually like this:

.. code-block:: none

  certbot --expand -d existing.com -d example.com -d newdomain.com

Consider using ``--cert-name`` instead of ``--expand``, as it gives more control
over which certificate is modified and it lets you remove domains as well as adding them.

``--allow-subset-of-names`` tells Certbot to continue with certificate generation if
only some of the specified domain authorizations can be obtained. This may
be useful if some domains specified in a certificate no longer point at this
system.

Whenever you obtain a new certificate in any of these ways, the new
certificate exists alongside any previously obtained certificates, whether
or not the previous certificates have expired. The generation of a new
certificate counts against several rate limits that are intended to prevent
abuse of the ACME protocol, as described
`here <https://letsencrypt.org/docs/rate-limits/>`__.

.. _Modifying the Renewal Configuration File:

Modifying the Renewal Configuration of Existing Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When creating a certificate, Certbot will keep track of all of the relevant options chosen by the user. At renewal
time, Certbot will remember these options and apply them once again.

Sometimes, you may encounter the need to change some of these options for future certificate renewals. To achieve this,
you will need to perform the following steps:

Certbot v2.3.0 and newer
~~~~~~~~~~~~~~~~~~~~~~~~
The ``certbot reconfigure`` command can be used to change a certificate's renewal options.
This command will use the new renewal options to perform a test renewal against the Let's Encrypt staging server.
If this is successful, the new renewal options will be saved and will apply to future renewals.

You will need to specify the ``--cert-name``, which can be found by running ``certbot certificates``.

A list of common options that may be updated with the ``reconfigure`` command can be found by running
``certbot help reconfigure``.

As a practical example, if you were using the ``webroot`` authenticator and had relocated your website to another directory,
you can change the ``--webroot-path`` to the new directory using the following command:

.. code-block:: shell

  certbot reconfigure --cert-name example.com --webroot-path /path/to/new/location

Certbot v2.2.0 and older
~~~~~~~~~~~~~~~~~~~~~~~~
1. Perform a *dry run renewal* with the amended options on the command line. This allows you to confirm that the change
   is valid and will result in successful future renewals.
2. If the dry run is successful, perform a *live renewal* of the certificate. This will persist the change for future
   renewals. If the certificate is not yet due to expire, you will need to force a renewal using ``--force-renewal``.

.. note:: Rate limits from the certificate authority may prevent you from performing multiple renewals in a short
   period of time. It is strongly recommended to perform the second step only once, when you have decided on what
   options should change.

As a practical example, if you were using the ``webroot`` authenticator and had relocated your website to another directory,
you would need to change the ``--webroot-path`` to the new directory. Following the above advice:

1. Perform a *dry-run renewal* of the individual certificate with the amended options::

     certbot renew --cert-name example.com --webroot-path /path/to/new/location --dry-run

2. If the dry-run was successful, make the change permanent by performing a *live renewal* of the certificate with the
   amended options, including ``--force-renewal``::

     certbot renew --cert-name example.com --webroot-path /path/to/new/location --force-renewal

   ``--cert-name`` selects the particular certificate to be modified. Without this option, all certificates will be selected.

   ``--webroot-path`` is the option intended to be changed. All other previously selected options will be kept the same
   and do not need to be included in the command.

For advanced certificate management tasks, it is also possible to manually modify the certificate's renewal configuration
file, but this is discouraged since it can easily break Certbot's ability to renew your certificates. These renewal
configuration files are located at ``/etc/letsencrypt/renewal/CERTNAME.conf``. If you choose to modify the renewal
configuration file we advise you to make a backup of the file beforehand and test its validity with the ``certbot renew --dry-run`` command.

.. warning:: Manually modifying files under ``/etc/letsencrypt/renewal/`` can damage them if done improperly and we do not recommend doing so.


.. _changing:

Changing a Certificate's Domains
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``--cert-name`` flag can also be used to modify the domains a certificate contains,
by specifying new domains using the ``-d`` or ``--domains`` flag. If certificate ``example.com``
previously contained ``example.com`` and ``www.example.com``, it can be modified to only
contain ``example.com`` by specifying only ``example.com`` with the ``-d`` or ``--domains`` flag. Example::

  certbot certonly --cert-name example.com -d example.com

The same format can be used to expand the set of domains a certificate contains, or to
replace that set entirely::

  certbot certonly --cert-name example.com -d example.org,www.example.org

.. _using-ecdsa-keys:

RSA and ECDSA keys
------------------------

Certbot supports two certificate private key algorithms: ``rsa`` and ``ecdsa``.

As of version 2.0.0, Certbot defaults to ECDSA ``secp256r1`` (P-256) certificate private keys
for all new certificates. Existing certificates will continue to renew using their existing key
type, unless a key type change is requested.

The type of key used by Certbot can be controlled through the ``--key-type`` option.
You can use the ``--elliptic-curve`` option to control the curve used in ECDSA
certificates and the ``--rsa-key-size`` option to control the size of RSA keys.

.. warning:: If you obtain certificates using ECDSA keys, you should be careful
   not to downgrade to a Certbot version earlier than 1.10.0 where ECDSA keys were
   not supported. Downgrades like this are possible if you switch from something like
   the snaps or pip to packages provided by your operating system which often lag behind.

Changing a certificate's key type
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unless you are aware that you need to support very old HTTPS clients that are
not supported by most sites, you can safely transition your site to use
ECDSA keys instead of RSA keys.

If you want to change a single certificate to use ECDSA keys, you'll need to
create or renew a certificate while setting ``--key-type ecdsa`` on the command line:

.. code-block:: shell

  certbot renew --key-type ecdsa --cert-name example.com --force-renewal

If you want to use ECDSA keys for all certificates in the future (including renewals
of existing certificates), you can add the following line to Certbot's
:ref:`configuration file <config-file>`:

.. code-block:: ini

  key-type = ecdsa

which will take effect upon the next renewal of each certificate.

Revoking certificates
---------------------

If you need to revoke a certificate, use the ``revoke`` subcommand to do so.

A certificate may be revoked by providing its name (see ``certbot certificates``) or by providing
its path directly::

  certbot revoke --cert-name example.com

  certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem

If the certificate being revoked was obtained via the ``--staging``, ``--test-cert`` or a non-default ``--server`` flag,
that flag must be passed to the ``revoke`` subcommand.

.. note:: After revocation, Certbot will (by default) ask whether you want to **delete** the certificate.
          Unless deleted, Certbot will try to renew revoked certificates the next time ``certbot renew`` runs.

You can also specify the reason for revoking your certificate by using the ``reason`` flag.
Reasons include ``unspecified`` which is the default, as well as ``keycompromise``,
``affiliationchanged``, ``superseded``, and ``cessationofoperation``::

  certbot revoke --cert-name example.com --reason keycompromise

Revoking by account key or certificate private key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, Certbot will try revoke the certificate using your ACME account key. If the certificate was created from
the same ACME account, the revocation will be successful.

If you instead have the corresponding private key file to the certificate you wish to revoke, use ``--key-path`` to perform the
revocation from any ACME account::

  certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem --key-path /etc/letsencrypt/live/example.com/privkey.pem

.. _deleting:

Deleting certificates
---------------------

If you need to delete a certificate, use the ``delete`` subcommand.

.. note:: Read this and the `Safely deleting certificates`_ sections carefully. This is an irreversible operation and must
          be done with care.

Certbot does not automatically revoke a certificate before deleting it. If you're no longer using a certificate and don't
plan to use it anywhere else, you may want to follow the instructions in `Revoking certificates`_ instead. Generally, there's
no need to revoke a certificate if its private key has not been compromised, but you may still receive expiration emails
from Let's Encrypt unless you revoke.

.. note:: Do not manually delete certificate files from inside ``/etc/letsencrypt/``. Always use the ``delete`` subcommand.

A certificate may be deleted by providing its name with ``--cert-name``. \
You may find its name using ``certbot certificates``.

Otherwise, you will be prompted to choose one or more
certificates to delete::

  certbot delete --cert-name example.com
  # or to choose from a list:
  certbot delete

Safely deleting certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Deleting a certificate without following the proper steps can result in a non-functioning server. To safely delete a
certificate, follow all the steps below to make sure that references to a certificate are removed from the configuration
of any installed server software (Apache, nginx, Postfix, etc) *before* deleting the certificate.

To explain further, when installing a certificate, Certbot modifies Apache or nginx's configuration to load the certificate
and its private key from the ``/etc/letsencrypt/live/`` directory. Before deleting a certificate, it is necessary to undo
that modification, by removing any references to the certificate from the webserver's configuration files.

Follow these steps to safely delete a certificate:

1. Find all references to the certificate (substitute ``example.com`` in the command for the name of the certificate
   you wish to delete)::

     sudo bash -c 'grep -R live/example.com /etc/{nginx,httpd,apache2}'

   If there are no references found, skip directly to Step 4.

   If some references are found, they will look something like::

     /etc/apache2/sites-available/000-default-le-ssl.conf:SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
     /etc/apache2/sites-available/000-default-le-ssl.conf:SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem

2. You will need a self-signed certificate to replace the certificate you are deleting. The following command will generate one
   for you, saving the certificate at ``/etc/letsencrypt/self-signed-cert.pem`` and its private key at
   ``/etc/letsencrypt/self-signed-privkey.pem``::

     sudo openssl req -nodes -batch -x509 -newkey rsa:2048 -keyout /etc/letsencrypt/self-signed-privkey.pem -out /etc/letsencrypt/self-signed-cert.pem -days 356

3. For each reference found in Step 1, open the file in a text editor and replace the reference to the existing
   certificate with a reference to the self-signed certificate.

   Continuing from the previous example, you would open ``/etc/apache2/sites-available/000-default-le-ssl.conf`` in a text editor
   and modify the two matching lines of text to instead say::

     SSLCertificateFile /etc/letsencrypt/self-signed-cert.pem
     SSLCertificateKeyFile /etc/letsencrypt/self-signed-privkey.pem

4. It is now safe to delete the certificate. Do so by running::

     sudo certbot delete --cert-name example.com

.. _renewal:

Renewing certificates
---------------------

Most Certbot installations come with automatic renewals preconfigured. This is done by means of a scheduled task which runs `certbot renew`_ periodically.

.. note:: Let's Encrypt CA issues short-lived certificates (90
   days). By default, Certbot will try to renew certificates 30
   days before they expire.

.. seealso:: Users of the `Manual`_ plugin should note that ``--manual`` certificates
   will not renew automatically, unless combined with authentication hook scripts.
   See `Renewal with the manual plugin <#manual-renewal>`_.

If you are unsure whether you need to configure automated renewal, follow these steps:

.. _renewal-config-file:

Automated Renewals
~~~~~~~~~~~~~~~~~~

1. Review the instructions for your system and installation method at
   https://certbot.eff.org/instructions. They will describe how to set up a scheduled task,
   if necessary. If no step is listed, your system comes with automated renewal pre-installed,
   and you should not need to take any additional actions.
2. On Linux and BSD, you can check to see if your installation method has pre-installed a timer
   for you. To do so, look for the ``certbot renew`` command in either your system's crontab
   (typically `/etc/crontab` or `/etc/cron.*/*`) or systemd timers (``systemctl list-timers``).
3. If you're still not sure, you can configure automated renewal manually by following the steps
   in the next section. Certbot has been carefully engineered to handle the case where both manual
   automated renewal and pre-installed automated renewal are set up.

.. _configure-automated-renewal:

Confiigure Automated Renewal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you think you may need to set up automated renewal, follow these instructions to set up a scheduled task to automatically renew your certificates in the background. 
If you are unsure whether your system has a pre-installed scheduled task for Certbot, it is safe to follow these instructions to create one.

.. note::
   If you're using Windows, these instructions are not neccessary as Certbot on Windows comes with
   a scheduled task for automated renewal pre-installed.

   If you are using macOS and installed Certbot using Homebrew, follow the instructions at
   https://certbot.eff.org/instructions to set up automated renewal. The instructions below
   are not applicable on macOS.

Run the following line, which will add a cron job to `/etc/crontab`:

.. code-block:: shell


  SLEEPTIME=$(awk 'BEGIN{srand(); print int(rand()*(3600+1))}'); echo "0 0,12 * * * root sleep $SLEEPTIME && certbot renew -q" | sudo tee -a /etc/crontab > /dev/null

If you're sure that this command executes successfully without human
intervention, you can add the command to ``crontab`` (since certificates
are only renewed when they're determined to be near expiry, the command
can run on a regular basis, like every week or every day). In that case,
you are likely to want to use the ``-q`` or ``--quiet`` quiet flag to
silence all output except errors.

If you are manually renewing all of your certificates, the
``--force-renewal`` flag may be helpful; it causes the expiration time of
the certificate(s) to be ignored when considering renewal, and attempts to
renew each and every installed certificate regardless of its age. (This
form is not appropriate to run daily because each certificate will be
renewed every day, which will quickly run into the certificate authority
rate limit.)

Starting with Certbot 2.7.0, certbot provides the environment variables
`RENEWED_DOMAINS` and `FAILED_DOMAINS` to all post renewal hooks. These
variables contain a space separated list of domains. These variables can be used
to determine if a renewal has succeeded or failed as part of your post renewal
hook.

Note that options provided to ``certbot renew`` will apply to
*every* certificate for which renewal is attempted; for example,
``certbot renew --rsa-key-size 4096`` would try to replace every
near-expiry certificate with an equivalent certificate using a 4096-bit
RSA public key. If a certificate is successfully renewed using
specified options, those options will be saved and used for future
renewals of that certificate.

An alternative form that provides for more fine-grained control over the
renewal process (while renewing specified certificates one at a time),
is ``certbot certonly`` with the complete set of subject domains of
a specific certificate specified via `-d` flags. You may also want to
include the ``-n`` or ``--noninteractive`` flag to prevent blocking on
user input (which is useful when running the command from cron).

``certbot certonly -n -d example.com -d www.example.com``

All of the domains covered by the certificate must be specified in
this case in order to renew and replace the old certificate rather
than obtaining a new one; don't forget any `www.` domains! Specifying
a subset of the domains creates a new, separate certificate containing
only those domains, rather than replacing the original certificate.
When run with a set of domains corresponding to an existing certificate,
the ``certonly`` command attempts to renew that specific certificate.

If you needed to stop your webserver to run Certbot, you'll want to
add ``pre`` and ``post`` hooks to stop and start your webserver automatically.
For example, if your webserver is HAProxy, run the following commands to create the hook files
in the appropriate directory:

.. code-block:: shell

  sudo sh -c 'printf "#!/bin/sh\nservice haproxy stop\n" > /etc/letsencrypt/renewal-hooks/pre/haproxy.sh'
  sudo sh -c 'printf "#!/bin/sh\nservice haproxy start\n" > /etc/letsencrypt/renewal-hooks/post/haproxy.sh'
  sudo chmod 755 /etc/letsencrypt/renewal-hooks/pre/haproxy.sh
  sudo chmod 755 /etc/letsencrypt/renewal-hooks/post/haproxy.sh

Congratulations, Certbot will now automatically renew your certificates in the background.

If you are interested in learning more about how Certbot renews your certificates, see the
`Renewing certificates`_ section above.

.. _references:

Reference:
------------------

.. _certbot_renew:

``certbot renew``
~~~~~~~~~~~~~~~~~

   This command attempts to renew any previously-obtained certificates that expire in less than 30 days. 
   The same plugin and options that were used at the time the certificate was originally issued will be used for the renewal attempt, unless you specify other plugins or options. 
   Unlike certonly, renew acts on multiple certificates and always takes into account whether each one is near expiry. 
   Because of this, renew is suitable (and designed) for automated use, to allow your system to automatically renew each certificate when appropriate. 
   Since renew only renews certificates that are near expiry it can be run as frequently as you want - since it will usually take no action.

   .. note:: Options provided to ``certbot renew`` will apply to
      *every* certificate for which renewal is attempted; for example,
      ``certbot renew --rsa-key-size 4096`` would try to replace every
      near-expiry certificate with an equivalent certificate using a 4096-bit
      RSA public key. If a certificate is successfully renewed using
      specified options, those options will be saved and used for future
      renewals of that certificate.

``-q``, ``--quiet``
^^^^^^^^^^^^^^^^^^^
   Silence all output except errors.

``--force-renewal``
^^^^^^^^^^^^^^^^^^^
   For manually renewing all of your certificates

   Causes the expiration time of the certificate(s) to be ignored when considering renewal, and attempts to
   renew each and every installed certificate regardless of its age. (This form is not appropriate to run daily because each certificate will be
   renewed every day, which will quickly run into the certificate authority rate limit.)

Certbot Renew: Hooks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The ``renew`` command includes hooks for running commands or scripts before or after a certificate is
renewed.

.. note:: ``certbot renew`` exit status will only be 1 if a renewal attempt failed. This means ``certbot renew`` exit status will be 0 if no certificate needs to be updated. 
  If you write a custom script and expect to run a command only after a certificate was actually renewed
  you will need to use the deploy_hook_ since the exit status will be 0 both on successful renewal
  and when renewal is not necessary.

Specifying Hooks
^^^^^^^^^^^^^^^^

You can specify hooks by placing files in subdirectories of Certbot's
configuration directory. Assuming your configuration directory is
``/etc/letsencrypt``, any executable files found in
``/etc/letsencrypt/renewal-hooks/pre``,
``/etc/letsencrypt/renewal-hooks/deploy``, and
``/etc/letsencrypt/renewal-hooks/post`` will be run as pre, deploy, and post
hooks respectively when any certificate is renewed with the ``renew``
subcommand. These hooks are run in alphabetical order and are not run for other
subcommands. (The order the hooks are run is determined by the byte value of
the characters in their filenames and is not dependent on your locale.)

``--pre-hook`` & ``--post-hook``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   Run before and after each attempt to renew it.

   For example, if you have a single certificate obtained using
   the standalone_ plugin, you might need to stop the webserver
   before renewing so standalone can bind to the necessary ports, and
   then restart it after the plugin is finished. Example::

     certbot renew --pre-hook "service nginx stop" --post-hook "service nginx start"

   If a hook exits with a non-zero exit code, the error will be printed
   to ``stderr`` but renewal will be attempted anyway.

.. _deploy_hook:

``--deploy-hook``
^^^^^^^^^^^^^^^^^

   Run only after a successful renewal.

   Example:
   ``certbot renew --deploy-hook /path/to/deploy-hook-script``

   Hooks specified in the command line, :ref:`configuration file
   <config-file>`, or :ref:`renewal configuration files <renewal-config-file>` are
   run as usual after running all hooks in these directories. One minor exception
   to this is if a hook specified elsewhere is simply the path to an executable
   file in the hook directory of the same type (e.g. your pre-hook is the path to
   an executable in ``/etc/letsencrypt/renewal-hooks/pre``), the file is not run a
   second time. You can stop Certbot from automatically running executables found
   in these directories by including ``--no-directory-hooks`` on the command line.

Failing Hooks
^^^^^^^^^^^^^
Doesn't directly cause Certbot to exit with a non-zero exit code, but
since Certbot exits with a non-zero exit code when renewals fail, a
failed hook causing renewal failures will indirectly result in a
non-zero exit code. Hooks will only be run if a certificate is due for
renewal, so you can run the above command frequently without
unnecessarily stopping your webserver.

More information about hooks can be found by running
``certbot --help renew``.


Please note that the CA will send notification emails to the address
you provide if you do not renew certificates that are about to expire.


.. _where-certs:

Where are my certificates?
==========================

All generated keys and issued certificates can be found in
``/etc/letsencrypt/live/$domain``, where ``$domain`` is the certificate
name (see the note below). Rather than copying, please point your (web)
server configuration directly to those files (or create symlinks).
During the renewal_, ``/etc/letsencrypt/live`` is updated with the latest
necessary files.

.. note::
  The certificate name ``$domain`` used in the path ``/etc/letsencrypt/live/$domain``
  follows this convention:

  * it is the name given to ``--cert-name``,
  * if ``--cert-name`` is not set by the user it is the first domain given to
    ``--domains``,
  * if the first domain is a wildcard domain (eg. ``*.example.com``) the
    certificate name will be ``example.com``,
  * if a name collision would occur with a certificate already named ``example.com``,
    the new certificate name will be constructed using a numerical sequence
    as ``example.com-001``.

For historical reasons, the containing directories are created with
permissions of ``0700`` meaning that certificates are accessible only
to servers that run as the root user.  **If you will never downgrade
to an older version of Certbot**, then you can safely fix this using
``chmod 0755 /etc/letsencrypt/{live,archive}``.

For servers that drop root privileges before attempting to read the
private key file, you will also need to use ``chgrp`` and ``chmod
0640`` to allow the server to read
``/etc/letsencrypt/live/$domain/privkey.pem``.

The following files are available:

``privkey.pem``
  Private key for the certificate.

  .. warning:: This **must be kept secret at all times**! Never share
     it with anyone, including Certbot developers. You cannot
     put it into a safe, however - your server still needs to access
     this file in order for SSL/TLS to work.

  .. note:: As of Certbot version 0.29.0, private keys for new certificate
     default to ``0600``. Any changes to the group mode or group owner (gid)
     of this file will be preserved on renewals.

  This is what Apache needs for `SSLCertificateKeyFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatekeyfile>`_,
  and Nginx for `ssl_certificate_key
  <https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate_key>`_.

``fullchain.pem``
  All certificates, **including** server certificate (aka leaf certificate or
  end-entity certificate). The server certificate is the first one in this file,
  followed by any intermediates.

  This is what Apache >= 2.4.8 needs for `SSLCertificateFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile>`_,
  and what Nginx needs for `ssl_certificate
  <https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate>`_.

``cert.pem`` and ``chain.pem`` (less common)
  ``cert.pem`` contains the server certificate by itself, and
  ``chain.pem`` contains the additional intermediate certificate or
  certificates that web browsers will need in order to validate the
  server certificate. If you provide one of these files to your web
  server, you **must** provide both of them, or some browsers will show
  "This Connection is Untrusted" errors for your site, `some of the time
  <https://whatsmychaincert.com/>`_.

  Apache < 2.4.8 needs these for `SSLCertificateFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatefile>`_.
  and `SSLCertificateChainFile
  <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslcertificatechainfile>`_,
  respectively.

  If you're using OCSP stapling with Nginx >= 1.3.7, ``chain.pem`` should be
  provided as the `ssl_trusted_certificate
  <https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_trusted_certificate>`_
  to validate OCSP responses.

.. note:: All files are PEM-encoded.
   If you need other format, such as DER or PFX, then you
   could convert using ``openssl``. You can automate that with
   ``--deploy-hook`` if you're using automatic renewal_.

.. _hooks:

Pre and Post Validation Hooks
=============================

Certbot allows for the specification of pre and post validation hooks when run
in manual mode. The flags to specify these scripts are ``--manual-auth-hook``
and ``--manual-cleanup-hook`` respectively and can be used as follows:

::

 certbot certonly --manual --manual-auth-hook /path/to/http/authenticator.sh --manual-cleanup-hook /path/to/http/cleanup.sh -d secure.example.com

This will run the ``authenticator.sh`` script, attempt the validation, and then run
the ``cleanup.sh`` script. Additionally certbot will pass relevant environment
variables to these scripts:

- ``CERTBOT_DOMAIN``: The domain being authenticated
- ``CERTBOT_VALIDATION``: The validation string
- ``CERTBOT_TOKEN``: Resource name part of the HTTP-01 challenge (HTTP-01 only)
- ``CERTBOT_REMAINING_CHALLENGES``: Number of challenges remaining after the current challenge
- ``CERTBOT_ALL_DOMAINS``: A comma-separated list of all domains challenged for the current certificate

Additionally for cleanup:

- ``CERTBOT_AUTH_OUTPUT``: Whatever the auth script wrote to stdout

Example usage for HTTP-01:

::

 certbot certonly --manual --preferred-challenges=http --manual-auth-hook /path/to/http/authenticator.sh --manual-cleanup-hook /path/to/http/cleanup.sh -d secure.example.com

/path/to/http/authenticator.sh

.. code-block:: none

   #!/bin/bash
   echo $CERTBOT_VALIDATION > /var/www/htdocs/.well-known/acme-challenge/$CERTBOT_TOKEN

/path/to/http/cleanup.sh

.. code-block:: none

   #!/bin/bash
   rm -f /var/www/htdocs/.well-known/acme-challenge/$CERTBOT_TOKEN

Example usage for DNS-01 (Cloudflare API v4) (for example purposes only, do not use as-is)

::

 certbot certonly --manual --preferred-challenges=dns --manual-auth-hook /path/to/dns/authenticator.sh --manual-cleanup-hook /path/to/dns/cleanup.sh -d secure.example.com

/path/to/dns/authenticator.sh

.. code-block:: none

   #!/bin/bash

   # Get your API key from https://www.cloudflare.com/a/account/my-account
   API_KEY="your-api-key"
   EMAIL="your.email@example.com"

   # Strip only the top domain to get the zone id
   DOMAIN=$(expr match "$CERTBOT_DOMAIN" '.*\.\(.*\..*\)')

   # Get the Cloudflare zone id
   ZONE_EXTRA_PARAMS="status=active&page=1&per_page=20&order=status&direction=desc&match=all"
   ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&$ZONE_EXTRA_PARAMS" \
        -H     "X-Auth-Email: $EMAIL" \
        -H     "X-Auth-Key: $API_KEY" \
        -H     "Content-Type: application/json" | python -c "import sys,json;print(json.load(sys.stdin)['result'][0]['id'])")

   # Create TXT record
   CREATE_DOMAIN="_acme-challenge.$CERTBOT_DOMAIN"
   RECORD_ID=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
        -H     "X-Auth-Email: $EMAIL" \
        -H     "X-Auth-Key: $API_KEY" \
        -H     "Content-Type: application/json" \
        --data '{"type":"TXT","name":"'"$CREATE_DOMAIN"'","content":"'"$CERTBOT_VALIDATION"'","ttl":120}' \
                | python -c "import sys,json;print(json.load(sys.stdin)['result']['id'])")
   # Save info for cleanup
   if [ ! -d /tmp/CERTBOT_$CERTBOT_DOMAIN ];then
           mkdir -m 0700 /tmp/CERTBOT_$CERTBOT_DOMAIN
   fi
   echo $ZONE_ID > /tmp/CERTBOT_$CERTBOT_DOMAIN/ZONE_ID
   echo $RECORD_ID > /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID

   # Sleep to make sure the change has time to propagate over to DNS
   sleep 25

/path/to/dns/cleanup.sh

.. code-block:: none

   #!/bin/bash

   # Get your API key from https://www.cloudflare.com/a/account/my-account
   API_KEY="your-api-key"
   EMAIL="your.email@example.com"

   if [ -f /tmp/CERTBOT_$CERTBOT_DOMAIN/ZONE_ID ]; then
           ZONE_ID=$(cat /tmp/CERTBOT_$CERTBOT_DOMAIN/ZONE_ID)
           rm -f /tmp/CERTBOT_$CERTBOT_DOMAIN/ZONE_ID
   fi

   if [ -f /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID ]; then
           RECORD_ID=$(cat /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID)
           rm -f /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID
   fi

   # Remove the challenge TXT record from the zone
   if [ -n "${ZONE_ID}" ]; then
       if [ -n "${RECORD_ID}" ]; then
           curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                   -H "X-Auth-Email: $EMAIL" \
                   -H "X-Auth-Key: $API_KEY" \
                   -H "Content-Type: application/json"
       fi
   fi

.. _lock-files:

Changing the ACME Server
========================

By default, Certbot uses Let's Encrypt's production server at
https://acme-v02.api.letsencrypt.org/directory. You can tell Certbot to use a
different CA by providing ``--server`` on the command line or in a
:ref:`configuration file <config-file>` with the URL of the server's
ACME directory. For example, if you would like to use Let's Encrypt's
staging server, you would add ``--server
https://acme-staging-v02.api.letsencrypt.org/directory`` to the command line.

.. note:: ``--dry-run`` uses the Let's Encrypt staging server, unless ``--server``
   is specified on the CLI or in the :ref:`cli.ini configuration file <config-file>`.
   Take caution when using ``--dry-run`` with a custom server, as it may cause real
   certificates to be issued and discarded.

If Certbot does not trust the SSL certificate used by the ACME server, you
can use the `REQUESTS_CA_BUNDLE
<https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification>`_
environment variable to override the root certificates trusted by Certbot. Certbot
uses the ``requests`` library, which does not use the operating system trusted root store.
Make sure that ``REQUESTS_CA_BUNDLE`` is set globally in the environment and not only on
the CLI, or scheduled renewal will not succeed.


Lock Files
==========

When processing a validation Certbot writes a number of lock files on your system
to prevent multiple instances from overwriting each other's changes. This means
that by default two instances of Certbot will not be able to run in parallel.

Since the directories used by Certbot are configurable, Certbot
will write a lock file for all of the directories it uses. This include Certbot's
``--work-dir``, ``--logs-dir``, and ``--config-dir``. By default these are
``/var/lib/letsencrypt``, ``/var/log/letsencrypt``, and ``/etc/letsencrypt``
respectively. Additionally if you are using Certbot with Apache or nginx it will
lock the configuration folder for that program, which are typically also in the
``/etc`` directory.

Note that these lock files will only prevent other instances of Certbot from
using those directories, not other processes. If you'd like to run multiple
instances of Certbot simultaneously you should specify different directories
as the ``--work-dir``, ``--logs-dir``, and ``--config-dir`` for each instance
of Certbot that you would like to run.

.. _config-file:

Configuration file
==================

Certbot accepts a global configuration file that applies its options to all invocations
of Certbot. Certificate specific configuration choices should be set in the ``.conf``
files that can be found in ``/etc/letsencrypt/renewal``.

By default no cli.ini file is created (though it may exist already if you installed Certbot
via a package manager, for instance).
After creating one it is possible to specify the location of this configuration file with
``certbot --config cli.ini`` (or shorter ``-c cli.ini``). An
example configuration file is shown below:

.. include:: ../examples/cli.ini
   :code: ini

By default, the following locations are searched:

- ``/etc/letsencrypt/cli.ini``
- ``$XDG_CONFIG_HOME/letsencrypt/cli.ini`` (or
  ``~/.config/letsencrypt/cli.ini`` if ``$XDG_CONFIG_HOME`` is not
  set).

Since this configuration file applies to all invocations of certbot it is incorrect
to list domains in it. Listing domains in cli.ini may prevent renewal from working.
Additionally due to how arguments in cli.ini are parsed, options which wish to
not be set should not be listed. Options set to false will instead be read
as being set to true by older versions of Certbot, since they have been listed
in the config file.

.. keep it up to date with constants.py

.. _log-rotation:

Log Rotation
============

By default certbot stores status logs in ``/var/log/letsencrypt``. By default
certbot will begin rotating logs once there are 1000 logs in the log directory.
Meaning that once 1000 files are in ``/var/log/letsencrypt`` Certbot will delete
the oldest one to make room for new logs. The number of subsequent logs can be
changed by passing the desired number to the command line flag
``--max-log-backups``. Setting this flag to 0 disables log rotation entirely,
causing certbot to always append to the same log file.

.. note:: Some distributions, including Debian and Ubuntu, disable
   certbot's internal log rotation in favor of a more traditional
   logrotate script.  If you are using a distribution's packages and
   want to alter the log rotation, check `/etc/logrotate.d/` for a
   certbot rotation script.

.. _command-line:

Certbot command-line options
============================

Certbot supports a lot of command line options. Here's the full list, from
``certbot --help all``:

.. literalinclude:: cli-help.txt

Getting help
============

If you're having problems, we recommend posting on the Let's Encrypt
`Community Forum <https://community.letsencrypt.org>`_.

If you find a bug in the software, please do report it in our `issue
tracker <https://github.com/certbot/certbot/issues>`_. Remember to
give us as much information as possible:

- copy and paste exact command line used and the output (though mind
  that the latter might include some personally identifiable
  information, including your email and domains)
- copy and paste logs from ``/var/log/letsencrypt`` (though mind they
  also might contain personally identifiable information)
- copy and paste ``certbot --version`` output
- your operating system, including specific version
- specify which installation method you've chosen
