"""
The `~certbot_dns_linode.dns_linode` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Linode API.

.. note::
   The plugin is not installed by default. It can be installed by heading to
   `certbot.eff.org <https://certbot.eff.org/instructions#wildcard>`_, choosing your system and
   selecting the Wildcard tab.

Named Arguments
---------------

==========================================  ===================================
``--dns-linode-credentials``                Linode credentials_ INI file.
                                            (Required)
``--dns-linode-propagation-seconds``        The number of seconds to wait for
                                            DNS to propagate before asking the
                                            ACME server to verify the DNS
                                            record.
                                            (Default: 120 because Linode
                                            updates its first DNS every 60
                                            seconds and we allow 60 more seconds
                                            for the update to reach other 5
                                            servers)
==========================================  ===================================


Credentials
-----------

Use of this plugin requires a configuration file containing Linode API
credentials, obtained from your Linode account's `Applications & API
Tokens page (legacy) <https://manager.linode.com/profile/api>`_ or `Applications
& API Tokens page (new) <https://cloud.linode.com/profile/tokens>`_. The credentials require the following permissions: _________.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Linode API credentials used by Certbot
   dns_linode_key = 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ64
   dns_linode_version = 4

The path to this file can be provided interactively or using the
``--dns-linode-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Linode account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-linode \\
     --dns-linode-credentials ~/.secrets/certbot/linode.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-linode \\
     --dns-linode-credentials ~/.secrets/certbot/linode.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 120 seconds
             for DNS propagation (Linode updates its first DNS every minute
             and we allow some extra time for the update to reach other 5
             servers)

   certbot certonly \\
     --dns-linode \\
     --dns-linode-credentials ~/.secrets/certbot/linode.ini \\
     --dns-linode-propagation-seconds 120 \\
     -d example.com

"""
