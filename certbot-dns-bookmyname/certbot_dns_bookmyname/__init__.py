"""
The `~certbot_dns_bookmyname.dns_bookmyname` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records in a BookMyName domain zone.


Named Arguments
---------------

==========================================  ===================================
``--dns-bookmyname-credentials``            BookMyName credentials_ INI file.
                                            (Required)
``--dns-bookmyname-propagation-seconds``    The number of seconds to wait for
                                            DNS to propagate before asking the
                                            ACME server to verify the DNS
                                            record.
                                            (Default: 900)
==========================================  ===================================


Credentials
-----------

Use of this plugin requires a configuration file containing BookMyName
credentials, which are the login and password of a BookMyName account
allowed to modify the domain zone.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # BookMyName API credentials used by Certbot
   dns_bookmyname_login = SomeBookMyNameId
   dns_bookmyname_password = CorrespondingPassword

The path to this file can be provided interactively or using the
``--dns-bookmyname-credentials`` command-line argument. Certbot records the
path to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as they include the password to your
   BookMyName account. Users who can read this file can use these credentials
   to manipulate or even cancel your domain. Users who can cause Certbot to
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
     --dns-bookmyname \\
     --dns-bookmyname-credentials ~/.secrets/certbot/bookmyname.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-bookmyname \\
     --dns-bookmyname-credentials ~/.secrets/certbot/bookmyname.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 60 seconds
             for DNS propagation

   certbot certonly \\
     --dns-bookmyname \\
     --dns-bookmyname-credentials ~/.secrets/certbot/bookmyname.ini \\
     --dns-bookmyname-propagation-seconds 60 \\
     -d example.com

"""
