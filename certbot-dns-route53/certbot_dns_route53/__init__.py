"""
The `~certbot_dns_route53.dns_route53` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the Amazon Web Services Route 53 API.

.. note::
   The plugin is not installed by default. It can be installed by heading to
   `certbot.eff.org <https://certbot.eff.org/instructions#wildcard>`_, choosing your system and
   selecting the Wildcard tab.

Credentials
-----------
Use of this plugin requires a configuration file containing Amazon Web Sevices
API credentials for an account with the following permissions:

* ``route53:ListHostedZones``
* ``route53:GetChange``
* ``route53:ChangeResourceRecordSets``

These permissions can be captured in an AWS policy like the one below. Amazon
provides `information about managing access <https://docs.aws.amazon.com/Route53
/latest/DeveloperGuide/access-control-overview.html>`_ and `information about
the required permissions <https://docs.aws.amazon.com/Route53/latest
/DeveloperGuide/r53-api-permissions-ref.html>`_

.. code-block:: json
   :name: sample-aws-policy.json
   :caption: Example AWS policy file:

   {
       "Version": "2012-10-17",
       "Id": "certbot-dns-route53 sample policy",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "route53:ListHostedZones",
                   "route53:GetChange"
               ],
               "Resource": [
                   "*"
               ]
           },
           {
               "Effect" : "Allow",
               "Action" : [
                   "route53:ChangeResourceRecordSets"
               ],
               "Resource" : [
                   "arn:aws:route53:::hostedzone/YOURHOSTEDZONEID"
               ]
           }
       ]
   }

The `access keys <https://docs.aws.amazon.com/general/latest/gr
/aws-sec-cred-types.html#access-keys-and-secret-access-keys>`_ for an account
with these permissions must be supplied in one of the following ways, which are
discussed in more detail in the Boto3 library's documentation about `configuring
credentials <https://boto3.readthedocs.io/en/latest/guide/configuration.html
#best-practices-for-configuring-credentials>`_.

* Using the ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` environment
  variables.
* Using a credentials configuration file at the default location,
  ``~/.aws/credentials``. If you're running on sudo, the credentials
  will be picked up from the root home.
* Using a credentials configuration file at a path supplied using the
  ``AWS_CONFIG_FILE`` environment variable.

.. code-block:: ini
   :name: config.ini
   :caption: Example credentials config file:

   [default]
   aws_access_key_id=AKIAIOSFODNN7EXAMPLE
   aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

.. caution::
   You should protect these API credentials as you would a password. Users who
   can read this file can use these credentials to issue some types of API calls
   on your behalf, limited by the permissions assigned to the account. Users who
   can cause Certbot to run using these credentials can complete a ``dns-01``
   challenge to acquire new certificates or revoke existing certificates for
   domains these credentials are authorized to manage.


Examples
--------
.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-route53 \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-route53 \\
     -d example.com \\
     -d www.example.com
"""
