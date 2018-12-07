.. _ciphersuites:

Ciphersuites
============

Autoupdates
-----------

Within certain limits, TLS server software can choose what kind of
cryptography to use when a client connects. These choices can affect
security, compatibility, and performance in complex ways. Most of
these options are independent of a particular certificate. Certbot
tries to provide defaults that we think are most useful to our users.

As described below, Certbot will default to modifying
server software's cryptographic settings to keep these up-to-date with
what we think are appropriate defaults when new versions of the Certbot
are installed (for example, by an operating system package manager).

When this feature is implemented, this document will be updated
to describe how to disable these automatic changes.


Cryptographic choices
---------------------

Software that uses cryptography must inevitably make choices about what
kind of cryptography to use and how. These choices entail assumptions
about how well particular cryptographic mechanisms resist attack, and what
trade-offs are available and appropriate. The choices are constrained
by compatibility issues (in order to interoperate with other software,
an implementation must agree to use cryptographic mechanisms that the
other side also supports) and protocol issues (cryptographic mechanisms
must be specified in protocols and there must be a way to agree to use
them in a particular context).

The best choices for a particular application may change over time in
response to new research, new standardization events, changes in computer
hardware, and changes in the prevalence of legacy software. Much important
research on cryptanalysis and cryptographic vulnerabilities is unpublished
because many researchers have been working in the interest of improving
some entities' communications security while weakening, or failing to
improve, others' security. But important information that improves our
understanding of the state of the art is published regularly.

When enabling TLS support in a compatible web server (which is a separate
step from obtaining a certificate), Certbot has the ability to
update that web server's TLS configuration. Again, this is *different
from the cryptographic particulars of the certificate itself*; the
certificate as of the initial release will be RSA-signed using one of
Let's Encrypt's 2048-bit RSA keys, and will describe the subscriber's
RSA public key ("subject public key") of at least 2048 bits, which is
used for key establishment.

Note that the subscriber's RSA public key can be used in a wide variety
of key establishment methods, most of which do not use RSA directly
for key exchange, but only for authenticating the server!  For example,
in DHE and ECDHE key exchanges, the subject public key is just used to
sign other parameters for authentication. You do not have to "use RSA"
for other purposes just because you're using an RSA key for authentication.

The certificate doesn't specify other cryptographic or ciphersuite
particulars; for example, it doesn't say whether or not parties should
use a particular symmetric algorithm like 3DES, or what cipher modes
they should use. All of these details are negotiated between client
and server independent of the content of the ciphersuite. The
Let's Encrypt project hopes to provide useful defaults that reflect
good security choices with respect to the publicly-known state of the
art. However, the Let's Encrypt certificate authority does *not*
dictate end-users' security policy, and any site is welcome to change
its preferences in accordance with its own policy or its administrators'
preferences, and use different cryptographic mechanisms or parameters,
or a different priority order, than the defaults provided by Certbot.

If you don't use Certbot to configure your server directly, because the 
client doesn't integrate with your server software or because you chose 
not to use this integration, then the cryptographic defaults haven't been
modified, and the cryptography chosen by the server will still be whatever
the default for your software was.  For example, if you obtain a
certificate using *standalone* mode and then manually install it in an IMAP
or LDAP server, your cryptographic settings will not be modified by the
client in any way.


Sources of defaults
-------------------

Initially, Certbot will configure users' servers to use the cryptographic
defaults recommended by the Mozilla project. These settings are well-reasoned
recommendations that carefully consider client software compatibility. They
are described at

https://wiki.mozilla.org/Security/Server_Side_TLS

and the version implemented by Certbot will be the
version that was most current as of the release date of each client
version. Mozilla offers three separate sets of cryptographic options,
which trade off security and compatibility differently. These are
referred to as the "Modern", "Intermediate", and "Old" configurations
(in order from most secure to least secure, and least-backwards compatible
to most-backwards compatible). The client will follow the Mozilla defaults
for the *Intermediate* configuration by default, at least with regards to
ciphersuites and TLS versions. Mozilla's web site describes which client
software will be compatible with each configuration. You can also use
the Qualys SSL Labs site, which Certbot will suggest
when installing a certificate, to test your server and see whether it
will be compatible with particular software versions.

It will be possible to ask Certbot to instead apply (and track) Modern
or Old configurations.

The Let's Encrypt project expects to follow the Mozilla recommendations
in the future as those recommendations are updated. (For example, some
users have proposed prioritizing a new ciphersuite known as ``0xcc13``
which uses the ChaCha and Poly1305 algorithms, and which is already
implemented by the Chrome browser.  Mozilla has delayed recommending
``0xcc13`` over compatibility and standardization concerns, but is likely
to recommend it in the future once these concerns have been addressed. At
that point, Certbot would likely follow the Mozilla recommendations and favor
the use of this ciphersuite as well.)

The Let's Encrypt project may deviate from the Mozilla recommendations
in the future if good cause is shown and we believe our users'
priorities would be well-served by doing so. In general, please address
relevant proposals for changing priorities to the Mozilla security
team first, before asking the Certbot developers to change
Certbot's priorities. The Mozilla security team is likely to have more
resources and expertise to bring to bear on evaluating reasons why its
recommendations should be updated.

The Let's Encrypt project will entertain proposals to create a *very*
small number of alternative configurations (apart from Modern,
Intermediate, and Old) that there's reason to believe would be widely
used by sysadmins; this would usually be a preferable course to modifying
an existing configuration. For example, if many sysadmins want their
servers configured to track a different expert recommendation, Certbot
could add an option to do so.


Resources for recommendations
-----------------------------

In the course of considering how to handle this issue, we received
recommendations with sources of expert guidance on ciphersuites and other
cryptographic parameters. We're grateful to everyone who contributed
suggestions. The recommendations we received are available under Feedback_.

Certbot users are welcome to review these authorities to
better inform their own cryptographic parameter choices. We also
welcome suggestions of other resources to add to this list. Please keep
in mind that different recommendations may reflect different priorities
or evaluations of trade-offs, especially related to compatibility!


Changing your settings
----------------------

This will probably look something like

.. code-block:: shell

  certbot --cipher-recommendations mozilla-secure
  certbot --cipher-recommendations mozilla-intermediate
  certbot --cipher-recommendations mozilla-old

to track Mozilla's *Secure*, *Intermediate*, or *Old* recommendations,
and

.. code-block:: shell

  certbot --update-ciphers on

to enable updating ciphers with each new Certbot release, or

.. code-block:: shell

  certbot --update-ciphers off

to disable automatic configuration updates. These features have not yet
been implemented and this syntax may change when they are implemented.


TODO
----

The status of this feature is tracked as part of issue #1123 in our
bug tracker.

https://github.com/certbot/certbot/issues/1123

Prior to implementation of #1123, the client does not actually modify
ciphersuites (this is intended to be implemented as a "configuration
enhancement", but the only configuration enhancement implemented
so far is redirecting HTTP requests to HTTPS in web servers, the
"redirect" enhancement). The changes here would probably be either a new
"ciphersuite" enhancement in each plugin that provides an installer,
or a family of enhancements, one per selectable ciphersuite configuration.

Feedback
--------
We receive lots of feedback on the type of ciphersuites that Let's Encrypt supports and list some collated feedback below. This section aims to track suggestions and references that people have offered or identified to improve the ciphersuites that Let's Encrypt enables when configuring TLS on servers.

Because of the Chatham House Rule applicable to some of the discussions, people are *not* individually credited for their suggestions, but most suggestions here were made or found by other people, and I thank them for their contributions.

Some people provided rationale information mostly having to do with compatibility of particular user-agents (especially UAs that don't support ECC, or that don't support DH groups > 1024 bits).  Some ciphersuite configurations have been chosen to try to increase compatibility with older UAs while allowing newer UAs to negotiate stronger crypto.  For example, some configurations forego forward secrecy entirely for connections from old UAs, like by offering ECDHE and RSA key exchange, but no DHE at all.  (There are UAs that can fail the negotiation completely if a DHE ciphersuite with prime > 1024 bits is offered.)

References
^^^^^^^^^^

RFC 7575
""""""""

IETF has published a BCP document, RFC 7525, "Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)"

https://datatracker.ietf.org/doc/rfc7525/

BetterCrypto.org
""""""""""""""""

BetterCrypto.org, a collaboration of mostly European IT security experts, has published a draft paper, "Applied Crypto Hardening"

https://bettercrypto.org/static/applied-crypto-hardening.pdf

FF-DHE Internet-Draft
"""""""""""""""""""""

Gillmor's Internet-Draft "Negotiated Discrete Log Diffie-Hellman Ephemeral Parameters for TLS" is being developed at the IETF TLS WG.  It advocates using *standardized* DH groups in all cases, not individually-chosen ones (mostly because of the Triple Handshake attack which can involve maliciously choosing invalid DH groups).  The draft provides a list of recommended groups, with primes beginning at 2048 bits and going up from there.  It also has a new protocol mechanism for agreeing to use these groups, with the possibility of backwards compatibility (and use of weaker DH groups) for older clients and servers that don't know about this mechanism.

https://tools.ietf.org/html/draft-ietf-tls-negotiated-ff-dhe-10

Mozilla
"""""""

Mozilla's general server configuration guidance is available at https://wiki.mozilla.org/Security/Server_Side_TLS

Mozilla has also produced a configuration generator: https://mozilla.github.io/server-side-tls/ssl-config-generator/

Dutch National Cyber Security Centre
""""""""""""""""""""""""""""""""""""

The Dutch National Cyber Security Centre has published guidance on "ICT-beveiligingsrichtlijnen voor Transport Layer Security (TLS)" ("IT Security Guidelines for Transport Layer Security (TLS)").  These are available only in Dutch at

https://www.ncsc.nl/dienstverlening/expertise-advies/kennisdeling/whitepapers/ict-beveiligingsrichtlijnen-voor-transport-layer-security-tls.html

I have access to an English-language summary of the recommendations.

Keylength.com
"""""""""""""

Damien Giry collects recommendations by academic researchers and standards organizations about keylengths for particular cryptoperiods, years, or security levels.  The keylength recommendations of the various sources are summarized in a chart.  This site has been updated over time and includes expert guidance from eight sources published between 2000 and 2017.

http://www.keylength.com/

NIST
""""
NISA published its "NIST Special Publication 800-52 Revision 1: Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations"

http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r1.pdf

and its "NIST Special Publication 800-57: Recommendation for Key Management – Part 1: General (Revision 3)"

http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf

ENISA
"""""

ENISA published its "Algorithms, Key Sizes and Parameters Report - 2013"

https://www.enisa.europa.eu/activities/identity-and-trust/library/deliverables/algorithms-key-sizes-and-parameters-report

WeakDH/Logjam
^^^^^^^^^^^^^

The WeakDH/Logjam research has thrown into question the safety of some existing practice using DH ciphersuites, especially the use of standardized groups with a prime ≤ 1024 bits.  The authors provided detailed guidance, including ciphersuite lists, at

https://weakdh.org/sysadmin.html

These lists may have been derived from Mozilla's recommendations.
One of the authors clarified his view of the priorities for various changes as a result of the research at

https://www.ietf.org/mail-archive/web/tls/current/msg16496.html

In particular, he supports ECDHE and also supports the use of the standardized groups in the FF-DHE Internet-Draft mentioned above (which isn't clear from the group's original recommendations).

Particular sites' opinions or configurations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Amazon ELB
""""""""""

Amazon ELB explains its current ciphersuite choices at

https://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-table.html

U.S. Government 18F
"""""""""""""""""""

The 18F site (https://18f.gsa.gov/) is using 

::

    ssl_ciphers 'kEECDH+ECDSA+AES128 kEECDH+ECDSA+AES256 kEECDH+AES128 kEECDH+AES256 kEDH+AES128 kEDH+AES256 DES-CBC3-SHA +SHA !aNULL !eNULL !LOW !MD5 !EXP !DSS !PSK !SRP !kECDH !CAMELLIA !RC4 !SEED';

Duraconf
""""""""

The Duraconf project collects particular configuration files, with an apparent focus on avoiding the use of obsolete symmetric ciphers and hash functions, and favoring forward secrecy while not requiring it.

https://github.com/ioerror/duraconf

Site scanning or rating tools
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Qualys SSL Labs
"""""""""""""""

Qualys offers the best-known TLS security scanner, maintained by Ivan Ristić.

https://www.ssllabs.com/

Dutch NCSC
""""""""""

The Dutch NCSC, mentioned above, has also made available its own site security scanner which indicates how well sites comply with the recommendations.

https://en.internet.nl/

Java compatibility issue
^^^^^^^^^^^^^^^^^^^^^^^^

A lot of backward-compatibility concerns have to do with Java hard-coding DHE primes to a 1024-bit limit, accepting DHE ciphersuites in negotiation, and then aborting the connection entirely if a prime > 1024 bits is presented.  The simple summary is that servers offering a Java-compatible DHE ciphersuite in preference to other Java-compatible ciphersuites, and then presenting a DH group with a prime > 1024 bits, will be completely incompatible with clients running some versions of Java.  (This may also be the case with very old MSIE versions...?)  There are various strategies for dealing with this, and maybe we can document the options here.
