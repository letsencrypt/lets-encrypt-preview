.. _what:

==================
About Certificates
==================

A public key or digital *certificate* (formerly called an SSL certificate) uses a public key 
and a private key to enable secure communication between a client program (web browser, email client, 
etc.) and a server over an encrypted SSL (secure socket layer) or TLS (transport layer security) connection.
The certificate is used both to encrypt the initial stage of communication (secure key exchange) 
and to identify the server. The certificate
includes information about the key, information about the server identity, and the digital signature
of the certificate issuer. If the issuer is trusted by the software that initiates the communication,
and the signature is valid, then the key can be used to communicate securely with the server identified by 
the certificate. Using a certificate is a good way to prevent "man-in-the-middle" attacks, in which
someone in between you and the server you think you are talking to is able to insert their own (harmful)
content.

You can use Certbot to easily obtain and configure a free certificate from Let's Encrypt, a
joint project of EFF, Mozilla, and many other sponsors.

Certificates and Lineages
=========================

Certbot introduces the concept of a *lineage,* which is a collection of all the versions of a certificate
plus Certbot configuration information maintained for that certificate from
renewal to renewal. Whenever you renew a certificate, Certbot keeps the same configuration unless
you explicitly change it, for example by adding or removing domains. If you add domains, you can 
either add them to an existing lineage or create
a new one. 

See also:
:ref:`updating_certs`
