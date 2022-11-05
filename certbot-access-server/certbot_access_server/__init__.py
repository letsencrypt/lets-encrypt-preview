"""
The `~certbot_access_server.installer_access_server` plugin automates the installation
of obtained certificates to OpenVPN Access Server by communicating with it
through XML-RPC calls.


Named Arguments
---------------

==========================================  ===================================
``--as-installer-socket``                   Path to the socket OpenVPN Access Server
                                            is listening at
                                            (Default:
                                            /usr/local/openvpn_as/etc/sock/sagent.localroot)
``--as-installer-path-only``                Set path to certificate to
                                            OpenVPN Access Server instead of
                                            certificate itself
                                            (Default: false)
==========================================  ===================================
"""
