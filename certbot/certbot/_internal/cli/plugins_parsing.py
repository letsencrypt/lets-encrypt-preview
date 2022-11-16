"""This is a module that handles parsing of plugins for the argument parser"""
from typing import TYPE_CHECKING

from certbot._internal.cli.cli_utils import flag_default
from certbot._internal.plugins import disco

if TYPE_CHECKING:
    from certbot._internal.cli import helpful


def _plugins_parsing(helpful: "helpful.HelpfulArgumentParser",
                     plugins: disco.PluginsRegistry) -> None:
    # It's nuts, but there are two "plugins" topics.  Somehow this works
    helpful.add_group(
        "plugins", description="Plugin Selection: Certbot client supports an "
        "extensible plugins architecture. See '%(prog)s plugins' for a "
        "list of all installed plugins and their names. You can force "
        "a particular plugin by setting options provided below. Running "
        "--help <plugin_name> will list flags specific to that plugin.")

    helpful.add("plugins", "--configurator", default=flag_default("configurator"),
                help="Name of the plugin that is both an authenticator and an installer."
                " Should not be used together with --authenticator or --installer. "
                "(default: Ask)")
    helpful.add("plugins", "-a", "--authenticator", default=flag_default("authenticator"),
                help="Authenticator plugin name.")
    helpful.add("plugins", "-i", "--installer", default=flag_default("installer"),
                help="Installer plugin name (also used to find domains).")
    helpful.add(["plugins", "certonly", "run", "install"],
                "--apache", action="store_true", default=flag_default("apache"),
                help="Obtain and install certificates using Apache")
    helpful.add(["plugins", "certonly", "run", "install"],
                "--nginx", action="store_true", default=flag_default("nginx"),
                help="Obtain and install certificates using Nginx")
    helpful.add(["plugins", "certonly"], "--standalone", action="store_true",
                default=flag_default("standalone"),
                help='Obtain certificates using a "standalone" webserver.')
    helpful.add(["plugins", "certonly"], "--manual", action="store_true",
                default=flag_default("manual"),
                help="Provide laborious manual instructions for obtaining a certificate")
    helpful.add(["plugins", "certonly"], "--webroot", action="store_true",
                default=flag_default("webroot"),
                help="Obtain certificates by placing files in a webroot directory.")
    helpful.add(["plugins", "certonly"], "--dns-cloudflare", action="store_true",
                default=flag_default("dns_cloudflare"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using Cloudflare for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-digitalocean", action="store_true",
                default=flag_default("dns_digitalocean"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using DigitalOcean for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-dnsimple", action="store_true",
                default=flag_default("dns_dnsimple"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using DNSimple for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-dnsmadeeasy", action="store_true",
                default=flag_default("dns_dnsmadeeasy"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using DNS Made Easy for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-gehirn", action="store_true",
                default=flag_default("dns_gehirn"),
                help=("Obtain certificates using a DNS TXT record "
                      "(if you are using Gehirn Infrastructure Service for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-google", action="store_true",
                default=flag_default("dns_google"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using Google Cloud DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-linode", action="store_true",
                default=flag_default("dns_linode"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using Linode for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-luadns", action="store_true",
                default=flag_default("dns_luadns"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using LuaDNS for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-nsone", action="store_true",
                default=flag_default("dns_nsone"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using NS1 for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-ovh", action="store_true",
                default=flag_default("dns_ovh"),
                help=("Obtain certificates using a DNS TXT record (if you are "
                      "using OVH for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-rfc2136", action="store_true",
                default=flag_default("dns_rfc2136"),
                help="Obtain certificates using a DNS TXT record (if you are using BIND for DNS).")
    helpful.add(["plugins", "certonly"], "--dns-route53", action="store_true",
                default=flag_default("dns_route53"),
                help=("Obtain certificates using a DNS TXT record (if you are using Route53 for "
                      "DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-sakuracloud", action="store_true",
                default=flag_default("dns_sakuracloud"),
                help=("Obtain certificates using a DNS TXT record "
                     "(if you are using Sakura Cloud for DNS)."))
    helpful.add(["plugins", "certonly"], "--dns-beget", action="store_true",
                default=flag_default("dns_beget"),
                help=("Obtain certificates using a DNS TXT record "
                     "(if you are using Beget for DNS)."))
    # things should not be reorder past/pre this comment:
    # plugins_group should be displayed in --help before plugin
    # specific groups (so that plugins_group.description makes sense)

    helpful.add_plugin_args(plugins)
