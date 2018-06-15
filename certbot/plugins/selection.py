"""Decide which plugins to use for authentication & installation"""
from __future__ import print_function

import os
import logging

import six
import zope.component

from certbot import errors
from certbot import interfaces

from certbot.display import util as display_util

logger = logging.getLogger(__name__)
z_util = zope.component.getUtility

def pick_configurator(
        config, default, plugins,
        question="How would you like to authenticate and install "
                 "certificates?"):
    """Pick configurator plugin."""
    return pick_plugin(
        config, default, plugins, question,
        (interfaces.IAuthenticator, interfaces.IInstaller))


def pick_installer(config, default, plugins,
                   question="How would you like to install certificates?"):
    """Pick installer plugin."""
    return pick_plugin(
        config, default, plugins, question, (interfaces.IInstaller,))


def pick_authenticator(
        config, default, plugins, question="How would you "
        "like to authenticate with the ACME CA?"):
    """Pick authentication plugin."""
    return pick_plugin(
        config, default, plugins, question, (interfaces.IAuthenticator,))


def pick_plugin(config, default, plugins, question, ifaces):
    """Pick plugin.

    :param certbot.interfaces.IConfig: Configuration
    :param str default: Plugin name supplied by user or ``None``.
    :param certbot.plugins.disco.PluginsRegistry plugins:
        All plugins registered as entry points.
    :param str question: Question to be presented to the user in case
        multiple candidates are found.
    :param list ifaces: Interfaces that plugins must provide.

    :returns: Initialized plugin.
    :rtype: IPlugin

    """
    if default is not None:
        # throw more UX-friendly error if default not in plugins
        filtered = plugins.filter(lambda p_ep: p_ep.name == default)
    else:
        if config.noninteractive_mode:
            # it's really bad to auto-select the single available plugin in
            # non-interactive mode, because an update could later add a second
            # available plugin
            raise errors.MissingCommandlineFlag(
                "Missing command line flags. For non-interactive execution, "
                "you will need to specify a plugin on the command line.  Run "
                "with '--help plugins' to see a list of options, and see "
                "https://eff.org/letsencrypt-plugins for more detail on what "
                "the plugins do and how to use them.")

        filtered = plugins.visible().ifaces(ifaces)

    filtered.init(config)
    verified = filtered.verify(ifaces)
    verified.prepare()
    prepared = verified.available()

    if len(prepared) > 1:
        logger.debug("Multiple candidate plugins: %s", prepared)
        plugin_ep = choose_plugin(list(six.itervalues(prepared)), question)
        if plugin_ep is None:
            return None
        else:
            return plugin_ep.init()
    elif len(prepared) == 1:
        plugin_ep = list(prepared.values())[0]
        logger.debug("Single candidate plugin: %s", plugin_ep)
        if plugin_ep.misconfigured:
            return None
        return plugin_ep.init()
    else:
        logger.debug("No candidate plugin")
        return None


def choose_plugin(prepared, question):
    """Allow the user to choose their plugin.

    :param list prepared: List of `~.PluginEntryPoint`.
    :param str question: Question to be presented to the user.

    :returns: Plugin entry point chosen by the user.
    :rtype: `~.PluginEntryPoint`

    """
    opts = [plugin_ep.description_with_name +
            (" [Misconfigured]" if plugin_ep.misconfigured else "")
            for plugin_ep in prepared]
    names = set(plugin_ep.name for plugin_ep in prepared)

    while True:
        disp = z_util(interfaces.IDisplay)
        if "CERTBOT_AUTO" in os.environ and names == set(("apache", "nginx")):
            # The possibility of being offered exactly apache and nginx here
            # is new interactivity brought by https://github.com/certbot/certbot/issues/4079,
            # so set apache as a default for those kinds of non-interactive use
            # (the user will get a warning to set --non-interactive or --force-interactive)
            apache_idx = [n for n, p in enumerate(prepared) if p.name == "apache"][0]
            code, index = disp.menu(question, opts, default=apache_idx)
        else:
            code, index = disp.menu(question, opts, force_interactive=True)

        if code == display_util.OK:
            plugin_ep = prepared[index]
            if plugin_ep.misconfigured:
                z_util(interfaces.IDisplay).notification(
                    "The selected plugin encountered an error while parsing "
                    "your server configuration and cannot be used. The error "
                    "was:\n\n{0}".format(plugin_ep.prepare()), pause=False)
            else:
                return plugin_ep
        else:
            return None

noninstaller_plugins = ["webroot", "manual", "standalone", "dns-cloudflare", "dns-cloudxns",
                        "dns-digitalocean", "dns-dnsimple", "dns-dnsmadeeasy", "dns-google",
                        "dns-luadns", "dns-nsone", "dns-rackspace", "dns-rfc2136", "dns-route53"]

def record_chosen_plugins(config, plugins, auth, inst):
    "Update the config entries to reflect the plugins we actually selected."
    config.authenticator = plugins.find_init(auth).name if auth else "None"
    config.installer = plugins.find_init(inst).name if inst else "None"
    logger.info("Plugins selected: Authenticator %s, Installer %s",
         config.authenticator, config.installer)


def choose_configurator_plugins(config, plugins, verb):
    # pylint: disable=too-many-branches
    """
    Figure out which configurator we're going to use, modifies
    config.authenticator and config.installer strings to reflect that choice if
    necessary.

    :raises errors.PluginSelectionError if there was a problem

    :returns: (an `IAuthenticator` or None, an `IInstaller` or None)
    :rtype: tuple
    """

    req_auth, req_inst = cli_plugin_requests(config)
    installer_question = None

    if verb == "enhance":
        installer_question = ("Which installer would you like to use to "
                              "configure the selected enhancements?")

    # Which plugins do we need?
    if verb == "run":
        need_inst = need_auth = True
        from certbot.cli import cli_command
        if req_auth in noninstaller_plugins and not req_inst:
            msg = ('With the {0} plugin, you probably want to use the "certonly" command, eg:{1}'
                   '{1}    {2} certonly --{0}{1}{1}'
                   '(Alternatively, add a --installer flag. See https://eff.org/letsencrypt-plugins'
                   '{1} and "--help plugins" for more information.)'.format(
                       req_auth, os.linesep, cli_command))

            raise errors.MissingCommandlineFlag(msg)
    else:
        need_inst = need_auth = False
    if verb == "certonly":
        need_auth = True
    if verb == "install" or verb == "enhance":
        need_inst = True
        if config.authenticator:
            logger.warning("Specifying an authenticator doesn't make sense when "
                           "running Certbot with verb \"%s\"", verb)
    # Try to meet the user's request and/or ask them to pick plugins
    authenticator = installer = None
    if verb == "run" and req_auth == req_inst:
        # Unless the user has explicitly asked for different auth/install,
        # only consider offering a single choice
        authenticator = installer = pick_configurator(config, req_inst, plugins)
    else:
        if need_inst or req_inst:
            installer = pick_installer(config, req_inst, plugins, installer_question)
        if need_auth:
            authenticator = pick_authenticator(config, req_auth, plugins)
    logger.debug("Selected authenticator %s and installer %s", authenticator, installer)

    # Report on any failures
    if need_inst and not installer:
        diagnose_configurator_problem("installer", req_inst, plugins)
    if need_auth and not authenticator:
        diagnose_configurator_problem("authenticator", req_auth, plugins)

    record_chosen_plugins(config, plugins, authenticator, installer)
    return installer, authenticator


def set_configurator(previously, now):
    """
    Setting configurators multiple ways is okay, as long as they all agree
    :param str previously: previously identified request for the installer/authenticator
    :param str requested: the request currently being processed
    """
    if not now:
        # we're not actually setting anything
        return previously
    if previously:
        if previously != now:
            msg = "Too many flags setting configurators/installers/authenticators {0} -> {1}"
            raise errors.PluginSelectionError(msg.format(repr(previously), repr(now)))
    return now


def cli_plugin_requests(config):  # pylint: disable=too-many-branches
    """
    Figure out which plugins the user requested with CLI and config options

    :returns: (requested authenticator string or None, requested installer string or None)
    :rtype: tuple
    """
    req_inst = req_auth = config.configurator
    req_inst = set_configurator(req_inst, config.installer)
    req_auth = set_configurator(req_auth, config.authenticator)

    if config.nginx:
        req_inst = set_configurator(req_inst, "nginx")
        req_auth = set_configurator(req_auth, "nginx")
    if config.apache:
        req_inst = set_configurator(req_inst, "apache")
        req_auth = set_configurator(req_auth, "apache")
    if config.standalone:
        req_auth = set_configurator(req_auth, "standalone")
    if config.webroot:
        req_auth = set_configurator(req_auth, "webroot")
    if config.manual:
        req_auth = set_configurator(req_auth, "manual")
    if config.dns_cloudflare:
        req_auth = set_configurator(req_auth, "dns-cloudflare")
    if config.dns_cloudxns:
        req_auth = set_configurator(req_auth, "dns-cloudxns")
    if config.dns_digitalocean:
        req_auth = set_configurator(req_auth, "dns-digitalocean")
    if config.dns_dnsimple:
        req_auth = set_configurator(req_auth, "dns-dnsimple")
    if config.dns_dnsmadeeasy:
        req_auth = set_configurator(req_auth, "dns-dnsmadeeasy")
    if config.dns_google:
        req_auth = set_configurator(req_auth, "dns-google")
    if config.dns_luadns:
        req_auth = set_configurator(req_auth, "dns-luadns")
    if config.dns_nsone:
        req_auth = set_configurator(req_auth, "dns-nsone")
    if config.dns_rackspace:
        req_auth = set_configurator(req_auth, "dns-rackspace")
    if config.dns_rfc2136:
        req_auth = set_configurator(req_auth, "dns-rfc2136")
    if config.dns_route53:
        req_auth = set_configurator(req_auth, "dns-route53")
    logger.debug("Requested authenticator %s and installer %s", req_auth, req_inst)
    return req_auth, req_inst


def diagnose_configurator_problem(cfg_type, requested, plugins):
    """
    Raise the most helpful error message about a plugin being unavailable

    :param str cfg_type: either "installer" or "authenticator"
    :param str requested: the plugin that was requested
    :param .PluginsRegistry plugins: available plugins

    :raises error.PluginSelectionError: if there was a problem
    """

    if requested:
        if requested not in plugins:
            msg = "The requested {0} plugin does not appear to be installed".format(requested)
        else:
            msg = ("The {0} plugin is not working; there may be problems with "
                   "your existing configuration.\nThe error was: {1!r}"
                   .format(requested, plugins[requested].problem))
    elif cfg_type == "installer":
        from certbot.cli import cli_command
        msg = ('Certbot doesn\'t know how to automatically configure the web '
          'server on this system. However, it can still get a certificate for '
          'you. Please run "{0} certonly" to do so. You\'ll need to '
          'manually configure your web server to use the resulting '
          'certificate.').format(cli_command)
    else:
        msg = "{0} could not be determined or is not installed".format(cfg_type)
    raise errors.PluginSelectionError(msg)
