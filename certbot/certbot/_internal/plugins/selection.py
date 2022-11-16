"""Decide which plugins to use for authentication & installation"""

import logging
from typing import cast
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import Type
from typing import TypeVar

from certbot import configuration
from certbot import errors
from certbot import interfaces
from certbot._internal.plugins import disco
from certbot.compat import os
from certbot.display import util as display_util

logger = logging.getLogger(__name__)


def pick_configurator(config: configuration.NamespaceConfig, default: Optional[str],
                      plugins: disco.PluginsRegistry,
                      question: str = "How would you like to authenticate and install "
                                      "certificates?") -> Optional[interfaces.Plugin]:
    """Pick configurator plugin."""
    return pick_plugin(
        config, default, plugins, question,
        (interfaces.Authenticator, interfaces.Installer))


def pick_installer(config: configuration.NamespaceConfig, default: Optional[str],
                   plugins: disco.PluginsRegistry,
                   question: str = "How would you like to install certificates?"
                   ) -> Optional[interfaces.Installer]:
    """Pick installer plugin."""
    return pick_plugin(config, default, plugins, question, (interfaces.Installer,))


def pick_authenticator(config: configuration.NamespaceConfig, default: Optional[str],
                       plugins: disco.PluginsRegistry,
                       question: str = "How would you "
                                       "like to authenticate with the ACME CA?"
                       ) -> Optional[interfaces.Authenticator]:
    """Pick authentication plugin."""
    return pick_plugin(
        config, default, plugins, question, (interfaces.Authenticator,))


def get_unprepared_installer(config: configuration.NamespaceConfig,
                             plugins: disco.PluginsRegistry) -> Optional[interfaces.Installer]:
    """
    Get an unprepared interfaces.Installer object.

    :param certbot.configuration.NamespaceConfig config: Configuration
    :param certbot._internal.plugins.disco.PluginsRegistry plugins:
        All plugins registered as entry points.

    :returns: Unprepared installer plugin or None
    :rtype: Plugin or None
    """

    _, req_inst = cli_plugin_requests(config)
    if not req_inst:
        return None
    installers = plugins.filter(lambda p_ep: p_ep.check_name(req_inst))
    installers.init(config)
    if len(installers) > 1:
        raise errors.PluginSelectionError(
            "Found multiple installers with the name %s, Certbot is unable to "
            "determine which one to use. Skipping." % req_inst)
    if installers:
        inst = list(installers.values())[0]
        logger.debug("Selecting plugin: %s", inst)
        return inst.init(config)
    raise errors.PluginSelectionError(
        "Could not select or initialize the requested installer %s." % req_inst)


P = TypeVar('P', bound=interfaces.Plugin)


def pick_plugin(config: configuration.NamespaceConfig, default: Optional[str],
                plugins: disco.PluginsRegistry, question: str,
                ifaces: Iterable[Type]) -> Optional[P]:
    """Pick plugin.

    :param certbot.configuration.NamespaceConfig config: Configuration
    :param str default: Plugin name supplied by user or ``None``.
    :param certbot._internal.plugins.disco.PluginsRegistry plugins:
        All plugins registered as entry points.
    :param str question: Question to be presented to the user in case
        multiple candidates are found.
    :param list ifaces: Interfaces that plugins must provide.

    :returns: Initialized plugin.
    :rtype: Plugin

    """
    if default is not None:
        # throw more UX-friendly error if default not in plugins
        filtered = plugins.filter(lambda p_ep: p_ep.check_name(default))
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
    filtered.prepare()
    prepared = filtered.available()

    if len(prepared) > 1:
        logger.debug("Multiple candidate plugins: %s", prepared)
        plugin_ep1 = choose_plugin(list(prepared.values()), question)
        if plugin_ep1 is None:
            return None
        return cast(P, plugin_ep1.init())
    elif len(prepared) == 1:
        plugin_ep2 = list(prepared.values())[0]
        logger.debug("Single candidate plugin: %s", plugin_ep2)
        if plugin_ep2.misconfigured:
            return None
        return plugin_ep2.init()
    else:
        logger.debug("No candidate plugin")
        return None


def choose_plugin(prepared: List[disco.PluginEntryPoint],
                  question: str) -> Optional[disco.PluginEntryPoint]:
    """Allow the user to choose their plugin.

    :param list prepared: List of `~.PluginEntryPoint`.
    :param str question: Question to be presented to the user.

    :returns: Plugin entry point chosen by the user.
    :rtype: `~.PluginEntryPoint`

    """
    opts = [plugin_ep.description_with_name +
            (" [Misconfigured]" if plugin_ep.misconfigured else "")
            for plugin_ep in prepared]

    while True:
        code, index = display_util.menu(question, opts, force_interactive=True)

        if code == display_util.OK:
            plugin_ep = prepared[index]
            if plugin_ep.misconfigured:
                display_util.notification(
                    "The selected plugin encountered an error while parsing "
                    "your server configuration and cannot be used. The error "
                    "was:\n\n{0}".format(plugin_ep.prepare()), pause=False)
            else:
                return plugin_ep
        else:
            return None


noninstaller_plugins = ["webroot", "manual", "standalone", "dns-cloudflare",
                        "dns-digitalocean", "dns-dnsimple", "dns-dnsmadeeasy", "dns-gehirn",
                        "dns-google", "dns-linode", "dns-luadns", "dns-nsone", "dns-ovh",
                        "dns-rfc2136", "dns-route53", "dns-sakuracloud", "dns-beget"]


def record_chosen_plugins(config: configuration.NamespaceConfig, plugins: disco.PluginsRegistry,
                          auth: Optional[interfaces.Authenticator],
                          inst: Optional[interfaces.Installer]) -> None:
    """Update the config entries to reflect the plugins we actually selected."""
    config.authenticator = None
    if auth:
        auth_ep = plugins.find_init(auth)
        if auth_ep:
            config.authenticator = auth_ep.name
    config.installer = None
    if inst:
        inst_ep = plugins.find_init(inst)
        if inst_ep:
            config.installer = inst_ep.name
    logger.info("Plugins selected: Authenticator %s, Installer %s",
                config.authenticator, config.installer)


def choose_configurator_plugins(config: configuration.NamespaceConfig,
                                plugins: disco.PluginsRegistry,
                                verb: str) -> Tuple[Optional[interfaces.Installer],
                                                    Optional[interfaces.Authenticator]]:
    """
    Figure out which configurator we're going to use, modifies
    config.authenticator and config.installer strings to reflect that choice if
    necessary.

    :raises errors.PluginSelectionError if there was a problem

    :returns: tuple of (`Installer` or None, `Authenticator` or None)
    :rtype: tuple
    """

    req_auth, req_inst = cli_plugin_requests(config)
    installer_question = ""

    if verb == "enhance":
        installer_question = ("Which installer would you like to use to "
                              "configure the selected enhancements?")

    # Which plugins do we need?
    if verb == "run":
        need_inst = need_auth = True
        from certbot._internal.cli import cli_command
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
    elif verb in ("install", "enhance"):
        need_inst = True
        if config.authenticator:
            logger.warning("Specifying an authenticator doesn't make sense when "
                           "running Certbot with verb \"%s\"", verb)
    # Try to meet the user's request and/or ask them to pick plugins
    authenticator: Optional[interfaces.Authenticator] = None
    installer: Optional[interfaces.Installer] = None
    if verb == "run" and req_auth == req_inst:
        # Unless the user has explicitly asked for different auth/install,
        # only consider offering a single choice
        configurator = pick_configurator(config, req_inst, plugins)
        authenticator = cast(Optional[interfaces.Authenticator], configurator)
        installer = cast(Optional[interfaces.Installer], configurator)
    else:
        if need_inst or req_inst:
            installer = pick_installer(config, req_inst, plugins, installer_question)
        if need_auth:
            authenticator = pick_authenticator(config, req_auth, plugins)

    # Report on any failures
    if need_inst and not installer:
        diagnose_configurator_problem("installer", req_inst, plugins)
    if need_auth and not authenticator:
        diagnose_configurator_problem("authenticator", req_auth, plugins)

    # As a special case for certonly, if a user selected apache or nginx, set
    # the relevant installer (unless the user specifically specified no
    # installer or only specified an authenticator on the command line)
    if verb == "certonly" and authenticator is not None:
        # user specified --nginx or --apache on CLI
        selected_configurator = config.nginx or config.apache
        # user didn't request an authenticator, and so interactively chose nginx
        # or apache
        interactively_selected = req_auth is None and authenticator.name in ("nginx", "apache")

        if selected_configurator or interactively_selected:
            installer = cast(Optional[interfaces.Installer], authenticator)
    logger.debug("Selected authenticator %s and installer %s", authenticator, installer)

    record_chosen_plugins(config, plugins, authenticator, installer)
    return installer, authenticator


def set_configurator(previously: Optional[str], now: Optional[str]) -> Optional[str]:
    """
    Setting configurators multiple ways is okay, as long as they all agree
    :param str previously: previously identified request for the installer/authenticator
    :param str now: the request currently being processed
    """
    if not now:
        # we're not actually setting anything
        return previously
    if previously:
        if previously != now:
            msg = "Too many flags setting configurators/installers/authenticators {0} -> {1}"
            raise errors.PluginSelectionError(msg.format(repr(previously), repr(now)))
    return now


def cli_plugin_requests(config: configuration.NamespaceConfig
                        ) -> Tuple[Optional[str], Optional[str]]:
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
    if config.dns_digitalocean:
        req_auth = set_configurator(req_auth, "dns-digitalocean")
    if config.dns_dnsimple:
        req_auth = set_configurator(req_auth, "dns-dnsimple")
    if config.dns_dnsmadeeasy:
        req_auth = set_configurator(req_auth, "dns-dnsmadeeasy")
    if config.dns_gehirn:
        req_auth = set_configurator(req_auth, "dns-gehirn")
    if config.dns_google:
        req_auth = set_configurator(req_auth, "dns-google")
    if config.dns_linode:
        req_auth = set_configurator(req_auth, "dns-linode")
    if config.dns_luadns:
        req_auth = set_configurator(req_auth, "dns-luadns")
    if config.dns_nsone:
        req_auth = set_configurator(req_auth, "dns-nsone")
    if config.dns_ovh:
        req_auth = set_configurator(req_auth, "dns-ovh")
    if config.dns_rfc2136:
        req_auth = set_configurator(req_auth, "dns-rfc2136")
    if config.dns_route53:
        req_auth = set_configurator(req_auth, "dns-route53")
    if config.dns_sakuracloud:
        req_auth = set_configurator(req_auth, "dns-sakuracloud")
    if config.dns_beget:
        req_auth = set_configurator(req_auth, "dns-beget")
    logger.debug("Requested authenticator %s and installer %s", req_auth, req_inst)
    return req_auth, req_inst


def diagnose_configurator_problem(cfg_type: str, requested: Optional[str],
                                  plugins: disco.PluginsRegistry) -> None:
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
        from certbot._internal.cli import cli_command
        msg = ('Certbot doesn\'t know how to automatically configure the web '
          'server on this system. However, it can still get a certificate for '
          'you. Please run "{0} certonly" to do so. You\'ll need to '
          'manually configure your web server to use the resulting '
          'certificate.').format(cli_command)
    else:
        msg = "{0} could not be determined or is not installed".format(cfg_type)
    raise errors.PluginSelectionError(msg)
