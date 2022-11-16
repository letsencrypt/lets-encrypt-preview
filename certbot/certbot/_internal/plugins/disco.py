"""Utilities for plugins discovery and selection."""
import itertools
import logging
import sys
from typing import Callable
from typing import cast
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Mapping
from typing import Optional
from typing import Type
from typing import Union

import pkg_resources

from certbot import configuration
from certbot import errors
from certbot import interfaces
from certbot._internal import constants
from certbot.compat import os
from certbot.errors import Error

logger = logging.getLogger(__name__)

PREFIX_FREE_DISTRIBUTIONS = [
    "certbot",
    "certbot-apache",
    "certbot-dns-cloudflare",
    "certbot-dns-digitalocean",
    "certbot-dns-dnsimple",
    "certbot-dns-dnsmadeeasy",
    "certbot-dns-gehirn",
    "certbot-dns-google",
    "certbot-dns-linode",
    "certbot-dns-luadns",
    "certbot-dns-nsone",
    "certbot-dns-ovh",
    "certbot-dns-rfc2136",
    "certbot-dns-route53",
    "certbot-dns-sakuracloud",
    "certbot-dns-beget",
    "certbot-nginx",
]
"""Distributions for which prefix will be omitted."""


class PluginEntryPoint:
    """Plugin entry point."""

    # this object is mutable, don't allow it to be hashed!
    __hash__ = None  # type: ignore

    def __init__(self, entry_point: pkg_resources.EntryPoint) -> None:
        self.name = self.entry_point_to_plugin_name(entry_point)
        self.plugin_cls: Type[interfaces.Plugin] = entry_point.load()
        self.entry_point = entry_point
        self.warning_message: Optional[str] = None
        self._initialized: Optional[interfaces.Plugin] = None
        self._prepared: Optional[Union[bool, Error]] = None

    def check_name(self, name: Optional[str]) -> bool:
        """Check if the name refers to this plugin."""
        if name == self.name:
            return True
        return False

    @classmethod
    def entry_point_to_plugin_name(cls, entry_point: pkg_resources.EntryPoint) -> str:
        """Unique plugin name for an ``entry_point``"""
        return entry_point.name

    @property
    def description(self) -> str:
        """Description of the plugin."""
        return self.plugin_cls.description

    @property
    def description_with_name(self) -> str:
        """Description with name. Handy for UI."""
        return "{0} ({1})".format(self.description, self.name)

    @property
    def long_description(self) -> str:
        """Long description of the plugin."""
        return getattr(self.plugin_cls, "long_description", self.description)

    @property
    def hidden(self) -> bool:
        """Should this plugin be hidden from UI?"""
        return getattr(self.plugin_cls, "hidden", False)

    def ifaces(self, *ifaces_groups: Iterable[Type]) -> bool:
        """Does plugin implements specified interface groups?"""
        return not ifaces_groups or any(
            all(issubclass(self.plugin_cls, iface)
                for iface in ifaces)
            for ifaces in ifaces_groups)

    @property
    def initialized(self) -> bool:
        """Has the plugin been initialized already?"""
        return self._initialized is not None

    def init(self, config: Optional[configuration.NamespaceConfig] = None) -> interfaces.Plugin:
        """Memoized plugin initialization."""
        if not self._initialized:
            self.entry_point.require()  # fetch extras!
            # For plugins implementing ABCs Plugin, Authenticator or Installer, the following
            # line will raise an exception if some implementations of abstract methods are missing.
            self._initialized = self.plugin_cls(config, self.name)
        return self._initialized

    @property
    def prepared(self) -> bool:
        """Has the plugin been prepared already?"""
        if not self.initialized:
            logger.debug(".prepared called on uninitialized %r", self)
        return self._prepared is not None

    def prepare(self) -> Union[bool, Error]:
        """Memoized plugin preparation."""
        if self._initialized is None:
            raise ValueError("Plugin is not initialized.")
        if self._prepared is None:
            try:
                self._initialized.prepare()
            except errors.MisconfigurationError as error:
                logger.debug("Misconfigured %r: %s", self, error, exc_info=True)
                self._prepared = error
            except errors.NoInstallationError as error:
                logger.debug(
                    "No installation (%r): %s", self, error, exc_info=True)
                self._prepared = error
            except errors.PluginError as error:
                logger.debug("Other error:(%r): %s", self, error, exc_info=True)
                self._prepared = error
            else:
                self._prepared = True
        # Mypy seems to fail to understand the actual type here, let's help it.
        return cast(Union[bool, Error], self._prepared)

    @property
    def misconfigured(self) -> bool:
        """Is plugin misconfigured?"""
        return isinstance(self._prepared, errors.MisconfigurationError)

    @property
    def problem(self) -> Optional[Exception]:
        """Return the Exception raised during plugin setup, or None if all is well"""
        if isinstance(self._prepared, Exception):
            return self._prepared
        return None

    @property
    def available(self) -> bool:
        """Is plugin available, i.e. prepared or misconfigured?"""
        return self._prepared is True or self.misconfigured

    def __repr__(self) -> str:
        return "PluginEntryPoint#{0}".format(self.name)

    def __str__(self) -> str:
        lines = [
            "* {0}".format(self.name),
            "Description: {0}".format(self.plugin_cls.description),
            "Interfaces: {0}".format(", ".join(
                cls.__name__ for cls in self.plugin_cls.mro()
                if cls.__module__ == 'certbot.interfaces'
            )),
            "Entry point: {0}".format(self.entry_point),
        ]

        if self.initialized:
            lines.append("Initialized: {0}".format(self.init()))
            if self.prepared:
                lines.append("Prep: {0}".format(self.prepare()))

        return "\n".join(lines)


class PluginsRegistry(Mapping):
    """Plugins registry."""

    def __init__(self, plugins: Mapping[str, PluginEntryPoint]) -> None:
        # plugins are sorted so the same order is used between runs.
        # This prevents deadlock caused by plugins acquiring a lock
        # and ensures at least one concurrent Certbot instance will run
        # successfully.
        self._plugins = dict(sorted(plugins.items()))

    @classmethod
    def find_all(cls) -> 'PluginsRegistry':
        """Find plugins using setuptools entry points."""
        plugins: Dict[str, PluginEntryPoint] = {}
        plugin_paths_string = os.getenv('CERTBOT_PLUGIN_PATH')
        plugin_paths = plugin_paths_string.split(':') if plugin_paths_string else []
        # XXX should ensure this only happens once
        sys.path.extend(plugin_paths)
        for plugin_path in plugin_paths:
            pkg_resources.working_set.add_entry(plugin_path)
        entry_points = itertools.chain(
            pkg_resources.iter_entry_points(
                constants.SETUPTOOLS_PLUGINS_ENTRY_POINT),
            pkg_resources.iter_entry_points(
                constants.OLD_SETUPTOOLS_PLUGINS_ENTRY_POINT),)
        for entry_point in entry_points:
            cls._load_entry_point(entry_point, plugins)

        return cls(plugins)

    @classmethod
    def _load_entry_point(cls, entry_point: pkg_resources.EntryPoint,
                          plugins: Dict[str, PluginEntryPoint]) -> None:
        plugin_ep = PluginEntryPoint(entry_point)
        if plugin_ep.name in plugins:
            other_ep = plugins[plugin_ep.name]
            plugin1 = plugin_ep.entry_point.dist.key if plugin_ep.entry_point.dist else "unknown"
            plugin2 = other_ep.entry_point.dist.key if other_ep.entry_point.dist else "unknown"
            raise Exception("Duplicate plugin name {0} from {1} and {2}.".format(
                plugin_ep.name, plugin1, plugin2))
        if issubclass(plugin_ep.plugin_cls, interfaces.Plugin):
            plugins[plugin_ep.name] = plugin_ep
        else:  # pragma: no cover
            logger.warning(
                "%r does not inherit from Plugin, skipping", plugin_ep)

    def __getitem__(self, name: str) -> PluginEntryPoint:
        return self._plugins[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._plugins)

    def __len__(self) -> int:
        return len(self._plugins)

    def init(self, config: configuration.NamespaceConfig) -> List[interfaces.Plugin]:
        """Initialize all plugins in the registry."""
        return [plugin_ep.init(config) for plugin_ep
                in self._plugins.values()]

    def filter(self, pred: Callable[[PluginEntryPoint], bool]) -> "PluginsRegistry":
        """Filter plugins based on predicate."""
        return type(self)({name: plugin_ep for name, plugin_ep
                           in self._plugins.items() if pred(plugin_ep)})

    def visible(self) -> "PluginsRegistry":
        """Filter plugins based on visibility."""
        return self.filter(lambda plugin_ep: not plugin_ep.hidden)

    def ifaces(self, *ifaces_groups: Iterable[Type]) -> "PluginsRegistry":
        """Filter plugins based on interfaces."""
        return self.filter(lambda p_ep: p_ep.ifaces(*ifaces_groups))

    def prepare(self) -> List[Union[bool, Error]]:
        """Prepare all plugins in the registry."""
        return [plugin_ep.prepare() for plugin_ep in self._plugins.values()]

    def available(self) -> "PluginsRegistry":
        """Filter plugins based on availability."""
        return self.filter(lambda p_ep: p_ep.available)
        # successfully prepared + misconfigured

    def find_init(self, plugin: interfaces.Plugin) -> Optional[PluginEntryPoint]:
        """Find an initialized plugin.

        This is particularly useful for finding a name for the plugin::

          # plugin is an instance providing Plugin, initialized
          # somewhere else in the code
          plugin_registry.find_init(plugin).name

        Returns ``None`` if ``plugin`` is not found in the registry.

        """
        # use list instead of set because PluginEntryPoint is not hashable
        candidates = [plugin_ep for plugin_ep in self._plugins.values()
                      if plugin_ep.initialized and plugin_ep.init() is plugin]
        assert len(candidates) <= 1
        if candidates:
            return candidates[0]
        return None

    def __repr__(self) -> str:
        return "{0}({1})".format(
            self.__class__.__name__, ','.join(
                repr(p_ep) for p_ep in self._plugins.values()))

    def __str__(self) -> str:
        if not self._plugins:
            return "No plugins"
        return "\n\n".join(str(p_ep) for p_ep in self._plugins.values())
