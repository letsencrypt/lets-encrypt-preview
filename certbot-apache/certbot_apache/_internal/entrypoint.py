""" Entry point for Apache Plugin """
from distutils.version import LooseVersion

import logging

from certbot import util
from certbot_apache._internal import configurator
from certbot_apache._internal import override_arch
from certbot_apache._internal import override_centos
from certbot_apache._internal import override_darwin
from certbot_apache._internal import override_debian
from certbot_apache._internal import override_fedora
from certbot_apache._internal import override_gentoo
from certbot_apache._internal import override_suse
from certbot_apache._internal import override_void

OVERRIDE_CLASSES = {
    "arch": override_arch.ArchConfigurator,
    "cloudlinux": override_centos.CentOSConfigurator,
    "darwin": override_darwin.DarwinConfigurator,
    "debian": override_debian.DebianConfigurator,
    "ubuntu": override_debian.DebianConfigurator,
    "centos": override_centos.CentOSConfigurator,
    "centos linux": override_centos.CentOSConfigurator,
    "fedora_old": override_centos.CentOSConfigurator,
    "fedora": override_fedora.FedoraConfigurator,
    "linuxmint": override_debian.DebianConfigurator,
    "ol": override_centos.CentOSConfigurator,
    "oracle": override_centos.CentOSConfigurator,
    "redhatenterpriseserver": override_centos.CentOSConfigurator,
    "red hat enterprise linux server": override_centos.CentOSConfigurator,
    "rhel": override_centos.CentOSConfigurator,
    "amazon": override_centos.CentOSConfigurator,
    "gentoo": override_gentoo.GentooConfigurator,
    "gentoo base system": override_gentoo.GentooConfigurator,
    "opensuse": override_suse.OpenSUSEConfigurator,
    "suse": override_suse.OpenSUSEConfigurator,
    "sles": override_suse.OpenSUSEConfigurator,
    "scientific": override_centos.CentOSConfigurator,
    "scientific linux": override_centos.CentOSConfigurator,
    "void": override_void.VoidConfigurator,
}


def get_configurator():
    """ Get correct configurator class based on the OS fingerprint """
    logger = logging.getLogger(__name__)
    os_name, os_version = util.get_os_info()
    os_name = os_name.lower()
    override_class = None
    logger.info("OS identified and as: %s", os_name)
    # Special case for older Fedora versions
    if os_name == 'fedora' and LooseVersion(os_version) < LooseVersion('29'):
        os_name = 'fedora_old'

    try:
        override_class = OVERRIDE_CLASSES[os_name]
        logger.info("Configuration for the OS successfully identified")
    except KeyError:
        # OS not found in the list
        logger.warning("OS not found in the list, beginning to try to find a similar OS")
        os_like = util.get_systemd_os_like()
        if os_like:
            for os_name in os_like:
                if os_name in OVERRIDE_CLASSES.keys():
                    override_class = OVERRIDE_CLASSES[os_name]
                    logger.info("OS Identified as: %s, configuration for the OS found", os_name)
        if not override_class:
            # No override class found, return the generic configurator
            override_class = configurator.ApacheConfigurator
            logger.warning("Similar OS not found, default configurator returned."
                "You may need to inspect the defaults")
    return override_class


ENTRYPOINT = get_configurator()
