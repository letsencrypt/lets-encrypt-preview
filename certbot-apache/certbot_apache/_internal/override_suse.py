""" Distribution specific override class for OpenSUSE """
import zope.interface

from certbot import interfaces
from certbot_apache._internal import configurator
from certbot_apache._internal.configurator import _OsOptions


@zope.interface.provider(interfaces.IPluginFactory)
class OpenSUSEConfigurator(configurator.ApacheConfigurator):
    """OpenSUSE specific ApacheConfigurator override class"""

    OS_DEFAULTS = _OsOptions(
        vhost_root="/etc/apache2/vhosts.d",
        vhost_files="*.conf",
        ctl="apachectl",
        version_cmd=['apachectl', '-v'],
        restart_cmd=['apachectl', 'graceful'],
        conftest_cmd=['apachectl', 'configtest'],
        enmod="a2enmod",
        dismod="a2dismod",
        challenge_location="/etc/apache2/vhosts.d",
    )
