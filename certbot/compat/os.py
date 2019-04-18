"""
This compat modules is a wrapper of the core os module that forbids usage of specific operations
(eg. chown, chmod, getuid) that would be harmful to the Windows file security model of Certbot.
This module is intended to replace standard os module throughout certbot projects (except acme).
"""
from __future__ import absolute_import

# First round of wrapping: we import statically all public attributes exposed by the os module
# This allows in particular to have pylint, mypy, IDEs be aware that most of os members are
# available in certbot.compat.os.
from os import *  # type: ignore  # pylint: disable=wildcard-import,unused-wildcard-import,redefined-builtin,os-module-forbidden

# Second round of wrapping: we import dynamically all attributes from the os module that have not
# yet been imported by the first round (static import). This covers in particular the case of
# specific python 3.x versions where not all public attributes are in the special __all__ of os,
# and so not in `from os import *`.
import os as std_os  # pylint: disable=os-module-forbidden
import sys as std_sys
ourselves = std_sys.modules[__name__]
for attribute in dir(std_os):
    # Check if the attribute does not already exist in our module. It could be internal attributes
    # of the module (__name__, __doc__), or attributes from standard os already imported with
    # `from os import *`.
    if not hasattr(ourselves, attribute):
        setattr(ourselves, attribute, getattr(std_os, attribute))

# Similar to os.path, allow certbot.compat.os.path to behave as a module
std_sys.modules[__name__ + '.path'] = path

# Clean all remaining importables that are not from the core os module.
del ourselves, std_os, std_sys


# The os.open function on Windows will have the same effect than a bare os.chown towards the given
# mode, and will create a file with the same flaws that what have been described for os.chown.
# So upon file creation, security.take_ownership will be called to ensure current user is the owner
# of the file, and security.chmod will do the same thing than for the modified os.chown.
# Internally, take_ownership will update the existing metdata of the file, to set the current
# username (resolved thanks to win32api module) as the owner of the file.
def open(*unused_args, **unused_kwargs):  # pylint: disable=function-redefined
    """Method os.open() is forbidden"""
    raise RuntimeError('Usage of os.open() is forbidden. '  # pragma: no cover
                       'Use certbot.compat.filesystem.open() instead.')
