"""Plugin utilities."""
import logging
import os
import re

from certbot import util

logger = logging.getLogger(__name__)

windows_drive_path = re.compile(r'^[A-Z]:\\$')

def get_prefixes(path):
    """Retrieves all possible path prefixes of a path, in descending order
    of length. For instance,
        (linux) /a/b/c/ returns ['/a/b/c/', '/a/b/c', '/a/b', '/a', '/']
        (windows) C:\\a\\b\\c returns ['C:\\a\\b\\c', 'C:\\a\\b', C:\\a]
    :param str path: the path to break into prefixes

    :returns: all possible path prefixes of given path in descending order
    :rtype: `list` of `str`
    """
    prefix = os.path.normpath(path)
    prefixes = []
    while len(prefix) > 0:
        prefixes.append(prefix)
        prefix, _ = os.path.split(prefix)
        # break once we hit '/' or ~ 'C:\'
        if prefix == prefixes[-1] or windows_drive_path.match(prefix):
            break
    return prefixes

def path_surgery(cmd):
    """Attempt to perform PATH surgery to find cmd

    Mitigates https://github.com/certbot/certbot/issues/1833

    :param str cmd: the command that is being searched for in the PATH

    :returns: True if the operation succeeded, False otherwise
    """
    dirs = ("/usr/sbin", "/usr/local/bin", "/usr/local/sbin")
    path = os.environ["PATH"]
    added = []
    for d in dirs:
        if d not in path:
            path += os.pathsep + d
            added.append(d)

    if any(added):
        logger.debug("Can't find %s, attempting PATH mitigation by adding %s",
                     cmd, os.pathsep.join(added))
        os.environ["PATH"] = path

    if util.exe_exists(cmd):
        return True
    else:
        expanded = " expanded" if any(added) else ""
        logger.warning("Failed to find executable %s in%s PATH: %s", cmd,
                       expanded, path)
        return False
