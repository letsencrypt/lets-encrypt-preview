"""
This compat module handles various platform specific calls that do not fall into one
particular category.
"""
import logging
import select
import subprocess
import sys
from typing import Optional
from typing import Tuple

from certbot import errors
from certbot.compat import os

try:
    from pywintypes import error as pywinerror
    from win32com.shell import shell as shellwin32
    from win32console import GetStdHandle
    from win32console import STD_OUTPUT_HANDLE
    POSIX_MODE = False
except ImportError:  # pragma: no cover
    POSIX_MODE = True


logger = logging.getLogger(__name__)

# For Linux: define OS specific standard binary directories
STANDARD_BINARY_DIRS = ["/usr/sbin", "/usr/local/bin", "/usr/local/sbin"] if POSIX_MODE else []


def raise_for_non_administrative_windows_rights() -> None:
    """
    On Windows, raise if current shell does not have the administrative rights.
    Do nothing on Linux.

    :raises .errors.Error: If the current shell does not have administrative rights on Windows.
    """
    if not POSIX_MODE and shellwin32.IsUserAnAdmin() == 0:  # pragma: no cover
        raise errors.Error('Error, certbot must be run on a shell with administrative rights.')


def prepare_virtual_console() -> None:
    """
    On Windows, ensure that Console Virtual Terminal Sequences are enabled.

    """
    if POSIX_MODE:
        return

    # https://docs.microsoft.com/en-us/windows/console/setconsolemode
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

    # stdout/stderr will be the same console screen buffer, but this could return None or raise
    try:
        h = GetStdHandle(STD_OUTPUT_HANDLE)
        if h:
            h.SetConsoleMode(h.GetConsoleMode() | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except pywinerror:
        logger.debug("Failed to set console mode", exc_info=True)


def readline_with_timeout(timeout: float, prompt: Optional[str]) -> str:
    """
    Read user input to return the first line entered, or raise after specified timeout.

    :param float timeout: The timeout in seconds given to the user.
    :param str prompt: The prompt message to display to the user.

    :returns: The first line entered by the user.
    :rtype: str

    """
    try:
        # Linux specific
        #
        # Call to select can only be done like this on UNIX
        rlist, _, _ = select.select([sys.stdin], [], [], timeout)
        if not rlist:
            raise errors.Error(
                "Timed out waiting for answer to prompt '{0}'".format(prompt if prompt else ""))
        return rlist[0].readline()
    except OSError:
        # Windows specific
        #
        # No way with select to make a timeout to the user input on Windows,
        # as select only supports socket in this case.
        # So no timeout on Windows for now.
        return sys.stdin.readline()


WINDOWS_DEFAULT_FOLDERS = {
    'config': 'C:\\Certbot',
    'work': 'C:\\Certbot\\lib',
    'logs': 'C:\\Certbot\\log',
}
LINUX_DEFAULT_FOLDERS = {
    'config': '/etc/letsencrypt',
    'work': '/var/lib/letsencrypt',
    'logs': '/var/log/letsencrypt',
}


def get_default_folder(folder_type: str) -> str:
    """
    Return the relevant default folder for the current OS

    :param str folder_type: The type of folder to retrieve (config, work or logs)

    :returns: The relevant default folder.
    :rtype: str

    """
    if os.name != 'nt':
        # Linux specific
        return LINUX_DEFAULT_FOLDERS[folder_type]
    # Windows specific
    return WINDOWS_DEFAULT_FOLDERS[folder_type]


def underscores_for_unsupported_characters_in_path(path: str) -> str:
    """
    Replace unsupported characters in path for current OS by underscores.
    :param str path: the path to normalize
    :return: the normalized path
    :rtype: str
    """
    if os.name != 'nt':
        # Linux specific
        return path

    # Windows specific
    drive, tail = os.path.splitdrive(path)
    return drive + tail.replace(':', '_')


def execute_command_status(cmd_name: str, shell_cmd: str,
                           env: Optional[dict] = None) -> Tuple[int, str, str]:
    """
    Run a command:
        - on Linux command will be run by the standard shell selected with
          subprocess.run(shell=True)
        - on Windows command will be run in a Powershell shell

    This function returns the exit code, and does not log the result and output
    of the command.

    :param str cmd_name: the user facing name of the hook being run
    :param str shell_cmd: shell command to execute
    :param dict env: environ to pass into subprocess.run

    :returns: `tuple` (`int` returncode, `str` stderr, `str` stdout)
    """
    logger.info("Running %s command: %s", cmd_name, shell_cmd)

    if POSIX_MODE:
        proc = subprocess.run(shell_cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True,
                              check=False, env=env)
    else:
        line = ['powershell.exe', '-Command', shell_cmd]
        proc = subprocess.run(line, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, check=False, env=env)

    # universal_newlines causes stdout and stderr to be str objects instead of
    # bytes in Python 3
    out, err = proc.stdout, proc.stderr
    return proc.returncode, err, out
