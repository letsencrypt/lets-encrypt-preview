"""Test utilities."""
import atexit
from contextlib import ExitStack
import copy
from importlib import reload as reload_module
import importlib.resources
import io
import logging
import multiprocessing
from multiprocessing import synchronize
import shutil
import sys
import tempfile
from typing import Any
from typing import Callable
from typing import cast
from typing import IO
from typing import Iterable
from typing import List
from typing import Optional
from typing import Union
import unittest
from unittest import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
import josepy as jose
from OpenSSL import crypto

from certbot import configuration
from certbot import util
from certbot._internal import constants
from certbot._internal import lock
from certbot._internal import storage
from certbot._internal.display import obj as display_obj
from certbot.compat import filesystem
from certbot.compat import os
from certbot.display import util as display_util
from certbot.plugins import common


class DummyInstaller(common.Installer):
    """Dummy installer plugin for test purpose."""
    def get_all_names(self) -> Iterable[str]:
        return []

    def deploy_cert(self, domain: str, cert_path: str, key_path: str, chain_path: str,
                    fullchain_path: str) -> None:
        pass

    def enhance(self, domain: str, enhancement: str,
                options: Optional[Union[List[str], str]] = None) -> None:
        pass

    def supported_enhancements(self) -> List[str]:
        return []

    def save(self, title: Optional[str] = None, temporary: bool = False) -> None:
        pass

    def config_test(self) -> None:
        pass

    def restart(self) -> None:
        pass

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        pass

    def prepare(self) -> None:
        pass

    def more_info(self) -> str:
        return ""


def vector_path(*names: str) -> str:
    """Path to a test vector."""
    _file_manager = ExitStack()
    atexit.register(_file_manager.close)
    vector_ref = importlib.resources.files(__package__).joinpath('testdata', *names)
    path = _file_manager.enter_context(importlib.resources.as_file(vector_ref))
    return str(path)


def load_vector(*names: str) -> bytes:
    """Load contents of a test vector."""
    vector_ref = importlib.resources.files(__package__).joinpath('testdata', *names)
    data = vector_ref.read_bytes()
    # Try at most to convert CRLF to LF when data is text
    try:
        return data.decode().replace('\r\n', '\n').encode()
    except ValueError:
        # Failed to process the file with standard encoding.
        # Most likely not a text file, return its bytes untouched.
        return data


def _guess_loader(filename: str, loader_pem: int, loader_der: int) -> int:
    _, ext = os.path.splitext(filename)
    if ext.lower() == '.pem':
        return loader_pem
    elif ext.lower() == '.der':
        return loader_der
    raise ValueError("Loader could not be recognized based on extension")  # pragma: no cover


def load_cert(*names: str) -> crypto.X509:
    """Load certificate."""
    loader = _guess_loader(
        names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    return crypto.load_certificate(loader, load_vector(*names))


def load_csr(*names: str) -> crypto.X509Req:
    """Load certificate request."""
    loader = _guess_loader(
        names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    return crypto.load_certificate_request(loader, load_vector(*names))


def load_comparable_csr(*names: str) -> jose.ComparableX509:
    """Load ComparableX509 certificate request."""
    return jose.ComparableX509(load_csr(*names))


def load_jose_rsa_private_key_pem(*names: str) -> jose.ComparableRSAKey:
    """Load RSA private key wrapped in jose.ComparableRSAKey"""
    return jose.ComparableRSAKey(load_rsa_private_key_pem(*names))


def load_rsa_private_key_pem(*names: str) -> RSAPrivateKey:
    """Load RSA private key."""
    loader = _guess_loader(names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    loader_fn: Callable[..., Any]
    if loader == crypto.FILETYPE_PEM:
        loader_fn = serialization.load_pem_private_key
    else:
        loader_fn = serialization.load_der_private_key
    key = loader_fn(load_vector(*names), password=None, backend=default_backend())
    assert isinstance(key, RSAPrivateKey)
    return key


def make_lineage(config_dir: str, testfile: str, ec: bool = True) -> str:
    """Creates a lineage defined by testfile.

    This creates the archive, live, and renewal directories if
    necessary and creates a simple lineage.

    :param str config_dir: path to the configuration directory
    :param str testfile: configuration file to base the lineage on
    :param bool ec: True if we generate the lineage with an ECDSA key

    :returns: path to the renewal conf file for the created lineage
    :rtype: str

    """
    lineage_name = testfile[:-len('.conf')]

    conf_dir = os.path.join(
        config_dir, constants.RENEWAL_CONFIGS_DIR)
    archive_dir = os.path.join(
        config_dir, constants.ARCHIVE_DIR, lineage_name)
    live_dir = os.path.join(
        config_dir, constants.LIVE_DIR, lineage_name)

    for directory in (archive_dir, conf_dir, live_dir,):
        if not os.path.exists(directory):
            filesystem.makedirs(directory)

    sample_archive = vector_path('sample-archive{}'.format('-ec' if ec else ''))
    for kind in os.listdir(sample_archive):
        shutil.copyfile(os.path.join(sample_archive, kind),
                        os.path.join(archive_dir, kind))

    for kind in storage.ALL_FOUR:
        os.symlink(os.path.join(archive_dir, '{0}1.pem'.format(kind)),
                   os.path.join(live_dir, '{0}.pem'.format(kind)))

    conf_path = os.path.join(config_dir, conf_dir, testfile)
    with open(vector_path(testfile)) as src:
        with open(conf_path, 'w') as dst:
            dst.writelines(
                line.replace('MAGICDIR', config_dir) for line in src)

    return conf_path


def patch_display_util() -> mock.MagicMock:
    """Patch certbot.display.util to use a special mock display utility.

    The mock display utility works like a regular mock object, except it also
    also asserts that methods are called with valid arguments.

    The mock created by this patch mocks out Certbot internals. That is, the
    mock object will be called by the certbot.display.util functions and the
    mock returned by that call will be used as the display utility. This was
    done to simplify the transition from zope.component and mocking
    certbot.display.util functions directly in test code should be preferred
    over using this function in the future.

    See https://github.com/certbot/certbot/issues/8948

    :returns: patch on the function used internally by certbot.display.util to
        get a display utility instance
    :rtype: mock.MagicMock

    """
    return cast(mock.MagicMock, mock.patch('certbot._internal.display.obj.get_display',
                                           new_callable=_create_display_util_mock))


def patch_display_util_with_stdout(
        stdout: Optional[IO] = None) -> mock.MagicMock:
    """Patch certbot.display.util to use a special mock display utility.

    The mock display utility works like a regular mock object, except it also
    asserts that methods are called with valid arguments.

    The mock created by this patch mocks out Certbot internals. That is, the
    mock object will be called by the certbot.display.util functions and the
    mock returned by that call will be used as the display utility. This was
    done to simplify the transition from zope.component and mocking
    certbot.display.util functions directly in test code should be preferred
    over using this function in the future.

    See https://github.com/certbot/certbot/issues/8948

    The `message` argument passed to the display utility methods is passed to
    stdout's write method.

    :param object stdout: object to write standard output to; it is
        expected to have a `write` method
    :returns: patch on the function used internally by certbot.display.util to
        get a display utility instance
    :rtype: mock.MagicMock

    """
    stdout = stdout if stdout else io.StringIO()

    return cast(mock.MagicMock, mock.patch('certbot._internal.display.obj.get_display',
                                           new=_create_display_util_mock_with_stdout(stdout)))


class FreezableMock:
    """Mock object with the ability to freeze attributes.

    This class works like a regular mock.MagicMock object, except
    attributes and behavior set before the object is frozen cannot
    be changed during tests.

    If a func argument is provided to the constructor, this function
    is called first when an instance of FreezableMock is called,
    followed by the usual behavior defined by MagicMock. The return
    value of func is ignored.

    """
    def __init__(self, frozen: bool = False, func: Optional[Callable[..., Any]] = None,
                 return_value: Any = mock.sentinel.DEFAULT) -> None:
        self._frozen_set = set() if frozen else {'freeze', }
        self._func = func
        self._mock = mock.MagicMock()
        if return_value != mock.sentinel.DEFAULT:
            self.return_value = return_value
        self._frozen = frozen

    def freeze(self) -> None:
        """Freeze object preventing further changes."""
        self._frozen = True

    def __call__(self, *args: Any, **kwargs: Any) -> mock.MagicMock:
        if self._func is not None:
            self._func(*args, **kwargs)
        return self._mock(*args, **kwargs)

    def __getattribute__(self, name: str) -> Any:
        if name == '_frozen':
            try:
                return object.__getattribute__(self, name)
            except AttributeError:
                return False
        elif name in ('return_value', 'side_effect',):
            return getattr(object.__getattribute__(self, '_mock'), name)
        elif name == '_frozen_set' or name in self._frozen_set:
            return object.__getattribute__(self, name)
        else:
            return getattr(object.__getattribute__(self, '_mock'), name)

    def __setattr__(self, name: str, value: Any) -> None:
        """ Before it is frozen, attributes are set on the FreezableMock
        instance and added to the _frozen_set. Attributes in the _frozen_set
        cannot be changed after the FreezableMock is frozen. In this case,
        they are set on the underlying _mock.

        In cases of return_value and side_effect, these attributes are always
        passed through to the instance's _mock and added to the _frozen_set
        before the object is frozen.

        """
        if self._frozen:
            if name in self._frozen_set:
                raise AttributeError('Cannot change frozen attribute ' + name)
            return setattr(self._mock, name, value)

        if name != '_frozen_set':
            self._frozen_set.add(name)

        if name in ('return_value', 'side_effect'):
            return setattr(self._mock, name, value)

        return object.__setattr__(self, name, value)


def _create_display_util_mock() -> FreezableMock:
    display = FreezableMock()
    # Use pylint code for disable to keep on single line under line length limit
    method_list = [func for func in dir(display_obj.FileDisplay)
                   if callable(getattr(display_obj.FileDisplay, func))
                   and not func.startswith("__")]
    for method in method_list:
        if method != 'notification':
            frozen_mock = FreezableMock(frozen=True, func=_assert_valid_call)
            setattr(display, method, frozen_mock)
    display.freeze()
    return FreezableMock(frozen=True, return_value=display)


def _create_display_util_mock_with_stdout(stdout: IO) -> FreezableMock:
    def _write_msg(message: str, *unused_args: Any, **unused_kwargs: Any) -> None:
        """Write to message to stdout.
        """
        if message:
            stdout.write(message)

    def mock_method(*args: Any, **kwargs: Any) -> None:
        """
        Mock function for display utility methods.
        """
        _assert_valid_call(args, kwargs)
        _write_msg(*args, **kwargs)

    display = FreezableMock()
    # Use pylint code for disable to keep on single line under line length limit
    method_list = [func for func in dir(display_obj.FileDisplay)
                   if callable(getattr(display_obj.FileDisplay, func))
                   and not func.startswith("__")]
    for method in method_list:
        if method == 'notification':
            frozen_mock = FreezableMock(frozen=True,
                                        func=_write_msg)
        else:
            frozen_mock = FreezableMock(frozen=True,
                                        func=mock_method)
        setattr(display, method, frozen_mock)
    display.freeze()
    return FreezableMock(frozen=True, return_value=display)


def _assert_valid_call(*args: Any, **kwargs: Any) -> None:
    assert_args = [args[0] if args else kwargs['message']]

    assert_kwargs = {
        'default': kwargs.get('default', None),
        'cli_flag': kwargs.get('cli_flag', None),
        'force_interactive': kwargs.get('force_interactive', False),
    }

    display_util.assert_valid_call(*assert_args, **assert_kwargs)


class TempDirTestCase(unittest.TestCase):
    """Base test class which sets up and tears down a temporary directory"""

    def setUp(self) -> None:
        """Execute before test"""
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Execute after test"""
        # Cleanup opened resources after a test. This is usually done through atexit handlers in
        # Certbot, but during tests, atexit will not run registered functions before tearDown is
        # called and instead will run them right before the entire test process exits.
        # It is a problem on Windows, that does not accept to clean resources before closing them.
        logging.shutdown()
        # Remove logging handlers that have been closed so they won't be
        # accidentally used in future tests.
        logging.getLogger().handlers = []
        util._release_locks()  # pylint: disable=protected-access

        shutil.rmtree(self.tempdir)


class ConfigTestCase(TempDirTestCase):
    """Test class which sets up a NamespaceConfig object."""
    def setUp(self) -> None:
        super().setUp()
        self.config = configuration.NamespaceConfig(
            # We make a copy here so any mutable values from CLI_DEFAULTS do not get modified.
            mock.MagicMock(**copy.deepcopy(constants.CLI_DEFAULTS)),
        )
        self.config.set_argument_sources({})
        self.config.namespace.verb = "certonly"
        self.config.namespace.config_dir = os.path.join(self.tempdir, 'config')
        self.config.namespace.work_dir = os.path.join(self.tempdir, 'work')
        self.config.namespace.logs_dir = os.path.join(self.tempdir, 'logs')
        self.config.namespace.cert_path = constants.CLI_DEFAULTS['auth_cert_path']
        self.config.namespace.fullchain_path = constants.CLI_DEFAULTS['auth_chain_path']
        self.config.namespace.chain_path = constants.CLI_DEFAULTS['auth_chain_path']
        self.config.namespace.server = "https://example.com"


def _handle_lock(event_in: synchronize.Event, event_out: synchronize.Event, path: str) -> None:
    """
    Acquire a file lock on given path, then wait to release it. This worker is coordinated
    using events to signal when the lock should be acquired and released.
    :param multiprocessing.Event event_in: event object to signal when to release the lock
    :param multiprocessing.Event event_out: event object to signal when the lock is acquired
    :param path: the path to lock
    """
    if os.path.isdir(path):
        my_lock = lock.lock_dir(path)
    else:
        my_lock = lock.LockFile(path)
    try:
        event_out.set()
        assert event_in.wait(timeout=20), 'Timeout while waiting to release the lock.'
    finally:
        my_lock.release()


def lock_and_call(callback: Callable[[], Any], path_to_lock: str) -> None:
    """
    Grab a lock on path_to_lock from a foreign process then execute the callback.
    :param callable callback: object to call after acquiring the lock
    :param str path_to_lock: path to file or directory to lock
    """
    # Reload certbot.util module to reset internal _LOCKS dictionary.
    reload_module(util)

    emit_event = multiprocessing.Event()
    receive_event = multiprocessing.Event()
    process = multiprocessing.Process(target=_handle_lock,
                                      args=(emit_event, receive_event, path_to_lock))
    process.start()

    # Wait confirmation that lock is acquired
    assert receive_event.wait(timeout=10), 'Timeout while waiting to acquire the lock.'
    # Execute the callback
    callback()
    # Trigger unlock from foreign process
    emit_event.set()

    # Wait for process termination
    process.join(timeout=10)
    assert process.exitcode == 0


def skip_on_windows(reason: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to skip permanently a test on Windows. A reason is required."""
    def wrapper(function: Callable[..., Any]) -> Callable[..., Any]:
        """Wrapped version"""
        return unittest.skipIf(sys.platform == 'win32', reason)(function)
    return wrapper


def temp_join(path: str) -> str:
    """
    Return the given path joined to the tempdir path for the current platform
    Eg.: 'cert' => /tmp/cert (Linux) or 'C:\\Users\\currentuser\\AppData\\Temp\\cert' (Windows)
    """
    return os.path.join(tempfile.gettempdir(), path)
