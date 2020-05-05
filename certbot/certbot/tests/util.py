"""Test utilities."""
import logging
from multiprocessing import Event
from multiprocessing import Process
import shutil
import sys
import tempfile
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import josepy as jose
try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
import OpenSSL
import pkg_resources
import six
from six.moves import reload_module

from certbot import interfaces
from certbot import util
from certbot._internal import configuration
from certbot._internal import constants
from certbot._internal import lock
from certbot._internal import storage
from certbot.compat import filesystem
from certbot.compat import os
from certbot.display import util as display_util


def vector_path(*names):
    """Path to a test vector."""
    return pkg_resources.resource_filename(
        __name__, os.path.join('testdata', *names))


def load_vector(*names):
    """Load contents of a test vector."""
    # luckily, resource_string opens file in binary mode
    data = pkg_resources.resource_string(
        __name__, os.path.join('testdata', *names))
    # Try at most to convert CRLF to LF when data is text
    try:
        return data.decode().replace('\r\n', '\n').encode()
    except ValueError:
        # Failed to process the file with standard encoding.
        # Most likely not a text file, return its bytes untouched.
        return data


def _guess_loader(filename, loader_pem, loader_der):
    _, ext = os.path.splitext(filename)
    if ext.lower() == '.pem':
        return loader_pem
    elif ext.lower() == '.der':
        return loader_der
    raise ValueError("Loader could not be recognized based on extension")  # pragma: no cover


def load_cert(*names):
    """Load certificate."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_certificate(loader, load_vector(*names))


def load_csr(*names):
    """Load certificate request."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_certificate_request(loader, load_vector(*names))


def load_comparable_csr(*names):
    """Load ComparableX509 certificate request."""
    return jose.ComparableX509(load_csr(*names))


def load_rsa_private_key(*names):
    """Load RSA private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return jose.ComparableRSAKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_pyopenssl_private_key(*names):
    """Load pyOpenSSL private key."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_privatekey(loader, load_vector(*names))


def make_lineage(config_dir, testfile):
    """Creates a lineage defined by testfile.

    This creates the archive, live, and renewal directories if
    necessary and creates a simple lineage.

    :param str config_dir: path to the configuration directory
    :param str testfile: configuration file to base the lineage on

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

    sample_archive = vector_path('sample-archive')
    for kind in os.listdir(sample_archive):
        shutil.copyfile(os.path.join(sample_archive, kind),
                        os.path.join(archive_dir, kind))

    for kind in storage.ALL_ITEMS:
        os.symlink(os.path.join(archive_dir, '{0}1.pem'.format(kind)),
                   os.path.join(live_dir, '{0}.pem'.format(kind)))

    conf_path = os.path.join(config_dir, conf_dir, testfile)
    with open(vector_path(testfile)) as src:
        with open(conf_path, 'w') as dst:
            dst.writelines(
                line.replace('MAGICDIR', config_dir) for line in src)

    return conf_path


def patch_get_utility(target='zope.component.getUtility'):
    """Patch zope.component.getUtility to use a special mock IDisplay.

    The mock IDisplay works like a regular mock object, except it also
    also asserts that methods are called with valid arguments.

    :param str target: path to patch

    :returns: mock zope.component.getUtility
    :rtype: mock.MagicMock

    """
    return mock.patch(target, new_callable=_create_get_utility_mock)


def patch_get_utility_with_stdout(target='zope.component.getUtility',
                                  stdout=None):
    """Patch zope.component.getUtility to use a special mock IDisplay.

    The mock IDisplay works like a regular mock object, except it also
    also asserts that methods are called with valid arguments.

    The `message` argument passed to the IDisplay methods is passed to
    stdout's write method.

    :param str target: path to patch
    :param object stdout: object to write standard output to; it is
        expected to have a `write` method

    :returns: mock zope.component.getUtility
    :rtype: mock.MagicMock

    """
    stdout = stdout if stdout else six.StringIO()

    freezable_mock = _create_get_utility_mock_with_stdout(stdout)
    return mock.patch(target, new=freezable_mock)


class FreezableMock(object):
    """Mock object with the ability to freeze attributes.

    This class works like a regular mock.MagicMock object, except
    attributes and behavior set before the object is frozen cannot
    be changed during tests.

    If a func argument is provided to the constructor, this function
    is called first when an instance of FreezableMock is called,
    followed by the usual behavior defined by MagicMock. The return
    value of func is ignored.

    """
    def __init__(self, frozen=False, func=None, return_value=mock.sentinel.DEFAULT):
        self._frozen_set = set() if frozen else {'freeze', }
        self._func = func
        self._mock = mock.MagicMock()
        if return_value != mock.sentinel.DEFAULT:
            self.return_value = return_value
        self._frozen = frozen

    def freeze(self):
        """Freeze object preventing further changes."""
        self._frozen = True

    def __call__(self, *args, **kwargs):
        if self._func is not None:
            self._func(*args, **kwargs)
        return self._mock(*args, **kwargs)

    def __getattribute__(self, name):
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

    def __setattr__(self, name, value):
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


def _create_get_utility_mock():
    display = FreezableMock()
    # Use pylint code for disable to keep on single line under line length limit
    for name in interfaces.IDisplay.names():  # pylint: E1120
        if name != 'notification':
            frozen_mock = FreezableMock(frozen=True, func=_assert_valid_call)
            setattr(display, name, frozen_mock)
    display.freeze()
    return FreezableMock(frozen=True, return_value=display)


def _create_get_utility_mock_with_stdout(stdout):
    def _write_msg(message, *unused_args, **unused_kwargs):
        """Write to message to stdout.
        """
        if message:
            stdout.write(message)

    def mock_method(*args, **kwargs):
        """
        Mock function for IDisplay methods.
        """
        _assert_valid_call(args, kwargs)
        _write_msg(*args, **kwargs)


    display = FreezableMock()
    # Use pylint code for disable to keep on single line under line length limit
    for name in interfaces.IDisplay.names():  # pylint: E1120
        if name == 'notification':
            frozen_mock = FreezableMock(frozen=True,
                                        func=_write_msg)
            setattr(display, name, frozen_mock)
        else:
            frozen_mock = FreezableMock(frozen=True,
                                        func=mock_method)
            setattr(display, name, frozen_mock)
    display.freeze()

    return FreezableMock(frozen=True, return_value=display)


def _assert_valid_call(*args, **kwargs):
    assert_args = [args[0] if args else kwargs['message']]

    assert_kwargs = {}
    assert_kwargs['default'] = kwargs.get('default', None)
    assert_kwargs['cli_flag'] = kwargs.get('cli_flag', None)
    assert_kwargs['force_interactive'] = kwargs.get('force_interactive', False)

    display_util.assert_valid_call(*assert_args, **assert_kwargs)


class TempDirTestCase(unittest.TestCase):
    """Base test class which sets up and tears down a temporary directory"""

    def setUp(self):
        """Execute before test"""
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
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
    def setUp(self):
        super(ConfigTestCase, self).setUp()
        self.config = configuration.NamespaceConfig(
            mock.MagicMock(**constants.CLI_DEFAULTS)
        )
        self.config.verb = "certonly"
        self.config.config_dir = os.path.join(self.tempdir, 'config')
        self.config.work_dir = os.path.join(self.tempdir, 'work')
        self.config.logs_dir = os.path.join(self.tempdir, 'logs')
        self.config.cert_path = constants.CLI_DEFAULTS['auth_cert_path']
        self.config.fullchain_path = constants.CLI_DEFAULTS['auth_chain_path']
        self.config.chain_path = constants.CLI_DEFAULTS['auth_chain_path']
        self.config.server = "https://example.com"


def _handle_lock(event_in, event_out, path):
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


def lock_and_call(callback, path_to_lock):
    """
    Grab a lock on path_to_lock from a foreign process then execute the callback.
    :param callable callback: object to call after acquiring the lock
    :param str path_to_lock: path to file or directory to lock
    """
    # Reload certbot.util module to reset internal _LOCKS dictionary.
    reload_module(util)

    emit_event = Event()
    receive_event = Event()
    process = Process(target=_handle_lock, args=(emit_event, receive_event, path_to_lock))
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


def skip_on_windows(reason):
    """Decorator to skip permanently a test on Windows. A reason is required."""
    def wrapper(function):
        """Wrapped version"""
        return unittest.skipIf(sys.platform == 'win32', reason)(function)
    return wrapper


def temp_join(path):
    """
    Return the given path joined to the tempdir path for the current platform
    Eg.: 'cert' => /tmp/cert (Linux) or 'C:\\Users\\currentuser\\AppData\\Temp\\cert' (Windows)
    """
    return os.path.join(tempfile.gettempdir(), path)
