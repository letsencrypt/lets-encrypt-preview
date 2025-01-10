"""Tests for certbot._internal.lock."""
import functools
import multiprocessing
import sys
from unittest import mock

import pytest

from certbot import errors
from certbot.compat import os
from certbot.tests import util as test_util

try:
    import fcntl  # pylint: disable=import-error,unused-import  # noqa
except ImportError:
    POSIX_MODE = False
else:
    POSIX_MODE = True


class LockDirTest(test_util.TempDirTestCase):
    """Tests for certbot._internal.lock.lock_dir."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.lock import lock_dir
        return lock_dir(*args, **kwargs)

    def test_it(self):
        assert_raises = functools.partial(
            self.assertRaises, errors.LockError, self._call, self.tempdir)
        lock_path = os.path.join(self.tempdir, '.certbot.lock')
        test_util.lock_and_call(assert_raises, lock_path)


class LockFileTest(test_util.TempDirTestCase):
    """Tests for certbot._internal.lock.LockFile."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.lock import LockFile
        return LockFile(*args, **kwargs)

    def setUp(self):
        super().setUp()
        self.lock_path = os.path.join(self.tempdir, 'test.lock')

    def test_acquire_without_deletion(self):
        # acquire the lock in another process but don't delete the file
        child = multiprocessing.Process(target=self._call,
                                        args=(self.lock_path,))
        child.start()
        child.join()
        assert child.exitcode == 0
        assert os.path.exists(self.lock_path)

        # Test we're still able to properly acquire and release the lock
        self.test_removed()

    def test_contention(self):
        assert_raises = functools.partial(
            self.assertRaises, errors.LockError, self._call, self.lock_path)
        test_util.lock_and_call(assert_raises, self.lock_path)

    def test_locked_repr(self):
        lock_file = self._call(self.lock_path)
        try:
            locked_repr = repr(lock_file)
            self._test_repr_common(lock_file, locked_repr)
            assert 'acquired' in locked_repr
        finally:
            lock_file.release()

    def test_released_repr(self):
        lock_file = self._call(self.lock_path)
        lock_file.release()
        released_repr = repr(lock_file)
        self._test_repr_common(lock_file, released_repr)
        assert 'released' in released_repr

    def _test_repr_common(self, lock_file, lock_repr):
        assert lock_file.__class__.__name__ in lock_repr
        assert self.lock_path in lock_repr

    @test_util.skip_on_windows(
        'Race conditions on lock are specific to the non-blocking file access approach on Linux.')
    def test_race(self):
        should_delete = [True, False]
        # Normally os module should not be imported in certbot codebase except in certbot.compat
        # for the sake of compatibility over Windows and Linux.
        # We make an exception here, since test_race is a test function called only on Linux.
        from os import stat  # pylint: disable=os-module-forbidden

        def delete_and_stat(path):
            """Wrap os.stat and maybe delete the file first."""
            if path == self.lock_path and should_delete.pop(0):
                os.remove(path)
            return stat(path)

        with mock.patch('certbot._internal.lock.filesystem.os.stat') as mock_stat:
            mock_stat.side_effect = delete_and_stat
            self._call(self.lock_path)
        assert len(should_delete) == 0

    def test_removed(self):
        lock_file = self._call(self.lock_path)
        lock_file.release()
        assert not os.path.exists(self.lock_path)

    def test_unexpected_lockf_or_locking_err(self):
        if POSIX_MODE:
            mocked_function = 'certbot._internal.lock.fcntl.lockf'
        else:
            mocked_function = 'certbot._internal.lock.msvcrt.locking'
        msg = 'hi there'
        with mock.patch(mocked_function) as mock_lock:
            mock_lock.side_effect = OSError(msg)
            try:
                self._call(self.lock_path)
            except OSError as err:
                assert msg in str(err)
            else:  # pragma: no cover
                self.fail('IOError not raised')

    def test_unexpected_os_err(self):
        if POSIX_MODE:
            mock_function = 'certbot._internal.lock.filesystem.os.stat'
        else:
            mock_function = 'certbot._internal.lock.msvcrt.locking'
        # The only expected errno are ENOENT and EACCES in lock module.
        msg = 'hi there'
        with mock.patch(mock_function) as mock_os:
            mock_os.side_effect = OSError(msg)
            try:
                self._call(self.lock_path)
            except OSError as err:
                assert msg in str(err)
            else:  # pragma: no cover
                self.fail('OSError not raised')


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
