#!/usr/bin/env python3
import argparse
import datetime
import functools
import glob
from multiprocessing import Manager
from multiprocessing import Pool
from multiprocessing import Process
from multiprocessing.managers import SyncManager
import os
from os.path import basename
from os.path import dirname
from os.path import join
from os.path import realpath
import random
import re
import string
import subprocess
import sys
import tempfile
from threading import Lock
import time
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

CERTBOT_DIR = dirname(dirname(dirname(realpath(__file__))))
PLUGINS = [basename(path) for path in glob.glob(join(CERTBOT_DIR, 'certbot-dns-*'))]


# In Python, stdout and stderr are buffered in each process by default. When
# printing output from multiple processes, this can cause delays in printing
# output with lines from different processes being interleaved depending
# on when the output for that process is flushed. To prevent this, we override
# print so that it always flushes its output. Disabling output buffering can
# also be done through command line flags or environment variables set when the
# Python process starts, but this approach was taken instead to ensure
# consistent behavior regardless of how the script is invoked.
print = functools.partial(print, flush=True)


def _snap_log_name(target: str, arch: str):
    return f'{target}_{arch}.txt'


def _execute_build(
        target: str, archs: Set[str], status: Dict[str, Dict[str, str]],
        workspace: str, output_lock: Lock) -> Tuple[int, List[str]]:
    # The implementation of remote-build recovery has changed over time.
    # Currently, you cannot set a build-id, and the build-id is instead derived
    # from a hash of the contents of the files in the directory:
    # https://github.com/canonical/craft-application/blob/5b09ab3d9152a2b61ffcdf57691289023ed6ba26/craft_application/remote/utils.py#L64
    #
    # We want a unique build ID so a fresh build is started for each run instead
    # of potentially reusing an old build. See https://github.com/certbot/certbot/pull/8719
    # and https://github.com/snapcore/snapcraft/pull/3554 for more info.
    #
    # In the hope that one day you can again set a build ID, we will modify
    # the directory by creating a file containing a build ID that conforms
    # to the shape of snapcraft's build ID: using a MD5 hash represented as a
    # 32 character hex string (we use a larger character set).

    random_string = ''.join(random.choice(string.ascii_lowercase + string.digits)
                            for _ in range(32))
    # place random string in build_id file inside `workspace` directory
    with open(join(workspace, 'build_id'), 'w') as build_id_file:
        build_id_file.write(random_string)

    with tempfile.TemporaryDirectory() as tempdir:
        environ = os.environ.copy()
        environ['XDG_CACHE_HOME'] = tempdir
        process = subprocess.Popen([
            'snapcraft', 'remote-build', '--launchpad-accept-public-upload',
            '--build-for', ','.join(archs)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, env=environ, cwd=workspace)

    killed = False
    process_output: List[str] = []
    for line in process.stdout:
        process_output.append(line)
        _extract_state(target, line, status)

        if not killed and any(state for state in status[target].values() if state == 'Chroot problem'):
            # On this error the snapcraft process hangs. Let's finish it.
            #
            # killed is used to stop us from executing this code path
            # multiple times per build that encounters "Chroot problem".
            with output_lock:
                print('Chroot problem encountered for build '
                      f'{target} for {",".join(archs)}.\n'
                      'Launchpad seems to be unable to recover from this '
                      'state so we are terminating the build.')
            process.kill()
            killed = True

    process_state = process.wait()

    return process_state, process_output


def _build_snap(
        target: str, archs: Set[str], status: Dict[str, Dict[str, str]],
        running: Dict[str, bool], output_lock: Lock) -> bool:
    if target == 'certbot':
        workspace = CERTBOT_DIR
    else:
        workspace = join(CERTBOT_DIR, target)
        # init and commit git repo in workspace
        subprocess.run(['git', 'init'], capture_output=True, check=True, cwd=workspace)
        subprocess.run(['git', 'add', '-A'], capture_output=True, check=True, cwd=workspace)
        subprocess.run(['git', 'commit', '-m', 'init'], capture_output=True, check=True, cwd=workspace)

    build_success = False
    retry = 3
    while retry:
        # Let's reset the status before each build so we're not starting with
        # old state values.
        status[target] = {arch: '...' for arch in archs}
        exit_code, process_output = _execute_build(target, archs, status, workspace, output_lock)
        with output_lock:
            print(f'Build {target} for {",".join(archs)} (attempt {4-retry}/3) ended with '
                  f'exit code {exit_code}.')

            failed_archs = [arch for arch in archs if status[target][arch] != 'Succeeded']
            # If the command failed or any architecture wasn't built
            # successfully, let's try to print all the output about the problem
            # that we can.
            dump_output = exit_code != 0 or failed_archs
            if exit_code == 0 and not failed_archs:
                # We expect to have all target snaps available, or something bad happened.
                snaps_list = glob.glob(join(workspace, '*.snap'))
                if not len(snaps_list) == len(archs):
                    print('Some of the expected snaps for a successful build are missing '
                          f'(current list: {snaps_list}).')
                    dump_output = True
                else:
                    build_success = True
                    break
            if dump_output:
                print(f'Dumping snapcraft remote-build output build for {target}:')
                print('\n'.join(process_output))
                _dump_failed_build_logs(target, archs, status, workspace)

        # Retry the remote build if it has been interrupted (non zero status code)
        # or if some builds have failed.
        retry = retry - 1

    running[target] = False

    return build_success


def _extract_state(project: str, output: str, status: Dict[str, Dict[str, str]]) -> None:
    state = status[project]

    if "Starting new build" in output:
        for arch in state.keys():
            state[arch] = "Starting new build"

    match = re.match(r'^(\w+): (\w+)$', output)
    if match:
        arch = match.group(2)
        state[arch] = match.group(1)

    # You need to reassign the value of status[project] here (rather than doing
    # something like status[project][arch] = match.group(1)) for the state change
    # to propagate to other processes. See
    # https://docs.python.org/3.8/library/multiprocessing.html#proxy-objects for
    # more info.
    status[project] = state


def _dump_status_helper(archs: Set[str], status: Dict[str, Dict[str, str]]) -> None:
    headers = ['project', *archs]
    print(''.join(f'| {item:<25}' for item in headers))
    print(f'|{"-" * 26}' * len(headers))
    for project, states in sorted(status.items()):
        print(''.join(f'| {item:<25}' for item in [project, *[states[arch] for arch in archs]]))
    print(f'|{"-" * 26}' * len(headers))
    print()


def _dump_status(
        archs: Set[str], status: Dict[str, Dict[str, str]],
        running: Dict[str, bool], output_lock: Lock) -> None:
    while any(running.values()):
        with output_lock:
            print(f'Remote build status at {datetime.datetime.now()}')
            _dump_status_helper(archs, status)
        time.sleep(10)


def _dump_failed_build_logs(
        target: str, archs: Set[str], status: Dict[str, Dict[str, str]],
        workspace: str) -> None:
    logs_list = glob.glob(join(workspace, f'snapcraft-{target}-*.txt'))
    for arch in archs:
        result = status[target][arch]

        if result != 'Succeeded':
            failures = True

            build_output_path = [log_name for log_name in logs_list if arch in log_name]
            if not build_output_path:
                build_output = 'No output has been dumped by snapcraft remote-build.'
            else:
                with open(build_output_path[0]) as file_h:
                    build_output = file_h.read()

            print(f'Output for failed build target={target} arch={arch}')
            print('-------------------------------------------')
            print(build_output)
            print('-------------------------------------------')
            print()


def _dump_results(archs: Set[str], status: Dict[str, Dict[str, str]]) -> None:
    print(f'Results for remote build finished at {datetime.datetime.now()}')
    _dump_status_helper(archs, status)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('targets', nargs='+', choices=['ALL', 'DNS_PLUGINS', 'certbot', *PLUGINS],
                        help='the list of snaps to build')
    parser.add_argument('--archs', nargs='+', choices=['amd64', 'arm64', 'armhf'],
                        default=['amd64'], help='the architectures for which snaps are built')
    parser.add_argument('--timeout', type=int, default=None,
                        help='build process will fail after the provided timeout (in seconds)')
    args = parser.parse_args()

    archs = set(args.archs)
    targets = set(args.targets)

    if 'ALL' in targets:
        targets.remove('ALL')
        targets.update(['certbot', 'DNS_PLUGINS'])

    if 'DNS_PLUGINS' in targets:
        targets.remove('DNS_PLUGINS')
        targets.update(PLUGINS)

    # If we're building anything other than just Certbot, we need to
    # generate the snapcraft files for the DNS plugins.
    if targets != {'certbot'}:
        subprocess.run(['tools/snap/generate_dnsplugins_all.sh'],
                       check=True, cwd=CERTBOT_DIR)

    print('Start remote snap builds...')
    print(f' - archs: {", ".join(archs)}')
    print(f' - projects: {", ".join(sorted(targets))}')
    print()

    manager: SyncManager = Manager()
    pool = Pool(processes=len(targets))
    with manager, pool:
        status: Dict[str, Dict[str, str]] = manager.dict()
        running = manager.dict({target: True for target in targets})
        # While multiple processes are running, this lock should be acquired
        # before printing output.
        output_lock = manager.Lock()

        async_results = [pool.apply_async(_build_snap, (target, archs, status, running, output_lock))
                         for target in targets]

        process = Process(target=_dump_status, args=(archs, status, running, output_lock))
        process.start()

        try:
            process.join(args.timeout)

            if process.is_alive():
                for target in targets:
                    if target == 'certbot':
                        workspace = CERTBOT_DIR
                    else:
                        workspace = join(CERTBOT_DIR, target)
                    _dump_failed_build_logs(target, archs, status, workspace)
                raise ValueError(f"Timeout out reached ({args.timeout} seconds) during the build!")

            build_success = True
            for async_result in async_results:
                if not async_result.get():
                    build_success = False

            _dump_results(archs, status)
            if build_success:
                print('All builds succeeded.')
            else:
                print('Some builds failed.')
                raise ValueError("There were failures during the build!")
        finally:
            process.terminate()


if __name__ == '__main__':
    sys.exit(main())
