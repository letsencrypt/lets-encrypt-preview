#!/usr/bin/env python
# pip installs packages using pinned package versions. If CERTBOT_OLDEST is set
# to 1, tools/oldest_constraints.txt is used, otherwise, tools/requirements.txt
# is used. Before installing the requested packages, core Python packaging
# tools like pip, setuptools, and wheel are updated to pinned versions to
# increase stability of the install.
#
# cryptography is currently using this script in their CI at
# https://github.com/pyca/cryptography/blob/14d45c2259b01f1459eeab8bb7d85ce4cfb0841b/.github/downstream.d/certbot.sh#L8-L9.
# We should try to remember to keep their repo updated if we make any changes
# to this script which may break things for them.

import os
import subprocess
import sys


def find_tools_path():
    return os.path.dirname(os.path.realpath(__file__))


def call_with_print(command, env):
    assert env is not None
    print(command)
    subprocess.check_call(command, shell=True, env=env)


def pip_install_with_print(args_str, env):
    command = ['"', sys.executable, '" -m pip install --disable-pip-version-check ', args_str]
    call_with_print(''.join(command), env=env)


def pip_constrained_environ():
    tools_path = find_tools_path()

    repo_path = os.path.dirname(tools_path)
    if os.environ.get('CERTBOT_OLDEST') == '1':
        constraints_path = os.path.normpath(os.path.join(
            repo_path, 'tools', 'oldest_constraints.txt'))
    else:
        constraints_path = os.path.normpath(os.path.join(
            repo_path, 'tools', 'requirements.txt'))

    env = os.environ.copy()
    # We set constraints for pip using an environment variable so that they
    # are also used when installing build dependencies. See
    # https://github.com/certbot/certbot/pull/8443 for more info.
    env["PIP_CONSTRAINT"] = constraints_path
    return env


def pipstrap(env=None):
    if env is None:
        env = pip_constrained_environ()
    pip_install_with_print('pip setuptools wheel', env=env)


def main(args):
    env = pip_constrained_environ()
    pipstrap(env)
    pip_install_with_print(' '.join(args), env=env)


if __name__ == '__main__':
    main(sys.argv[1:])
