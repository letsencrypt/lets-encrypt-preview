"""Utility functions for Certbot plugin tests."""
import argparse
import copy
import os
import re
import shutil
import tarfile

import josepy as jose

from certbot._internal import constants
from certbot.tests import util as test_util
from certbot_compatibility_test import errors

_KEY_BASE = "rsa2048_key.pem"
KEY_PATH = test_util.vector_path(_KEY_BASE)
KEY = test_util.load_rsa_private_key_pem(_KEY_BASE)
JWK = jose.JWKRSA(key=test_util.load_jose_rsa_private_key_pem(_KEY_BASE))
IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def create_le_config(parent_dir: str) -> argparse.Namespace:
    """Sets up LE dirs in parent_dir and returns the config dict"""
    config = copy.deepcopy(constants.CLI_DEFAULTS)

    le_dir = os.path.join(parent_dir, "certbot")
    os.mkdir(le_dir)
    for dir_name in ("config", "logs", "work"):
        full_path = os.path.join(le_dir, dir_name)
        os.mkdir(full_path)
        full_name = dir_name + "_dir"
        config[full_name] = full_path

    config["domains"] = None

    return argparse.Namespace(**config)


def extract_configs(configs: str, parent_dir: str) -> str:
    """Extracts configs to a new dir under parent_dir and returns it"""
    config_dir = os.path.join(parent_dir, "configs")

    if os.path.isdir(configs):
        shutil.copytree(configs, config_dir, symlinks=True)
    elif tarfile.is_tarfile(configs):
        with tarfile.open(configs, "r") as tar:
            tar.extractall(config_dir)
    else:
        raise errors.Error("Unknown configurations file type")

    return config_dir
