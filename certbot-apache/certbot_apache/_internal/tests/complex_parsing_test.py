"""Tests for certbot_apache._internal.parser."""
import shutil
import sys

import pytest

from certbot import errors
from certbot.compat import os
from certbot_apache._internal.tests import util


class ComplexParserTest(util.ParserTest):
    """Apache Parser Test."""

    def setUp(self, **kwargs):
        super().setUp("complex_parsing", "complex_parsing")

        self.setup_variables()
        # This needs to happen after due to setup_variables not being run
        # until after
        self.parser.parse_modules()  # pylint: disable=protected-access

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def setup_variables(self):
        """Set up variables for parser."""
        self.parser.variables.update(
            {
                "COMPLEX": "",
                "tls_port": "1234",
                "fnmatch_filename": "test_fnmatch.conf",
                "tls_port_str": "1234"
            }
        )

    def test_filter_args_num(self):
        """Note: This may also fail do to Include conf-enabled/ syntax."""
        matches = self.parser.find_dir("TestArgsDirective")

        assert len(self.parser.filter_args_num(matches, 1)) == 3
        assert len(self.parser.filter_args_num(matches, 2)) == 2
        assert len(self.parser.filter_args_num(matches, 3)) == 1

    def test_basic_variable_parsing(self):
        matches = self.parser.find_dir("TestVariablePort")

        assert len(matches) == 1
        assert self.parser.get_arg(matches[0]) == "1234"

    def test_basic_variable_parsing_quotes(self):
        matches = self.parser.find_dir("TestVariablePortStr")

        assert len(matches) == 1
        assert self.parser.get_arg(matches[0]) == "1234"

    def test_invalid_variable_parsing(self):
        del self.parser.variables["tls_port"]

        matches = self.parser.find_dir("TestVariablePort")
        with pytest.raises(errors.PluginError):
            self.parser.get_arg(matches[0])

    def test_basic_ifdefine(self):
        assert len(self.parser.find_dir("VAR_DIRECTIVE")) == 2
        assert len(self.parser.find_dir("INVALID_VAR_DIRECTIVE")) == 0

    def test_basic_ifmodule(self):
        assert len(self.parser.find_dir("MOD_DIRECTIVE")) == 2
        assert len(self.parser.find_dir("INVALID_MOD_DIRECTIVE")) == 0

    def test_nested(self):
        assert len(self.parser.find_dir("NESTED_DIRECTIVE")) == 3
        assert len(self.parser.find_dir("INVALID_NESTED_DIRECTIVE")) == 0

    def test_load_modules(self):
        """If only first is found, there is bad variable parsing."""
        assert "status_module" in self.parser.modules
        assert "mod_status.c" in self.parser.modules

        # This is in an IfDefine
        assert "ssl_module" in self.parser.modules
        assert "mod_ssl.c" in self.parser.modules

    def verify_fnmatch(self, arg, hit=True):
        """Test if Include was correctly parsed."""
        from certbot_apache._internal import parser
        self.parser.add_dir(parser.get_aug_path(self.parser.loc["default"]),
                            "Include", [arg])
        if hit:
            assert self.parser.find_dir("FNMATCH_DIRECTIVE")
        else:
            assert not self.parser.find_dir("FNMATCH_DIRECTIVE")

    # NOTE: Only run one test per function otherwise you will have
    # inf recursion
    def test_include(self):
        self.verify_fnmatch("test_fnmatch.?onf")

    def test_include_complex(self):
        self.verify_fnmatch("../complex_parsing/[te][te]st_*.?onf")

    def test_include_fullpath(self):
        self.verify_fnmatch(os.path.join(self.config_path,
                                         "test_fnmatch.conf"))

    def test_include_fullpath_trailing_slash(self):
        self.verify_fnmatch(self.config_path + "//")

    def test_include_single_quotes(self):
        self.verify_fnmatch("'" + self.config_path + "'")

    def test_include_double_quotes(self):
        self.verify_fnmatch('"' + self.config_path + '"')

    def test_include_variable(self):
        self.verify_fnmatch("../complex_parsing/${fnmatch_filename}")

    def test_include_missing(self):
        # This should miss
        self.verify_fnmatch("test_*.onf", False)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
