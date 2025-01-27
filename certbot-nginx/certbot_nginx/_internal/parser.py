"""NginxParser is a member object of the NginxConfigurator class."""
import copy
import functools
import glob
import logging
import re
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Union

import pyparsing

from certbot import errors
from certbot.compat import os
from certbot_nginx._internal import nginxparser
from certbot_nginx._internal import obj
from certbot_nginx._internal.nginxparser import UnspacedList

logger = logging.getLogger(__name__)


class NginxParser:
    """Class handles the fine details of parsing the Nginx Configuration.

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.
    :ivar dict parsed: Mapping of file paths to parsed trees

    """

    def __init__(self, root: str) -> None:
        self.parsed: Dict[str, UnspacedList] = {}
        self.root = os.path.abspath(root)
        self.config_root = self._find_config_root()

        # Parse nginx.conf and included files.
        # TODO: Check sites-available/ as well. For now, the configurator does
        # not enable sites from there.
        self.load()

    def load(self) -> None:
        """Loads Nginx files into a parsed tree.

        """
        self.parsed = {}
        self._parse_recursively(self.config_root)

    def _parse_recursively(self, filepath: str) -> None:
        """Parses nginx config files recursively by looking at 'include'
        directives inside 'http' and 'server' blocks. Note that this only
        reads Nginx files that potentially declare a virtual host.

        :param str filepath: The path to the files to parse, as a glob

        """
        # pylint: disable=too-many-nested-blocks
        filepath = self.abs_path(filepath)
        trees = self._parse_files(filepath)
        for tree in trees:
            for entry in tree:
                if _is_include_directive(entry):
                    # Parse the top-level included file
                    self._parse_recursively(entry[1])
                elif entry[0] == ['http'] or entry[0] == ['server']:
                    # Look for includes in the top-level 'http'/'server' context
                    for subentry in entry[1]:
                        if _is_include_directive(subentry):
                            self._parse_recursively(subentry[1])
                        elif entry[0] == ['http'] and subentry[0] == ['server']:
                            # Look for includes in a 'server' context within
                            # an 'http' context
                            for server_entry in subentry[1]:
                                if _is_include_directive(server_entry):
                                    self._parse_recursively(server_entry[1])

    def abs_path(self, path: str) -> str:
        """Converts a relative path to an absolute path relative to the root.
        Does nothing for paths that are already absolute.

        :param str path: The path
        :returns: The absolute path
        :rtype: str

        """
        if not os.path.isabs(path):
            return os.path.normpath(os.path.join(self.root, path))
        return os.path.normpath(path)

    def _build_addr_to_ssl(self) -> Dict[Tuple[str, str], bool]:
        """Builds a map from address to whether it listens on ssl in any server block
        """
        servers = self._get_raw_servers()

        addr_to_ssl: Dict[Tuple[str, str], bool] = {}
        for server_list in servers.values():
            for server, _ in server_list:
                # Parse the server block to save addr info
                parsed_server = _parse_server_raw(server)
                for addr in parsed_server['addrs']:
                    addr_tuple = addr.normalized_tuple()
                    if addr_tuple not in addr_to_ssl:
                        addr_to_ssl[addr_tuple] = addr.ssl
                    addr_to_ssl[addr_tuple] = addr.ssl or addr_to_ssl[addr_tuple]
        return addr_to_ssl

    def _get_raw_servers(self) -> Dict[str, Union[List[Any], UnspacedList]]:
        # pylint: disable=cell-var-from-loop
        """Get a map of unparsed all server blocks
        """
        servers: Dict[str, Union[List[Any], nginxparser.UnspacedList]] = {}
        for filename, tree in self.parsed.items():
            servers[filename] = []
            srv = servers[filename]  # workaround undefined loop var in lambdas

            # Find all the server blocks
            _do_for_subarray(tree, lambda x: len(x) >= 2 and x[0] == ['server'],
                             lambda x, y: srv.append((x[1], y)))

            # Find 'include' statements in server blocks and append their trees
            for i, (server, path) in enumerate(servers[filename]):
                new_server = self._get_included_directives(server)
                servers[filename][i] = (new_server, path)
        return servers

    def get_vhosts(self) -> List[obj.VirtualHost]:
        """Gets list of all 'virtual hosts' found in Nginx configuration.
        Technically this is a misnomer because Nginx does not have virtual
        hosts, it has 'server blocks'.

        :returns: List of :class:`~certbot_nginx._internal.obj.VirtualHost`
            objects found in configuration
        :rtype: list

        """
        enabled = True  # We only look at enabled vhosts for now
        servers = self._get_raw_servers()

        vhosts = []
        for filename, server_list in servers.items():
            for server, path in server_list:
                # Parse the server block into a VirtualHost object

                parsed_server = _parse_server_raw(server)
                vhost = obj.VirtualHost(filename,
                                        parsed_server['addrs'],
                                        parsed_server['ssl'],
                                        enabled,
                                        parsed_server['names'],
                                        server,
                                        path)
                vhosts.append(vhost)

        self._update_vhosts_addrs_ssl(vhosts)

        return vhosts

    def _update_vhosts_addrs_ssl(self, vhosts: Iterable[obj.VirtualHost]) -> None:
        """Update a list of raw parsed vhosts to include global address sslishness
        """
        addr_to_ssl = self._build_addr_to_ssl()
        for vhost in vhosts:
            for addr in vhost.addrs:
                addr.ssl = addr_to_ssl[addr.normalized_tuple()]
                if addr.ssl:
                    vhost.ssl = True

    def _get_included_directives(self, block: UnspacedList) -> UnspacedList:
        """Returns array with the "include" directives expanded out by
        concatenating the contents of the included file to the block.

        :param list block:
        :rtype: list

        """
        result = copy.deepcopy(block)  # Copy the list to keep self.parsed idempotent
        for directive in block:
            if _is_include_directive(directive):
                included_files = glob.glob(
                    self.abs_path(directive[1]))
                for incl in included_files:
                    try:
                        result.extend(self.parsed[incl])
                    except KeyError:
                        pass
        return result

    def _parse_files(self, filepath: str, override: bool = False) -> List[UnspacedList]:
        """Parse files from a glob

        :param str filepath: Nginx config file path
        :param bool override: Whether to parse a file that has been parsed
        :returns: list of parsed tree structures
        :rtype: list

        """
        files = glob.glob(filepath) # nginx on unix calls glob(3) for this
                                    # XXX Windows nginx uses FindFirstFile, and
                                    # should have a narrower call here
        trees = []
        for item in files:
            if item in self.parsed and not override:
                continue
            try:
                with open(item, "r", encoding="utf-8") as _file:
                    parsed = nginxparser.load(_file)
                    self.parsed[item] = parsed
                    trees.append(parsed)
            except OSError:
                logger.warning("Could not open file: %s", item)
            except UnicodeDecodeError:
                logger.warning("Could not read file: %s due to invalid "
                               "character. Only UTF-8 encoding is "
                               "supported.", item)
            except pyparsing.ParseException as err:
                logger.warning("Could not parse file: %s due to %s", item, err)
        return trees

    def _find_config_root(self) -> str:
        """Return the Nginx Configuration Root file."""
        location = ['nginx.conf']

        for name in location:
            if os.path.isfile(os.path.join(self.root, name)):
                return os.path.join(self.root, name)

        raise errors.NoInstallationError(
            "Could not find Nginx root configuration file (nginx.conf)")

    def filedump(self, ext: str = 'tmp', lazy: bool = True) -> None:
        """Dumps parsed configurations into files.

        :param str ext: The file extension to use for the dumped files. If
            empty, this overrides the existing conf files.
        :param bool lazy: Only write files that have been modified

        """
        # Best-effort atomicity is enforced above us by reverter.py
        for filename, tree in self.parsed.items():
            if ext:
                filename = filename + os.path.extsep + ext
            if not isinstance(tree, UnspacedList):
                raise ValueError(f"Error tree {tree} is not an UnspacedList")
            try:
                if lazy and not tree.is_dirty():
                    continue
                out = nginxparser.dumps(tree)
                logger.debug('Writing nginx conf tree to %s:\n%s', filename, out)
                with open(filename, 'w', encoding='utf-8') as _file:
                    _file.write(out)

            except OSError:
                logger.error("Could not open file for writing: %s", filename)

    def parse_server(self, server: UnspacedList) -> Dict[str, Any]:
        """Parses a list of server directives, accounting for global address sslishness.

        :param list server: list of directives in a server block
        :rtype: dict
        """
        addr_to_ssl = self._build_addr_to_ssl()
        parsed_server = _parse_server_raw(server)
        _apply_global_addr_ssl(addr_to_ssl, parsed_server)
        return parsed_server

    def has_ssl_on_directive(self, vhost: obj.VirtualHost) -> bool:
        """Does vhost have ssl on for all ports?

        :param :class:`~certbot_nginx._internal.obj.VirtualHost` vhost: The vhost in question

        :returns: True if 'ssl on' directive is included
        :rtype: bool

        """
        server = vhost.raw
        for directive in server:
            if not directive:
                continue
            if _is_ssl_on_directive(directive):
                return True

        return False

    def add_server_directives(self, vhost: obj.VirtualHost, directives: List[Any],
                              insert_at_top: bool = False) -> None:
        """Add directives to the server block identified by vhost.

        This method modifies vhost to be fully consistent with the new directives.

        ..note :: It's an error to try and add a nonrepeatable directive that already
            exists in the config block with a conflicting value.

        ..todo :: Doesn't match server blocks whose server_name directives are
            split across multiple conf files.

        :param :class:`~certbot_nginx._internal.obj.VirtualHost` vhost: The vhost
            whose information we use to match on
        :param list directives: The directives to add
        :param bool insert_at_top: True if the directives need to be inserted at the top
            of the server block instead of the bottom

        """
        self._modify_server_directives(vhost,
            functools.partial(_add_directives, directives, insert_at_top))

    def update_or_add_server_directives(self, vhost: obj.VirtualHost, directives: List[Any],
                                        insert_at_top: bool = False) -> None:
        """Add or replace directives in the server block identified by vhost.

        This method modifies vhost to be fully consistent with the new directives.

        ..note :: When a directive with the same name already exists in the
        config block, the first instance will be replaced. Otherwise, the directive
        will be appended/prepended to the config block as in add_server_directives.

        ..todo :: Doesn't match server blocks whose server_name directives are
            split across multiple conf files.

        :param :class:`~certbot_nginx._internal.obj.VirtualHost` vhost: The vhost
            whose information we use to match on
        :param list directives: The directives to add
        :param bool insert_at_top: True if the directives need to be inserted at the top
            of the server block instead of the bottom

        """
        self._modify_server_directives(vhost,
            functools.partial(_update_or_add_directives, directives, insert_at_top))

    def remove_server_directives(self, vhost: obj.VirtualHost, directive_name: str,
                                 match_func: Optional[Callable[[Any], bool]] = None) -> None:
        """Remove all directives of type directive_name.

        :param :class:`~certbot_nginx._internal.obj.VirtualHost` vhost: The vhost
            to remove directives from
        :param string directive_name: The directive type to remove
        :param callable match_func: Function of the directive that returns true for directives
            to be deleted.
        """
        self._modify_server_directives(vhost,
            functools.partial(_remove_directives, directive_name, match_func))

    def _update_vhost_based_on_new_directives(self, vhost: obj.VirtualHost,
                                              directives_list: UnspacedList) -> None:
        new_server = self._get_included_directives(directives_list)
        parsed_server = self.parse_server(new_server)
        vhost.addrs = parsed_server['addrs']
        vhost.ssl = parsed_server['ssl']
        vhost.names = parsed_server['names']
        vhost.raw = new_server

    def _modify_server_directives(self, vhost: obj.VirtualHost,
                                  block_func: Callable[[List[Any]], None]) -> None:
        filename = vhost.filep
        try:
            result = self.parsed[filename]
            for index in vhost.path:
                result = result[index]
            if not isinstance(result, list) or len(result) != 2:
                raise errors.MisconfigurationError("Not a server block.")
            result = result[1]
            block_func(result)

            self._update_vhost_based_on_new_directives(vhost, result)
        except errors.MisconfigurationError as err:
            raise errors.MisconfigurationError("Problem in %s: %s" % (filename, str(err)))

    def duplicate_vhost(self, vhost_template: obj.VirtualHost,
                        remove_singleton_listen_params: bool = False,
                        only_directives: Optional[List[Any]] = None) -> obj.VirtualHost:
        """Duplicate the vhost in the configuration files.

        :param :class:`~certbot_nginx._internal.obj.VirtualHost` vhost_template: The vhost
            whose information we copy
        :param bool remove_singleton_listen_params: If we should remove parameters
            from listen directives in the block that can only be used once per address
        :param list only_directives: If it exists, only duplicate the named directives. Only
            looks at first level of depth; does not expand includes.

        :returns: A vhost object for the newly created vhost
        :rtype: :class:`~certbot_nginx._internal.obj.VirtualHost`
        """
        # TODO: https://github.com/certbot/certbot/issues/5185
        # put it in the same file as the template, at the same level
        new_vhost = copy.deepcopy(vhost_template)

        enclosing_block = self.parsed[vhost_template.filep]
        for index in vhost_template.path[:-1]:
            enclosing_block = enclosing_block[index]
        raw_in_parsed = copy.deepcopy(enclosing_block[vhost_template.path[-1]])

        if only_directives is not None:
            new_directives = nginxparser.UnspacedList([])
            for directive in raw_in_parsed[1]:
                if directive and directive[0] in only_directives:
                    new_directives.append(directive)
            raw_in_parsed[1] = new_directives

            self._update_vhost_based_on_new_directives(new_vhost, new_directives)

        enclosing_block.append(raw_in_parsed)
        new_vhost.path[-1] = len(enclosing_block) - 1
        if remove_singleton_listen_params:
            for addr in new_vhost.addrs:
                addr.default = False
                addr.ipv6only = False
            for directive in enclosing_block[new_vhost.path[-1]][1]:
                if directive and directive[0] == 'listen':
                    # Exclude one-time use parameters which will cause an error if repeated.
                    # https://nginx.org/en/docs/http/ngx_http_core_module.html#listen
                    exclude = {'default_server', 'default', 'setfib', 'fastopen', 'backlog',
                                   'rcvbuf', 'sndbuf', 'accept_filter', 'deferred', 'bind',
                                   'ipv6only', 'reuseport', 'so_keepalive'}

                    for param in exclude:
                        # See: github.com/certbot/certbot/pull/6223#pullrequestreview-143019225
                        keys = [x.split('=')[0] for x in directive]
                        if param in keys:
                            del directive[keys.index(param)]
        return new_vhost


def _parse_ssl_options(ssl_options: Optional[str]) -> List[UnspacedList]:
    if ssl_options is not None:
        try:
            with open(ssl_options, "r", encoding="utf-8") as _file:
                return nginxparser.load(_file)
        except OSError:
            logger.warning("Missing NGINX TLS options file: %s", ssl_options)
        except UnicodeDecodeError:
            logger.warning("Could not read file: %s due to invalid character. "
                           "Only UTF-8 encoding is supported.", ssl_options)
        except pyparsing.ParseBaseException as err:
            logger.warning("Could not parse file: %s due to %s", ssl_options, err)
    return UnspacedList([])


def _do_for_subarray(entry: List[Any], condition: Callable[[List[Any]], bool],
                     func: Callable[[List[Any], List[int]], None],
                     path: Optional[List[int]] = None) -> None:
    """Executes a function for a subarray of a nested array if it matches
    the given condition.

    :param list entry: The list to iterate over
    :param function condition: Returns true iff func should be executed on item
    :param function func: The function to call for each matching item

    """
    if path is None:
        path = []
    if isinstance(entry, list):
        if condition(entry):
            func(entry, path)
        else:
            for index, item in enumerate(entry):
                _do_for_subarray(item, condition, func, path + [index])


def get_best_match(target_name: str, names: Iterable[str]) -> Tuple[Optional[str], Optional[str]]:
    """Finds the best match for target_name out of names using the Nginx
    name-matching rules (exact > longest wildcard starting with * >
    longest wildcard ending with * > regex).

    :param str target_name: The name to match
    :param set names: The candidate server names
    :returns: Tuple of (type of match, the name that matched)
    :rtype: tuple

    """
    exact = []
    wildcard_start = []
    wildcard_end = []
    regex = []

    for name in names:
        if _exact_match(target_name, name):
            exact.append(name)
        elif _wildcard_match(target_name, name, True):
            wildcard_start.append(name)
        elif _wildcard_match(target_name, name, False):
            wildcard_end.append(name)
        elif _regex_match(target_name, name):
            regex.append(name)

    if exact:
        # There can be more than one exact match; e.g. eff.org, .eff.org
        match = min(exact, key=len)
        return 'exact', match
    if wildcard_start:
        # Return the longest wildcard
        match = max(wildcard_start, key=len)
        return 'wildcard_start', match
    if wildcard_end:
        # Return the longest wildcard
        match = max(wildcard_end, key=len)
        return 'wildcard_end', match
    if regex:
        # Just return the first one for now
        match = regex[0]
        return 'regex', match

    return None, None


def _exact_match(target_name: str, name: str) -> bool:
    target_lower = target_name.lower()
    return name.lower() in (target_lower, '.' + target_lower)


def _wildcard_match(target_name: str, name: str, start: bool) -> bool:
    # Degenerate case
    if name == '*':
        return True

    parts = target_name.split('.')
    match_parts = name.split('.')

    # If the domain ends in a wildcard, do the match procedure in reverse
    if not start:
        parts.reverse()
        match_parts.reverse()

    # The first part must be a wildcard or blank, e.g. '.eff.org'
    first = match_parts.pop(0)
    if first not in ('*', ''):
        return False

    target_name_lower = '.'.join(parts).lower()
    name_lower = '.'.join(match_parts).lower()

    # Ex: www.eff.org matches *.eff.org, eff.org does not match *.eff.org
    return target_name_lower.endswith('.' + name_lower)


def _regex_match(target_name: str, name: str) -> bool:
    # Must start with a tilde
    if len(name) < 2 or name[0] != '~':
        return False

    # After tilde is a perl-compatible regex
    try:
        regex = re.compile(name[1:])
        return bool(re.match(regex, target_name))
    except re.error:  # pragma: no cover
        # perl-compatible regexes are sometimes not recognized by python
        return False


def _is_include_directive(entry: Any) -> bool:
    """Checks if an nginx parsed entry is an 'include' directive.

    :param list entry: the parsed entry
    :returns: Whether it's an 'include' directive
    :rtype: bool

    """
    return (isinstance(entry, list) and
            len(entry) == 2 and entry[0] == 'include' and
            isinstance(entry[1], str))


def _is_ssl_on_directive(entry: Any) -> bool:
    """Checks if an nginx parsed entry is an 'ssl on' directive.

    :param list entry: the parsed entry
    :returns: Whether it's an 'ssl on' directive
    :rtype: bool

    """
    return (isinstance(entry, list) and
            len(entry) == 2 and entry[0] == 'ssl' and
            entry[1] == 'on')


def _add_directives(directives: List[Any], insert_at_top: bool,
                    block: UnspacedList) -> None:
    """Adds directives to a config block."""
    for directive in directives:
        _add_directive(block, directive, insert_at_top)
    if block and '\n' not in block[-1]:  # could be "   \n  " or ["\n"] !
        block.append(nginxparser.UnspacedList('\n'))


def _update_or_add_directives(directives: List[Any], insert_at_top: bool,
                              block: UnspacedList) -> None:
    """Adds or replaces directives in a config block."""
    for directive in directives:
        _update_or_add_directive(block, directive, insert_at_top)
    if block and '\n' not in block[-1]:  # could be "   \n  " or ["\n"] !
        block.append(nginxparser.UnspacedList('\n'))


INCLUDE = 'include'
REPEATABLE_DIRECTIVES = {'server_name', 'listen', INCLUDE, 'rewrite', 'add_header'}
COMMENT = ' managed by Certbot'
COMMENT_BLOCK = [' ', '#', COMMENT]


def comment_directive(block: UnspacedList, location: int) -> None:
    """Add a ``#managed by Certbot`` comment to the end of the line at location.

    :param list block: The block containing the directive to be commented
    :param int location: The location within ``block`` of the directive to be commented
    """
    next_entry = block[location + 1] if location + 1 < len(block) else None
    if isinstance(next_entry, list) and next_entry:
        if len(next_entry) >= 2 and next_entry[-2] == "#" and COMMENT in next_entry[-1]:
            return
        if isinstance(next_entry, nginxparser.UnspacedList):
            next_entry = next_entry.spaced[0]
        else:
            next_entry = next_entry[0]

    block.insert(location + 1, COMMENT_BLOCK[:])
    if next_entry is not None and "\n" not in next_entry:
        block.insert(location + 2, '\n')


def _comment_out_directive(block: UnspacedList, location: int, include_location: str) -> None:
    """Comment out the line at location, with a note of explanation."""
    comment_message = ' duplicated in {0}'.format(include_location)
    # add the end comment
    # create a dumpable object out of block[location] (so it includes the ;)
    directive = block[location]
    new_dir_block = nginxparser.UnspacedList([])  # just a wrapper
    new_dir_block.append(directive)
    dumped = nginxparser.dumps(new_dir_block)
    commented = dumped + ' #' + comment_message  # add the comment directly to the one-line string
    new_dir = nginxparser.loads(commented)  # reload into UnspacedList

    # add the beginning comment
    insert_location = 0
    if new_dir[0].spaced[0] != new_dir[0][0]:  # if there's whitespace at the beginning
        insert_location = 1
    new_dir[0].spaced.insert(insert_location, "# ")  # comment out the line
    new_dir[0].spaced.append(";")  # directly add in the ;, because now dumping won't work properly
    dumped = nginxparser.dumps(new_dir)
    new_dir = nginxparser.loads(dumped)  # reload into an UnspacedList

    block[location] = new_dir[0] # set the now-single-line-comment directive back in place


def _find_location(block: UnspacedList, directive_name: str,
                   match_func: Optional[Callable[[Any], bool]] = None) -> Optional[int]:
    """Finds the index of the first instance of directive_name in block.
       If no line exists, use None."""
    return next((index for index, line in enumerate(block) if (
        line and line[0] == directive_name and (match_func is None or match_func(line)))), None)


def _is_whitespace_or_comment(directive: Sequence[Any]) -> bool:
    """Is this directive either a whitespace or comment directive?"""
    return len(directive) == 0 or directive[0] == '#'


def _add_directive(block: UnspacedList, directive: Sequence[Any], insert_at_top: bool) -> None:
    if not isinstance(directive, nginxparser.UnspacedList):
        directive = nginxparser.UnspacedList(directive)
    if _is_whitespace_or_comment(directive):
        # whitespace or comment
        block.append(directive)
        return

    location = _find_location(block, directive[0])

    # Append or prepend directive. Fail if the name is not a repeatable directive name,
    # and there is already a copy of that directive with a different value
    # in the config file.

    # handle flat include files

    directive_name = directive[0]

    def can_append(loc: Optional[int], dir_name: str) -> bool:
        """ Can we append this directive to the block? """
        return loc is None or (isinstance(dir_name, str)
                               and dir_name in REPEATABLE_DIRECTIVES)

    err_fmt = 'tried to insert directive "{0}" but found conflicting "{1}".'

    # Give a better error message about the specific directive than Nginx's "fail to restart"
    if directive_name == INCLUDE:
        # in theory, we might want to do this recursively, but in practice, that's really not
        # necessary because we know what file we're talking about (and if we don't recurse, we
        # just give a worse error message)
        included_directives = _parse_ssl_options(directive[1])

        for included_directive in included_directives:
            included_dir_loc = _find_location(block, included_directive[0])
            included_dir_name = included_directive[0]
            if (not _is_whitespace_or_comment(included_directive)
                    and not can_append(included_dir_loc, included_dir_name)):

                # By construction of can_append(), included_dir_loc cannot be None at that point
                resolved_included_dir_loc = cast(int, included_dir_loc)

                if block[resolved_included_dir_loc] != included_directive:
                    raise errors.MisconfigurationError(err_fmt.format(
                        included_directive, block[resolved_included_dir_loc]))
                _comment_out_directive(block, resolved_included_dir_loc, directive[1])

    if can_append(location, directive_name):
        if insert_at_top:
            # Add a newline so the comment doesn't comment
            # out existing directives
            block.insert(0, nginxparser.UnspacedList('\n'))
            block.insert(0, directive)
            comment_directive(block, 0)
        else:
            block.append(directive)
            comment_directive(block, len(block) - 1)
        return

    # By construction of can_append(), location cannot be None at that point
    resolved_location = cast(int, location)

    if block[resolved_location] != directive:
        raise errors.MisconfigurationError(err_fmt.format(directive, block[resolved_location]))


def _update_directive(block: UnspacedList, directive: Sequence[Any], location: int) -> None:
    block[location] = directive
    comment_directive(block, location)


def _update_or_add_directive(block: UnspacedList, directive: Sequence[Any],
                             insert_at_top: bool) -> None:
    if not isinstance(directive, nginxparser.UnspacedList):
        directive = nginxparser.UnspacedList(directive)
    if _is_whitespace_or_comment(directive):
        # whitespace or comment
        block.append(directive)
        return

    location = _find_location(block, directive[0])

    # we can update directive
    if location is not None:
        _update_directive(block, directive, location)
        return

    _add_directive(block, directive, insert_at_top)


def _is_certbot_comment(directive: Sequence[Any]) -> bool:
    return '#' in directive and COMMENT in directive


def _remove_directives(directive_name: str, match_func: Callable[[Any], bool],
                       block: UnspacedList) -> None:
    """Removes directives of name directive_name from a config block if match_func matches.
    """
    while True:
        location = _find_location(block, directive_name, match_func=match_func)
        if location is None:
            return
        # if the directive was made by us, remove the comment following
        if location + 1 < len(block) and _is_certbot_comment(block[location + 1]):
            del block[location + 1]
        del block[location]


def _apply_global_addr_ssl(addr_to_ssl: Mapping[Tuple[str, str], bool],
                           parsed_server: Dict[str, Any]) -> None:
    """Apply global sslishness information to the parsed server block
    """
    for addr in parsed_server['addrs']:
        addr.ssl = addr_to_ssl[addr.normalized_tuple()]
        if addr.ssl:
            parsed_server['ssl'] = True


def _parse_server_raw(server: UnspacedList) -> Dict[str, Any]:
    """Parses a list of server directives.

    :param list server: list of directives in a server block
    :rtype: dict

    """
    addrs: Set[obj.Addr] = set()
    ssl: bool = False
    names: Set[str] = set()

    apply_ssl_to_all_addrs = False

    for directive in server:
        if not directive:
            continue
        if directive[0] == 'listen':
            addr = obj.Addr.fromstring(" ".join(directive[1:]))
            if addr:
                addrs.add(addr)
                if addr.ssl:
                    ssl = True
        elif directive[0] == 'server_name':
            params = directive[1:]
            while '#' in params:
                end_index = [i for i, param in enumerate(params) if param.startswith('\n')][0]
                params = params[:params.index('#')] + params[end_index+1:]
            names.update(x.strip('"\'') for x in params)
        elif _is_ssl_on_directive(directive):
            ssl = True
            apply_ssl_to_all_addrs = True

    if apply_ssl_to_all_addrs:
        for addr in addrs:
            addr.ssl = True

    return {
        'addrs': addrs,
        'ssl': ssl,
        'names': names
    }
