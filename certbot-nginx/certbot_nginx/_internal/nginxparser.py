"""Very low-level nginx config parser based on pyparsing."""
# Forked from https://github.com/fatiherikli/nginxparser (MIT Licensed)
import copy
import logging
import operator
import typing
from typing import Any
from typing import IO
from typing import Iterable
from typing import Iterator
from typing import List
from typing import overload
from typing import SupportsIndex
from typing import Tuple
from typing import Union

from pyparsing import Combine
from pyparsing import Forward
from pyparsing import Group
from pyparsing import Literal
from pyparsing import Optional
from pyparsing import ParseResults
from pyparsing import QuotedString
from pyparsing import Regex
from pyparsing import restOfLine
from pyparsing import stringEnd
from pyparsing import White
from pyparsing import ZeroOrMore

logger = logging.getLogger(__name__)


class RawNginxParser:
    # pylint: disable=pointless-statement
    """A class that parses nginx configuration with pyparsing."""

    # constants
    space = Optional(White()).leaveWhitespace()
    required_space = White().leaveWhitespace()

    left_bracket = Literal("{").suppress()
    right_bracket = space + Literal("}").suppress()
    semicolon = Literal(";").suppress()
    dquoted = QuotedString('"', multiline=True, unquoteResults=False, escChar='\\')
    squoted = QuotedString("'", multiline=True, unquoteResults=False, escChar='\\')
    quoted = dquoted | squoted
    head_tokenchars = Regex(r"(\$\{)|[^{};\s'\"]") # if (last_space)
    tail_tokenchars = Regex(r"(\$\{)|[^{;\s]") # else
    lua_regex = Regex(r"[^{;\s}]+_by_lua_[^{]+") # regex for lua token
    tokenchars = Combine(head_tokenchars + ZeroOrMore(tail_tokenchars))
    paren_quote_extend = Combine(quoted + Literal(')') + ZeroOrMore(tail_tokenchars))
    # note: ')' allows extension, but then we fall into else, not last_space.

    token = paren_quote_extend | tokenchars | quoted

    whitespace_token_group = space + token + ZeroOrMore(required_space + token) + space
    assignment = whitespace_token_group + semicolon

    comment = space + Literal('#') + restOfLine

    block = Forward()
    anything_block = Forward()
    anything_content =  Regex(r"[^{}]+")
    anything_block <<= left_bracket + ZeroOrMore(anything_content | anything_block) + right_bracket
    lua_block = space + lua_regex + anything_block

    # order matters! see issue 518, and also http { # server { \n}
    contents = Group(comment) | Group(block) | Group(assignment)
    block_begin = Group(whitespace_token_group)
    block_innards = Group(ZeroOrMore(contents) + space).leaveWhitespace()
    block << block_begin + left_bracket + block_innards + right_bracket

    script = ZeroOrMore(contents) + space + stringEnd
    script.ignore(lua_block)
    script.parseWithTabs().leaveWhitespace()

    def __init__(self, source: str) -> None:
        self.source = source

    def parse(self) -> ParseResults:
        """Returns the parsed tree."""
        return self.script.parseString(self.source)

    def as_list(self) -> List[Any]:
        """Returns the parsed tree as a list."""
        return self.parse().asList()


class RawNginxDumper:
    """A class that dumps nginx configuration from the provided tree."""
    def __init__(self, blocks: List[Any]) -> None:
        self.blocks = blocks

    def __iter__(self, blocks: typing.Optional[List[Any]] = None) -> Iterator[str]:
        """Iterates the dumped nginx content."""
        blocks = blocks or self.blocks
        for b0 in blocks:
            if isinstance(b0, str):
                yield b0
                continue
            item = copy.deepcopy(b0)
            if spacey(item[0]):
                yield item.pop(0) # indentation
                if not item:
                    continue

            if isinstance(item[0], list): # block
                yield "".join(item.pop(0)) + '{'
                for parameter in item.pop(0):
                    for line in self.__iter__([parameter]): # negate "for b0 in blocks"
                        yield line
                yield '}'
            else: # not a block - list of strings
                semicolon = ";"
                if isinstance(item[0], str) and item[0].strip() == '#': # comment
                    semicolon = ""
                yield "".join(item) + semicolon

    def __str__(self) -> str:
        """Return the parsed block as a string."""
        return ''.join(self)


def spacey(x: Any) -> bool:
    """Is x an empty string or whitespace?"""
    return (isinstance(x, str) and x.isspace()) or x == ''


class UnspacedList(List[Any]):
    """Wrap a list [of lists], making any whitespace entries magically invisible"""

    def __init__(self, list_source: Iterable[Any]) -> None:
        # ensure our argument is not a generator, and duplicate any sublists
        self.spaced = copy.deepcopy(list(list_source))
        self.dirty = False

        # Turn self into a version of the source list that has spaces removed
        # and all sub-lists also UnspacedList()ed
        super().__init__(list_source)
        for i, entry in reversed(list(enumerate(self))):
            if isinstance(entry, list):
                sublist = UnspacedList(entry)
                super().__setitem__(i, sublist)
                self.spaced[i] = sublist.spaced
            elif spacey(entry):
                # don't delete comments
                if "#" not in self[:i]:
                    super().__delitem__(i)

    @overload
    def _coerce(self, inbound: None) -> Tuple[None, None]: ...

    @overload
    def _coerce(self, inbound: str) -> Tuple[str, str]: ...

    @overload
    def _coerce(self, inbound: List[Any]) -> Tuple["UnspacedList", List[Any]]: ...

    def _coerce(self, inbound: Any) -> Tuple[Any, Any]:
        """
        Coerce some inbound object to be appropriately usable in this object

        :param inbound: string or None or list or UnspacedList
        :returns: (coerced UnspacedList or string or None, spaced equivalent)
        :rtype: tuple

        """
        if not isinstance(inbound, list):  # str or None
            return inbound, inbound
        else:
            if not hasattr(inbound, "spaced"):
                inbound = UnspacedList(inbound)
            return inbound, inbound.spaced

    def insert(self, i: "SupportsIndex", x: Any) -> None:
        """Insert object before index."""
        idx = operator.index(i)
        item, spaced_item = self._coerce(x)
        slicepos = self._spaced_position(idx) if idx < len(self) else len(self.spaced)
        self.spaced.insert(slicepos, spaced_item)
        if not spacey(item):
            super().insert(idx, item)
        self.dirty = True

    def append(self, x: Any) -> None:
        """Append object to the end of the list."""
        item, spaced_item = self._coerce(x)
        self.spaced.append(spaced_item)
        if not spacey(item):
            super().append(item)
        self.dirty = True

    def extend(self, x: Any) -> None:
        """Extend list by appending elements from the iterable."""
        item, spaced_item = self._coerce(x)
        self.spaced.extend(spaced_item)
        super().extend(item)
        self.dirty = True

    def __add__(self, other: List[Any]) -> "UnspacedList":
        new_list = copy.deepcopy(self)
        new_list.extend(other)
        new_list.dirty = True
        return new_list

    def pop(self, *args: Any, **kwargs: Any) -> None:
        """Function pop() is not implemented for UnspacedList"""
        raise NotImplementedError("UnspacedList.pop() not yet implemented")

    def remove(self, *args: Any, **kwargs: Any) -> None:
        """Function remove() is not implemented for UnspacedList"""
        raise NotImplementedError("UnspacedList.remove() not yet implemented")

    def reverse(self) -> None:
        """Function reverse() is not implemented for UnspacedList"""
        raise NotImplementedError("UnspacedList.reverse() not yet implemented")

    def sort(self, *_args: Any, **_kwargs: Any) -> None:
        """Function sort() is not implemented for UnspacedList"""
        raise NotImplementedError("UnspacedList.sort() not yet implemented")

    def __setslice__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError("Slice operations on UnspacedLists not yet implemented")

    def __setitem__(self, i: Union["SupportsIndex", slice], value: Any) -> None:
        if isinstance(i, slice):
            raise NotImplementedError("Slice operations on UnspacedLists not yet implemented")
        item, spaced_item = self._coerce(value)
        self.spaced.__setitem__(self._spaced_position(i), spaced_item)
        if not spacey(item):
            super().__setitem__(i, item)
        self.dirty = True

    def __delitem__(self, i: Union["SupportsIndex", slice]) -> None:
        if isinstance(i, slice):
            raise NotImplementedError("Slice operations on UnspacedLists not yet implemented")
        self.spaced.__delitem__(self._spaced_position(i))
        super().__delitem__(i)
        self.dirty = True

    def __deepcopy__(self, memo: Any) -> "UnspacedList":
        new_spaced = copy.deepcopy(self.spaced, memo=memo)
        new_list = UnspacedList(new_spaced)
        new_list.dirty = self.dirty
        return new_list

    def is_dirty(self) -> bool:
        """Recurse through the parse tree to figure out if any sublists are dirty"""
        if self.dirty:
            return True
        return any((isinstance(x, UnspacedList) and x.is_dirty() for x in self))

    def _spaced_position(self, idx: "SupportsIndex") -> int:
        """Convert from indexes in the unspaced list to positions in the spaced one"""
        int_idx = operator.index(idx)
        pos = spaces = 0
        # Normalize indexes like list[-1] etc, and save the result
        if int_idx < 0:
            int_idx = len(self) + int_idx
        if not 0 <= int_idx < len(self):
            raise IndexError("list index out of range")
        int_idx0 = int_idx
        # Count the number of spaces in the spaced list before int_idx in the unspaced one
        while int_idx != -1:
            if spacey(self.spaced[pos]):
                spaces += 1
            else:
                int_idx -= 1
            pos += 1
        return int_idx0 + spaces


# Shortcut functions to respect Python's serialization interface
# (like pyyaml, picker or json)

def loads(source: str) -> UnspacedList:
    """Parses from a string.

    :param str source: The string to parse
    :returns: The parsed tree
    :rtype: list

    """
    return UnspacedList(RawNginxParser(source).as_list())


def load(file_: IO[Any]) -> UnspacedList:
    """Parses from a file.

    :param file file_: The file to parse
    :returns: The parsed tree
    :rtype: list

    """
    return loads(file_.read())


def dumps(blocks: UnspacedList) -> str:
    """Dump to a Unicode string.

    :param UnspacedList blocks: The parsed tree
    :rtype: str

    """
    return str(RawNginxDumper(blocks.spaced))


def dump(blocks: UnspacedList, file_: IO[Any]) -> None:
    """Dump to a file.

    :param UnspacedList blocks: The parsed tree
    :param IO[Any] file_: The file stream to dump to. It must be opened with
                          Unicode encoding.
    :rtype: None

    """
    file_.write(dumps(blocks))
