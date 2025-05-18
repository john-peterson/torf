import os
import functools
import collections


def is_sequence(obj):
    """Whether `obj` is a sequence but not a :class:`str`"""
    return (
        not isinstance(obj, (str, bytes, bytearray))
        and isinstance(obj, collections.abc.Sequence)
    )


def flatten(items):
    """Yield all items from nested iterables"""
    flat_items = []
    for item in items:
        if isinstance(item, collections.abc.Iterable) and not isinstance(item, str):
            flat_items.extend(flatten(item))
        else:
            flat_items.append(item)
    return tuple(flat_items)


def iterable_startswith(a, b):
    """Whether sequence `a` starts with the items in sequence `b`"""
    return tuple(a[:len(b)]) == tuple(b)


class File(str):
    """
    :class:`str` with :attr:`size` and :attr:`path` attribute

    :param path: File path as sequence (e.g. ``("foo", "bar", "baz")`` -> "foo/bar/baz")
    :param size: Size of the file in bytes
    """

    def __new__(cls, *path, size):
        try:
            self = super().__new__(cls, os.path.join(*path))
        except TypeError:
            raise ValueError(f'Unexpected path: {path!r}')
        self._path = tuple(self.split(os.path.sep))
        try:
            self._size = int(size)
        except (ValueError, TypeError):
            raise ValueError(f'size must be int, not {type(size).__name__}: {size!r}')
        return self

    @property
    def path(self):
        """Individual path components"""
        return self._path

    @property
    def size(self):
        """Size of the file in bytes"""
        return self._size

    @property
    def name(self):
        """Last item in :attr:`path`"""
        return self._path[-1]

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return (
                self.path == other.path
                and self.size == other.size
            )
        else:
            return NotImplemented

    def __hash__(self):
        return hash((self.path, self.size))

    def __repr__(self):
        posargs = ', '.join(repr(part) for part in self.path)
        kwargs = f'size={self.size}'
        args = ', '.join((posargs, kwargs))
        return f'{type(self).__name__}({args})'
