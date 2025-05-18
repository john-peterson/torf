import base64
import collections
import datetime
import functools
import hashlib
import inspect
import math
import os

from .. import __version__, _bencode, _errors, _metainfo, _utils

NO_DEFAULT = object()
PACKAGE_NAME = __name__.split('.')[0]


class KeywordArguments:
    def __init__(self, provided, defaults):
        for key in provided:
            assert key in defaults
        self.provided = provided
        self.defaults = defaults
        self.all = {**defaults, **provided}


def _get_kwargs():
    """
    Return keyword arguments of the caller method as :class:`dict`

    Defaults are ommitted.
    """
    caller_frame = inspect.currentframe().f_back
    argvalues = inspect.getargvalues(caller_frame)

    # self = argvalues.locals['self']
    # cls = type(self)
    cls = Torrent

    caller_name = caller_frame.f_code.co_name
    caller = getattr(cls, caller_name)
    signature = inspect.signature(caller)

    defaults = {
        name: parameter.default
        for name, parameter in signature.parameters.items()
        if name != 'self'
    }
    # print('defaults:', defaults)

    # For mutable values, if we store the original and it is modified later, our internally stored
    # value suddenly has a different value. If that modified value is used in __repr__() or copy(),
    # horrible things can happen. So here we create a copy of potentially mutable arguments.
    type_map = {
        _utils.is_sequence: lambda x: tuple(
            get_storable_value(item) for item in x
        ),
        lambda x: isinstance(x, collections.abc.Iterator): lambda x: tuple(
            get_storable_value(item) for item in x
        ),
    }

    def get_storable_value(value):
        for is_type, create_copy in type_map.items():
            if is_type(value):
                return create_copy(value)
        return value

    kwargs = {
        name: get_storable_value(argvalues.locals[name])
        for name in argvalues.args
        if (
                name != 'self'
                and argvalues.locals[name] != defaults[name]
        )
    }
    return KeywordArguments(kwargs, defaults)


class Torrent:
    """
    ...
    """

    MAX_TORRENT_SIZE = int(30e6)  # 30MB
    """
    Maximum length of bencoded metainfo

    Reading anything larger will raise an exception. We don't want to read gigabytes into memory if
    a wrong file/stream is accidentally passed.

    :param str encoding: Metainfo encoding for :class:`str` values

        .. important:: Only UTF-8 creates compliant torrents. This option only exists to read
            non-compliant torrents.

        A list of valid `encoding` values can be found here:
        https://docs.python.org/3/library/codecs.html#standard-encodings

    :param bool raise_on_decoding_error: Whether decoding badly encoded strings should raise
        :class:`CodecError` or the relevant characters should be replaced with "�" (Unicode
        "REPLACEMENT CHARACTER")

    :param bool validate: Whether the provided metadata should be checked to make sure it represents
        a valid torrent

    :raise: :class:`TypeError` or :class:`ValueError` if any argument is invalid
    """

    def __init__(
            self,
            *,
            encoding='UTF-8',
            raise_on_decoding_error=False,
            validate=True,
            # Metainfo arguments
            announce=(),
            comment='',
            created_by=f'{PACKAGE_NAME} {__version__}',
            creation_date=None,
            files=(),
            httpseeds=(),
            name='',
            pieces=b'',
            private=False,
            source='',
            webseeds=(),
            metainfo=None,
    ):
        self._kwargs = _get_kwargs()
        print(f'[{id(self)}]: INIT: FOUND PROVIDED KWARGS: {self._kwargs.provided}')
        self._handle_kwargs(self._kwargs.provided)

        if metainfo is not None:
            self.metainfo.update(metainfo)

        if validate:
            print(f'[{id(self)}]: INIT: CALLING VALIDATE():', repr(self.validate))
            self.validate()
        else:
            print(f'[{id(self)}]: INIT: NOT CALLING VALIDATE():', repr(self.validate))

    def _handle_kwargs(self, kwargs):
        for name, value in kwargs.items():
            if name not in ('validate', 'metainfo'):
                method = getattr(self, f'_handle_kwarg_{name}', None)
                print(f'[{id(self)}] calling {method}({value!r})')
                method(value)

    def _handle_kwarg_encoding(self, encoding):
        self.metainfo.values_encoding = encoding

    def _handle_kwarg_raise_on_decoding_error(self, raise_on_decoding_error):
        self.metainfo.raise_on_decoding_error = raise_on_decoding_error

    def copy(self, **kwargs):
        """
        Create copy of an instance

        This method takes the same arguments as the class. They overload the original arguments that
        were provided when the instance was created.

        :return: :class:`Torrent` instance
        """
        # Create blank instance. Nothing to validate.
        copy = type(self)(validate=False)

        # Copy original metainfo, including any non-standard values.
        copy.metainfo.update(self.metainfo)

        # We must also provide keyword arguments because 1) they can have effects outside of
        # `metainfo` (e.g. "encoding") and 2) they update the existing `metainfo`. We combine the
        # original kwargs with our own so we only have to handle each argument once.
        combined_kwargs = {**self._kwargs.provided, **kwargs}
        copy._handle_kwargs(combined_kwargs)

        # Now we can validate the new copy unless the user prevents it.
        if combined_kwargs.get('validate', True):
            copy.validate()

        return copy

    def __repr__(self):
        if hasattr(self, '_kwargs'):
            kwargs = self._kwargs.provided.copy()
            if kwargs:
                # Don't display pieces in full, which is usually hundreds or thousands of bytes.
                if 'pieces' in kwargs and len(pieces := kwargs['pieces']) > 20:
                    kwargs['pieces'] = pieces[:8] + b'...' + pieces[-8:]
                kwargs_str = ' '.join(f'{k}={v!r}' for k, v in kwargs.items())
            else:
                kwargs_str = '[no arguments]'
        else:
            kwargs_str = '[unknown arguments]'
        return f'<{type(self).__name__} {kwargs_str}>'

    def _get_metainfo(self, *keypath, type=None, default=NO_DEFAULT):
        obj = self.metainfo
        for i, key in enumerate(keypath):
            try:
                obj = obj[key]
            except (KeyError, IndexError):
                if default is NO_DEFAULT:
                    path_so_far = '.'.join(str(k) for k in keypath[:i + 1])
                    raise ValueError(f'{path_so_far}: Not found')
                else:
                    return default
        if type:
            return type(obj)
        else:
            return obj

    def _set_metainfo(self, keypath, value):
        obj = self.metainfo
        if keypath[0] == 'info' and 'info' not in obj:
            obj['info'] = {}
        for key in keypath[:-1]:
            obj = obj[key]
        if value is None:
            try:
                del obj[keypath[-1]]
            except (KeyError, IndexError):
                pass
        else:
            obj[keypath[-1]] = value

    @property
    def announce(self):
        """
        :class:`tuple` of tiers (i.e. :class:`tuple`\\ s) of announce URLs

        https://bittorrent.org/beps/bep_0003.html
        https://bittorrent.org/beps/bep_0012.html
        """
        if 'announce-list' in self.metainfo:
            return tuple(
                tuple(url for url in tier)
                for tier in self.metainfo['announce-list']
            )
        elif 'announce' in self.metainfo:
            # Wrap only tracker in single tier.
            return (
                (self.metainfo['announce'],),
            )
        else:
            return ()

    def _handle_kwarg_announce(self, announce):
        if announce is None:
            self.metainfo.pop('announce', None)
            self.metainfo.pop('announce-list', None)

        elif isinstance(announce, str):
            if announce:
                self.metainfo['announce'] = announce
                # Remove "announce-list" if it exists.
                self.metainfo.pop('announce-list', None)
            else:
                raise ValueError('announce is empty string')

        elif isinstance(announce, collections.abc.Iterable):
            announce_list = []
            for announce_or_tier in announce:
                if isinstance(announce_or_tier, str):
                    announce_list.append((announce_or_tier,))
                elif isinstance(announce_or_tier, collections.abc.Iterable):
                    tier = []
                    for announce in announce_or_tier:
                        if isinstance(announce, str):
                            tier.append(announce)
                        else:
                            raise TypeError(f'Unexpected announce type: {type(announce).__name__}: {announce!r}')
                    announce_list.append(tier)
                else:
                    raise TypeError(
                        f'Unexpected announce type: {type(announce_or_tier).__name__}: '
                        f'{announce_or_tier!r}'
                    )

            if announce_list:
                self.metainfo['announce-list'] = announce_list
            else:
                # Remove empty "announce-list" if it exists.
                self.metainfo.pop('announce-list', None)
            # Remove "announce" if it exists.
            self.metainfo.pop('announce', None)

        else:
            raise TypeError(f'Unexpected announce type: {type(announce).__name__}: {announce!r}')

    @property
    def webseeds(self):
        """
        :class:`tuple` of WebSeed URLs

        http://bittorrent.org/beps/bep_0019.html
        """
        return self._get_metainfo('url-list', type=tuple, default=())

    def _handle_kwarg_webseeds(self, webseeds):
        if webseeds is None:
            self.metainfo.pop('url-list', None)

        elif isinstance(webseeds, str):
            if webseeds:
                self.metainfo['url-list'] = (webseeds,)
            else:
                raise ValueError('webseed is empty string')

        elif isinstance(webseeds, collections.abc.Iterable):
            url_list = []
            for url in webseeds:
                if isinstance(url, str):
                    url_list.append(url)
                else:
                    raise TypeError(f'Unexpected webseed type: {type(url).__name__}: {url!r}')
            if url_list:
                self.metainfo['url-list'] = url_list
            else:
                self.metainfo.pop('url-list', None)

        else:
            raise TypeError(f'Unexpected webseeds type: {type(webseeds).__name__}: {webseeds!r}')

    @property
    def httpseeds(self):
        """
        :class:`tuple` of HTTP Seeding URLs

        http://bittorrent.org/beps/bep_0017.html
        """
        return self._get_metainfo('httpseeds', type=tuple, default=())

    def _handle_kwarg_httpseeds(self, httpseeds):
        if isinstance(httpseeds, str):
            if httpseeds:
                self.metainfo['httpseeds'] = (httpseeds,)
            else:
                raise ValueError('httpseed is empty string')

        elif isinstance(httpseeds, collections.abc.Iterable):
            urls = []
            for url in httpseeds:
                if isinstance(url, str):
                    urls.append(url)
                else:
                    raise TypeError(f'Unexpected httpseed type: {type(url).__name__}: {url!r}')
            if urls:
                self.metainfo['httpseeds'] = urls
            else:
                self.metainfo.pop('httpseeds', None)

        else:
            raise TypeError(f'Unexpected httpseeds type: {type(httpseeds).__name__}: {httpseeds!r}')

    @property
    def comment(self):
        """
        :attr:`metainfo`\\ ``['comment']`` or ``None`` if not specified
        """
        return self._get_metainfo('comment', type=str, default=None)

    def _handle_kwarg_comment(self, comment):
        if comment is None:
            self._set_metainfo(('comment',), None)
        elif isinstance(comment, str):
            self._set_metainfo(('comment',), comment or None)
        else:
            raise TypeError(f'Unexpected comment type: {type(comment).__name__}: {comment!r}')

    @property
    def created_by(self):
        """
        :attr:`metainfo`\\ ``['created by']`` as :class:`str` or ``None`` if not specified
        """
        return self._get_metainfo('created by', type=str, default=None)

    def _handle_kwarg_created_by(self, created_by):
        if created_by is None:
            self._set_metainfo(('created by',), None)
        elif isinstance(created_by, str):
            self._set_metainfo(('created by',), created_by or None)
        else:
            raise TypeError(f'Unexpected created_by type: {type(created_by).__name__}: {created_by!r}')

    @property
    def creation_date(self):
        """
        :attr:`metainfo`\\ ``['creation date']`` as :class:`datetime.datetime` or ``None`` if
        not specified
        """
        return self._get_metainfo('creation date', type=datetime.datetime.fromtimestamp, default=None)

    def _handle_kwarg_creation_date(self, creation_date):
        if creation_date is None:
            self._set_metainfo(('creation date',), None)
        elif isinstance(creation_date, (int, float)):
            self._set_metainfo(('creation date',), int(creation_date))
        elif isinstance(creation_date, datetime.datetime):
            self._set_metainfo(('creation date',), int(creation_date.timestamp()))
        else:
            raise TypeError(f'Unexpected creation_date type: {type(creation_date).__name__}: {creation_date!r}')

    @property
    def filelist(self):
        """
        :class:`tuple` of relative :class:`~.File` paths in this torrent

        Every path starts with :attr:`name`.
        """
        if info := self._get_metainfo('info', type=dict, default=None):
            # Multi-file torrent
            name = info.get('name', '')
            files = info.get('files', ())
            if name and files:
                return tuple(
                    _utils.File(*(name, *path), size=length)
                    for file in files
                    if (
                            (path := file.get('path', ()))
                            and (length := file.get('length', 0))
                    )
                )

            # Single-file torrent
            length = info.get('length', 0)
            if name and length:
                return (_utils.File(name, size=length),)

        return ()

    def _handle_kwarg_files(self, files):
        if files is None:
            metainfo_files = None
        elif isinstance(files, collections.abc.Iterable):
            metainfo_files = []
            for file in files:
                if isinstance(file, collections.abc.Mapping):
                    metainfo_files.append(file)
                elif isinstance(file, _utils.File):
                    metainfo_files.append({'length': file.size, 'path': file.path})
                elif isinstance(file, collections.abc.Sequence):
                    if len(file) >= 2:
                        path = file[0]
                        if not _utils.is_sequence(path):
                            raise TypeError(f'Expected sequence for path, not {type(path).__name__}: {path!r}')
                        for part in path:
                            if not isinstance(part, str):
                                raise TypeError(f'Expected str in path, not {type(part).__name__}: {part!r}')
                        length = file[1]
                        if not isinstance(length, int):
                            raise TypeError(f'Expected int for size, not {type(length).__name__}: {length!r}')
                        metainfo_files.append({'length': length, 'path': path})
                    else:
                        raise ValueError(f'Expected (<path>, <size>): {file!r}')
                else:
                    raise TypeError(f'Unexpected file type: {type(file).__name__}: {file!r}')
        else:
            raise TypeError(f'Unexpected files type: {type(files).__name__}: {files!r}')
        self._set_metainfo(('info', 'files'), metainfo_files)

    @property
    def filetree(self):
        """
        Nested :class:`dict` :class:`~.File` instances as specified in :attr:`metainfo`

        Keys are :class:`~.File` instances and values are either :class:`dict` or :class:`~.File`
        instances.

        Every path starts with :attr:`name`.

        For example, here is an ``info`` section and the resulting ``filetree``:

        .. code:: python

            {
                'name': 'mytorrent',
                'files': [
                    {'length': 3, 'path': ['foo']},
                    {'length': 6, 'path': ['bar', 'baz']},
                ],
            }

        .. code:: python

            {
                _utils.File('mytorrent', size=9): {
                    _utils.File('mytorrent', 'foo', size=3): _utils.File('mytorrent', 'foo', size=3),
                    _utils.File('mytorrent', 'bar', size=6): {
                        _utils.File('mytorrent', 'bar', 'baz', size=6): _utils.File('mytorrent', 'bar', 'baz', size=6),
                    },
                },
            },
        """
        tree = {}
        for file in self.filelist:
            # Path without filename.
            dirpath = file.path[:-1]

            # Add any missing parent directories.
            subtree = tree
            for i in range(len(dirpath)):
                keypath = dirpath[:i + 1]
                key = _utils.File(*keypath, size=self.size_partial(keypath))
                if key not in subtree:
                    subtree[key] = {}
                # Set current directory to immediate parent directory.
                subtree = subtree[key]

            # Add file to current subtree.
            value = _utils.File(*file.path, size=self.size_partial(file.path))
            subtree[value] = value

        return tree

    @property
    def infohash(self):
        """
        SHA1 hash of the data in :attr:`metainfo`\\ ``['info']``

        :raises ValidationError: if :attr:`metainfo` contains invalid data
        """
        # The infohash is set explicitly when creating a Torrent from a Magnet URI.
        infohash = getattr(self, '_infohash', None)
        if infohash is not None:
            return infohash
        else:
            # If we don't have proper metainfo, the infohash will be useless.
            self.validate()
            return hashlib.sha1(_bencode.encode(self.metainfo_raw[b'info'])).hexdigest()

    @property
    def infohash_base32(self):
        """Base32 encoded :attr:`infohash`"""
        return base64.b32encode(base64.b16decode(self.infohash.upper()))

    @property
    def name(self):
        """
        :attr:`metainfo`\\ ``['info']``\\ ``['name']`` or ``None`` if not specified
        """
        return self._get_metainfo('info', 'name', type=str, default=None)

    def _handle_kwarg_name(self, name):
        if name is None:
            self._set_metainfo(('info', 'name'), None)
        elif isinstance(name, str):
            self._set_metainfo(('info', 'name'), name or None)
        else:
            raise TypeError(f'Unexpected name type: {type(name).__name__}: {name!r}')

    @property
    def pieces(self):
        """
        :class:`tuple` of SHA1 piece hashes as :class:`bytes` or empty :class:`tuple` (``()``)

        Pieces are stored in :attr:`metainfo`\\ ``['info']``\\ ``['pieces']``.
        """
        pieces = self._get_metainfo('info', 'pieces', type=bytes, default=None)
        if pieces:
            # Each piece is 20 bytes long.
            return tuple(
                bytes(pieces[pos : pos + 20])
                for pos in range(0, len(pieces), 20)
            )
        else:
            return ()

    def _handle_kwarg_pieces(self, pieces):
        if isinstance(pieces, (bytes, bytearray)):
            self._set_metainfo(('info', 'pieces'), pieces)
        elif _utils.is_sequence(pieces):
            for piece in pieces:
                if not isinstance(piece, (bytes, bytearray)):
                    raise TypeError(f'Unexpected piece type: {type(piece).__name__}: {piece!r}')
            self._set_metainfo(('info', 'pieces'), b''.join(pieces))
        else:
            raise TypeError(f'Unexpected pieces type: {type(pieces).__name__}: {pieces!r}')

    @property
    def piece_count(self):
        """
        Number of pieces the content is split into for hashing

        This means you can know the number of pieces before

        The number of pieces is calculated from :attr:`size` and :attr:`piece_length`.

        This property does not rely on :attr:`pieces`.
        """
        size, piece_length = self.size, self.piece_length
        if size > 0 and piece_length > 0:
            return math.ceil(size / piece_length)
        else:
            return 0

    @property
    def piece_length(self):
        """
        :attr:`metainfo`\\ ``['info']``\\ ``['piece length']`` or ``None`` if not specified
        """
        return self._get_metainfo('info', 'piece length', type=int, default=None)

    @property
    def private(self):
        """
        :attr:`metainfo`\\ ``['info']``\\ ``['private']`` as :class:`bool`

        ``True`` if the field exists and is truthy, ``False`` otherwise

        Private torrents must only use trackers and not DHT or PEX for finding peers.
        """
        return self._get_metainfo('info', 'private', type=bool, default=False)

    def _handle_kwarg_private(self, private):
        # Set private flag to 1 (True) or remove it (False).
        self._set_metainfo(('info', 'private'), 1 if private else None)

    @property
    def size(self):
        """Total size of content in bytes as :class:`int`"""
        # Single-file torrent.
        length = self._get_metainfo('info', 'length', type=int, default=None)
        if length is not None:
            return length

        # Multi-file torrent.
        files = self._get_metainfo('info', 'files', type=tuple, default=None)
        if files is not None:
            return sum(
                fileinfo.get('length', 0)
                for fileinfo in files
                if isinstance(fileinfo, collections.abc.Mapping)
            )

        # No size found.
        return 0

    def size_partial(self, path):
        """
        Return combined size of one or more files as specified in :attr:`metainfo`

        :param path: Relative path within torrent, starting with :attr:`name`
        :type path: str, path-like or iterable

        If `path` points to a directory (i.e. an incomplete file path), the sizes of all file that
        start with that path are combined.

        :raises PathError: if `path` is not known
        :raises ValueError: if `path` is of unexpected type
        """
        if isinstance(path, str):
            path = tuple(path.split(os.sep))
        elif isinstance(path, os.PathLike):
            path = tuple(os.fspath(path).split(os.sep))
        elif isinstance(path, collections.abc.Iterable):
            path = tuple(str(part) for part in path)
        else:
            raise ValueError(f'Must be str, PathLike or Iterable, not {type(path).__name__}: {path}')
        if not path:
            raise ValueError(f'path must be not be empty: {path}')

        if info := self._get_metainfo('info', type=dict, default=None):
            name = info.get('name', None)

            # If this is a single-file torrent, `path` can only have one value.
            if (length := info.get('length', None)) and path == (name,):
                return length

            elif fileinfos := info.get('files', ()):
                file_sizes = []
                for fileinfo in fileinfos:
                    this_path = (name, *(part for part in fileinfo['path'] if part))
                    if this_path == path:
                        # `path` points to file.
                        return fileinfo.get('length', 0)
                    elif _utils.iterable_startswith(this_path, path):
                        # path points to directory
                        file_sizes.append(fileinfo.get('length', 0))
                if file_sizes:
                    return sum(file_sizes)

        raise _errors.PathError('Unknown path', path=os.path.join(*path))

    @property
    def source(self):
        """
        :attr:`metainfo`\\ ``['info']``\\ ``['source']`` as :class:`str` or ``None`` if not
        specified
        """
        return self._get_metainfo('info', 'source', type=str, default=None)

    def _handle_kwarg_source(self, source):
        if isinstance(source, str):
            self._set_metainfo(('info', 'source'), source)
        else:
            raise TypeError(f'Unexpected source type: {type(source).__name__}: {source!r}')

    @classmethod
    def from_path(
            cls,
            path,
            *,
            exclude_globs=(),
            exclude_regexs=(),
            include_globs=(),
            include_regexs=(),
            validate=True,
    ):
        """
        Create instance from file or directory tree

        :param path: Path to file or directory that will be hashed to create a torrent

        :raises ReadError: if `path` or one of its subpaths is not readable

        :return: :class:`Torrent` instance
        """
        self = cls(**kwargs)
        self._path = path
        return self

    @classmethod
    def from_torrentfile(cls, torrentfile, **kwargs):
        """
        Create instance from ``.torrent`` file

        :param torrentfile: Path to ``.torrent`` file

        :raises ReadError: if reading `torrentfile` fails
        :raises BdecodeError: if `torrentfile` does not contain a valid bencoded byte sequence
        :raises MetainfoError: if `validate` is ``True`` and the metainfo is invalid

        :return: :class:`Torrent` instance
        """
        try:
            with open(torrentfile, 'rb') as f:
                return cls.from_stream(f, **kwargs)
        except (OSError, _errors.ReadError) as e:
            raise _errors.ReadError(e, path=torrentfile)
        except _errors.BencodeError:
            raise _errors.BencodeError(torrentfile)

    @classmethod
    def from_stream(cls, stream, **kwargs):
        """
        Create instance from file-like object

        :param stream: Instance of :class:`bytes` or :class:`bytearray` or readable file-like object
            (e.g. :class:`io.BytesIO`)
        :param bool validate: Whether to run :meth:`validate` the new instance

        :raises ReadStreamError: if reading from `stream` fails
        :raises BdecodeError: if `stream` does not produce a valid bencoded byte sequence
        :raises MetainfoError: if `validate` is ``True`` and the read metainfo is invalid

        :return: :class:`Torrent` instance
        """
        data = cls._read_stream(stream)
        metainfo = _bencode.decode(data)
        self = cls(**kwargs)
        self.metainfo_raw.clear()
        self.metainfo_raw.update(metainfo)
        return self

    @classmethod
    def _read_stream(cls, stream):
        if hasattr(stream, 'read'):
            # Read from file-like object. We try to read more than MAX_TORRENT_SIZE so ReadError is
            # raised below if we get too many bytes. (`read(n)` reads `n` bytes or less.)
            data = stream.read(cls.MAX_TORRENT_SIZE + 1)
        elif not isinstance(data, (bytes, bytearray)):
            raise TypeError(
                'Expected bytes, bytearray or a readable file-like object, '
                f'got {type(data).__name__}: {data!r}'
            )
        else:
            data = stream

        if len(data) > cls.MAX_TORRENT_SIZE:
            raise _errors.ReadError(
                f'Metainfo exceeds maximum size: {len(data)} > {Torrent.MAX_TORRENT_SIZE}'
            )
        else:
            return data

    def validate(self):
        # TODO: Check if '.' or '..' in any path.
        # TODO: Check if '/' or '\\' in any path.

        pass

        # # Only a dictionary can be valid torrent metainfo, not a list or anything else.
        # if not isinstance(metainfo, collections.abc.Mapping):
        #     raise _errors.BdecodeError()
        # else:
        #     # Convert all `bytes` in `metainfo` to `str`.
        #     ...



    @functools.cached_property
    def metainfo_raw(self):
        """
        Raw metainfo as :class:`dict`

        Keys must be :class:`bytes` and values must be :class:`bytes`, :class:`int`, :class:`dict`
        (or dict-like) or :class:`list` (any iterable is also supported).

        Consider using :attr:`metainfo` to prevent encoding/decoding issues.

        .. warning:: Keep in mind that manipulating this property can break things horribly,
            unexpectedly and non-obviously.
        """
        return {}

    @functools.cached_property
    def metainfo(self):
        """
        Decoded metainfo

        This is a wrapper around :attr:`metainfo_raw` that decodes/encodes strings on demand. This
        object always contains the same data as :attr:`metainfo_raw`, only decoded. Setting values
        on this object encodes them properly or raises :class:`~.CodecError`.

        Consider using :meth:`copy` instead if you want to modify the metainfo.

        .. warning:: Keep in mind that manipulating this property can break things horribly,
            unexpectedly and non-obviously.
        """
        return _metainfo.CodecMapping(
            self.metainfo_raw,
            # Not sure what the best encoding for keys is. Ideally it doesn't matter because every
            # key in every torrent ever created is pure ASCII, but who knows what's out there.
            keys_encoding='UTF-8',
            no_encoding_keypaths=(
                ('info', 'pieces'),
            ),
        )

    def as_magnet(self, name=True, size=True, trackers=True, webseeds=True):
        """
        :class:`Magnet` instance

        :param bool name: Whether to include the name
        :param bool size: Whether to include the size
        :param trackers: ``True`` to include all trackers, :class:`int` to include only that many
            trackers, ``False`` or ``None`` to not include any trackers
        :param webseeds: ``True`` to include all webseeds, :class:`int` to include only that many
            webseeds, ``False`` or ``None`` to not include any webseeds

        :raises MetainfoError: if :attr:`metainfo` is invalid
        """
        kwargs = {'xt': 'urn:btih:' + self.infohash}
        if name:
            kwargs['dn'] = self.name
        if size:
            kwargs['xl'] = self.size

        if trackers is True:
            kwargs['tr'] = _utils.flatten(self.announce)
        elif isinstance(trackers, int) and trackers >= 1:
            kwargs['tr'] = _utils.flatten(self.announce)[:trackers]

        if webseeds is True:
            kwargs['ws'] = self.webseeds
        elif isinstance(webseeds, int) and webseeds >= 1:
            kwargs['ws'] = self.webseeds[:webseeds]

        # Prevent circular import issues.
        from .._magnet import Magnet
        return Magnet(**kwargs)

    # @property
    # def path(self):
    #     """Local file system path of to the files in this torrent or ``None``"""
    #     return self._path
