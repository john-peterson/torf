import os
import re

import pytest

from torf import _utils


@pytest.mark.parametrize(
    argnames='obj, exp_return_value',
    argvalues=(
        pytest.param('foo', False, id='str'),
        pytest.param('foo'.encode('ascii'), False, id='bytes'),
        pytest.param(bytearray('foo'.encode('ascii')), False, id='bytearray'),
        pytest.param(['foo'], True, id='list'),
        pytest.param(('foo',), True, id='tuple'),
        pytest.param(iter(('foo',)), False, id='iterator'),
    ),
)
def test_is_sequence(obj, exp_return_value):
    assert _utils.is_sequence(obj) is exp_return_value


@pytest.mark.parametrize(
    argnames='obj, exp_return_value',
    argvalues=(
        pytest.param([], (), id='Empty sequence'),
        pytest.param(['foo', 'bar', 'baz'], ('foo', 'bar', 'baz'), id='Flat sequence'),
        pytest.param(['foo', ('bar', 'baz')], ('foo', 'bar', 'baz'), id='Nesting level 1'),
        pytest.param(['foo', ('bar', ['baz'])], ('foo', 'bar', 'baz'), id='Nesting level 2'),
        pytest.param([('foo', ('bar', ['baz']),)], ('foo', 'bar', 'baz'), id='Nesting level 3'),
    ),
)
def test_flatten(obj, exp_return_value):
    assert _utils.flatten(obj) == exp_return_value


@pytest.mark.parametrize(
    argnames='lst, other, exp_return_value',
    argvalues=(
        pytest.param(('a', 'b', 'c'), ('a', 'b', 'c'), True, id='a and b are identical'),
        pytest.param(('a', 'b', 'c', 'd'), ('a', 'b', 'c'), True, id='a is longer than b'),
        pytest.param(('a', 'b', 'c'), ('a', 'b', 'c', 'd'), False, id='a is shorter than b'),
        pytest.param(('a', 'b', 'c'), ('A', 'b', 'c'), False, id='b differes from a at index 0'),
        pytest.param(('a', 'b', 'c'), ('a', 'B', 'c'), False, id='b differes from a at index 1'),
        pytest.param(('a', 'b', 'c'), ('a', 'b', 'C'), False, id='b differes from a at index 2'),
        pytest.param((), (), True, id='a and b are empty'),
    ),
)
def test_iterable_startswith(lst, other, exp_return_value):
    assert _utils.iterable_startswith(lst, other) is exp_return_value


class Test_File:

    @pytest.mark.parametrize(
        argnames='path, size, exp_result',
        argvalues=(
            pytest.param(
                ('a', 'b', 'c'),
                123,
                _utils.File('a', 'b', 'c', size=123),
                id='path and size are valid',
            ),
            pytest.param(
                ('a', (), 'c'),
                123,
                ValueError("Unexpected path: ('a', (), 'c')"),
                id='path contains has unexpected type',
            ),
            pytest.param(
                ('a', 'b', 'c'),
                'one million',
                ValueError("size must be int, not str: 'one million'"),
                id='size is unexpected type',
            ),
            pytest.param(
                ('a', f'b{os.sep}c', 'd'),
                123,
                _utils.File('a', 'b', 'c', 'd', size=123),
                id='path contains os.sep',
            ),
        ),
    )
    def test___init__(self, path, size, exp_result):
        if isinstance(exp_result, Exception):
            with pytest.raises(type(exp_result), match=rf'^{re.escape(str(exp_result))}$'):
                _utils.File(*path, size=size)
        else:
            f = _utils.File(*path, size=size)
            assert f == exp_result

    def test_path(self, mocker):
        f = _utils.File('a', 'b', 'c', size=123)
        mocker.patch.object(f, '_path', 'this is the path')
        assert f.path == 'this is the path'

    def test_size(self, mocker):
        f = _utils.File('a', 'b', 'c', size=123)
        mocker.patch.object(f, '_size', 'this is the size')
        assert f.size == 'this is the size'

    def test_name(self, mocker):
        f = _utils.File('a', 'b', 'c', size=123)
        assert f.name == 'c'

    @pytest.mark.parametrize(
        argnames='a, b, exp_return_value',
        argvalues=(
            pytest.param(
                _utils.File('a', 'b', 'c', size=123),
                _utils.File('a', 'b', 'c', size=123),
                True,
                id='path is equal and size is equal',
            ),
            pytest.param(
                _utils.File('a', 'b', 'c', size=123),
                _utils.File('a', 'b', 'c', size=999),
                False,
                id='path is equal and size is different',
            ),
            pytest.param(
                _utils.File('a', 'b', size=123),
                _utils.File('a', 'b', 'c', size=123),
                False,
                id='path is different and size is equal',
            ),
            pytest.param(
                _utils.File('a', 'b', 'c', size=123),
                'not a File object',
                NotImplemented,
                id='Unsupported type',
            ),
        ),
    )
    def test___eq__(self, a, b, exp_return_value):
        assert a.__eq__(b) is exp_return_value

    def test___hash__(self):
        f = _utils.File('a', 'b', size=123)
        assert hash(f) == hash((('a', 'b'), 123))

    def test___repr__(self):
        f = _utils.File('a', 'b', size=123)
        assert repr(f) == "File('a', 'b', size=123)"
