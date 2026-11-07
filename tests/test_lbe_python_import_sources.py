"""Nonexecuting Python source import selection and mapping T0 tests."""
import pytest

from gateway.lbe_python_import_sources import (
    D4PythonImportDenied, _classify_source, _resolve_first_party,
)


_SELECTED = {
    "src/__init__.py",
    "src/pkg/__init__.py",
    "src/pkg/entry.py",
    "src/pkg/util.py",
    "tests/__init__.py",
    "tests/test_main.py",
}


@pytest.mark.parametrize("source,edge", [
    (b"from .util import x\n", ("src/pkg/entry.py", "src/pkg/util.py")),
    (b"import src.pkg.util\n", ("src/pkg/entry.py", "src/pkg/util.py")),
    (b"from src.pkg import value\n",
     ("src/pkg/entry.py", "src/pkg/__init__.py")),
    (b"from . import util\n", ("src/pkg/entry.py", "src/pkg/__init__.py")),
    (b"from ..pkg import util\n",
     ("src/pkg/entry.py", "src/pkg/__init__.py")),
])
def test_python_selected_relative_and_absolute_import_edges(source, edge):
    edges, unknown, dynamic = _classify_source(
        "src/pkg/entry.py", source, _SELECTED)
    assert edge in edges
    assert not unknown
    assert not dynamic


@pytest.mark.parametrize("source", [
    b"from ...escaped import secret\n",
    b"from .missing import secret\n",
    b"import src.pkg.missing\n",
    b"from src.nope import secret\n",
    b"from . import bad\n def nonsense(:\n",
    b"from .bad import (\n",
])
def test_python_unqualified_local_import_or_bad_ast_denied(source):
    with pytest.raises(D4PythonImportDenied):
        _classify_source("src/pkg/entry.py", source, _SELECTED)


def test_python_external_and_dynamic_sources_not_silently_attested():
    source = (
        b"import os\nimport importlib\n"
        b"from pytest import fixture\n"
        b"importlib.import_module('unknown')\n"
        b"__import__('foreign')\n")
    edges, unknown, dynamic = _classify_source(
        "tests/test_main.py", source, _SELECTED)
    assert edges == set()
    assert unknown == {"os", "importlib", "pytest"}
    assert dynamic == {"tests/test_main.py"}


def test_python_module_path_lookup_only_from_selected_files():
    assert _resolve_first_party("src.pkg", _SELECTED) == "src/pkg/__init__.py"
    assert _resolve_first_party("src.pkg.util", _SELECTED) == "src/pkg/util.py"
    assert _resolve_first_party("src.pkg.missing", _SELECTED) is None
    assert _resolve_first_party("../outside", _SELECTED) is None


def test_python_from_package_import_submodule_includes_parent_initializer():
    source = b'from src.pkg import util\n'
    edges, unknown, dynamic = _classify_source(
        "src/pkg/entry.py", source, _SELECTED)
    assert edges == {
        ("src/pkg/entry.py", "src/__init__.py"),
        ("src/pkg/entry.py", "src/pkg/__init__.py"),
        ("src/pkg/entry.py", "src/pkg/util.py"),
    }
    assert not unknown and not dynamic


def test_python_relative_from_import_submodule_includes_parent_initializer():
    edges, unknown, dynamic = _classify_source(
        "src/pkg/entry.py", b'from . import util\n', _SELECTED)
    assert edges == {
        ("src/pkg/entry.py", "src/__init__.py"),
        ("src/pkg/entry.py", "src/pkg/__init__.py"),
        ("src/pkg/entry.py", "src/pkg/util.py"),
    }
    assert not unknown and not dynamic


def test_python_namespace_package_import_resolves_available_child():
    source = {"src/pkg/entry.py", "src/pkg/util.py"}
    edges, unknown, dynamic = _classify_source(
        "src/pkg/entry.py", b'import src.pkg.util\n', source)
    assert edges == {("src/pkg/entry.py", "src/pkg/util.py")}
    assert not unknown and not dynamic


def test_python_attribute_or_star_import_never_claims_full_closure():
    attribute, unknown, dynamic = _classify_source(
        "src/pkg/entry.py", b'from . import provided_by_initializer\n', _SELECTED)
    assert attribute == {
        ("src/pkg/entry.py", "src/__init__.py"),
        ("src/pkg/entry.py", "src/pkg/__init__.py"),
    }
    assert not unknown and not dynamic
    starred, unknown, dynamic = _classify_source(
        "src/pkg/entry.py", b'from . import *\n', _SELECTED)
    assert starred == attribute
    assert not unknown
    assert dynamic == {"src/pkg/entry.py"}
