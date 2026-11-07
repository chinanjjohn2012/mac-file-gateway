"""Source-only Go import classification; no Go compiler or foreign execution."""
import pytest

from gateway.lbe_go_import_sources import (
    _direct_imports, D4GoImportSourceDenied,
)


@pytest.mark.parametrize("source,expected", [
    (b"package main\nfunc main() {}\n", ()),
    (b'package main\nimport "fmt"\n', ("fmt",)),
    (b'package main\nimport (\n "fmt"\n alias "os/exec"\n)\n',
     ("fmt", "os/exec")),
    (b'package main\n// import "C"\nvar s = "import \\"C\\""\n'
     b'import /* harmless */ "fmt"\n', ("fmt",)),
    (b'package main\nimport /* allowed comment */ . "fmt"\n', ("fmt",)),
])
def test_import_lexes_direct_source_without_running_go(source, expected):
    assert _direct_imports(source) == expected


@pytest.mark.parametrize("source", [
    b'package main\nimport "C"\n',
    b'package main\nimport (\n alias "C"\n)\n',
    b'package main\nimport "../escape"\n',
    b'package main\nimport "fmt"\n/* never closed',
    b'package main\nimport "fmt/../../escaped"\n',
])
def test_import_syntax_and_cgo_source_fails_closed(source):
    with pytest.raises(D4GoImportSourceDenied):
        _direct_imports(source)
