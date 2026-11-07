"""Source-only Go import classification; no Go compiler or foreign execution."""
import pytest

from gateway.lbe_go_import_sources import (
    _direct_imports, _darwin_arm64_filename_selected, D4GoImportSourceDenied,
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



@pytest.mark.parametrize("name,active", [
    ("cmd/app/main.go", True),
    ("cmd/app/main_darwin.go", True),
    ("cmd/app/main_arm64.go", True),
    ("cmd/app/main_darwin_arm64.go", True),
    ("cmd/app/main_darwin_arm64_test.go", True),
    ("cmd/app/main_linux.go", False),
    ("cmd/app/main_windows_amd64.go", False),
    ("cmd/app/main_darwin_amd64.go", False),
    ("cmd/app/main_amd64.go", False),
    ("cmd/app/main_linux_test.go", False),
    ("cmd/app/main_windows_arm64_test.go", False),
    ("cmd/app/main_unknownfuture.go", True),
    ("cmd/app/main_unix.go", True),
    ("cmd/app/main_arm64_custom.go", True),
])
def test_d4_go_filename_implicit_constraints_are_darwin_arm64_only(
        name, active):
    assert _darwin_arm64_filename_selected(name) is active


@pytest.mark.parametrize("bad", ["main.py", "main", 0, None, True])
def test_d4_go_filename_policy_refuses_non_source_inputs(bad):
    with pytest.raises(D4GoImportSourceDenied):
        _darwin_arm64_filename_selected(bad)
