"""Source-only Go import classification; no Go compiler or foreign execution."""
import pytest

from gateway.lbe_go_import_sources import (
    _direct_imports, _darwin_arm64_filename_selected,
    _darwin_arm64_explicit_selected, D4GoImportSourceDenied,
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



@pytest.mark.parametrize("content,included", [
    (b'package main\n', True),
    (b'//go:build darwin && arm64\n\npackage main\n', True),
    (b'//go:build darwin && !cgo\n\npackage main\n', True),
    (b'//go:build (darwin || linux) && arm64\n\npackage main\n', True),
    (b'//go:build unix && gc && go1.27\n\npackage main\n', True),
    (b'//go:build windows\n\npackage main\n', False),
    (b'//go:build linux || amd64\n\npackage main\n', False),
    (b'//go:build go1.28\n\npackage main\n', False),
    (b'// +build darwin,arm64\n\npackage main\n', True),
    (b'// +build linux darwin\n\npackage main\n', True),
    (b'// +build linux,arm64\n\npackage main\n', False),
    (b'//go:build darwin && arm64\n// +build darwin,arm64\n\npackage main\n',
     True),
    (b'//go:build windows\n// +build windows\n\npackage main\n', False),
])
def test_d4_go_explicit_build_tag_selection_for_fixed_darwin_arm64(
        content, included):
    assert _darwin_arm64_explicit_selected(content) is included


@pytest.mark.parametrize("content", [
    b'//go:build darwin || custom_hook\n\npackage main\n',
    b'//go:build arm64.v8\n\npackage main\n',
    b'//go:build race\n\npackage main\n',
    b'//go:build darwin &&\n\npackage main\n',
    b'//go:build (darwin\n\npackage main\n',
    b'//go:build darwin arm64\n\npackage main\n',
    b'//go:build darwin && arm64 && && gc\n\npackage main\n',
    b'//go:build darwin\n//go:build arm64\n\npackage main\n',
    b'//go:build darwin\n// +build linux\n\npackage main\n',
    b'// +build darwin,,arm64\n\npackage main\n',
    b'package main\n//go:build darwin\n',
    b'//go:build darwin\nfunc bad() {}\npackage main\n',
])
def test_d4_go_unknown_or_ambiguous_explicit_build_constraints_denied(content):
    with pytest.raises(D4GoImportSourceDenied):
        _darwin_arm64_explicit_selected(content)



@pytest.mark.parametrize("content,selected", [
    (b'/* Copyright\n * fixed source\n */\n'
     b'//go:build darwin && arm64\n\npackage main\n', True),
    (b'/* Copyright */\n//go:build linux\n\npackage main\n', False),
    (b'// Copyright\n\n// +build darwin,arm64\n\npackage main\n', True),
    (b'/* old copyright */\n//go:build darwin\n'
     b'// +build darwin\n\npackage main\n', True),
    # Modern Go build tags are recognized even without a blank line.
    (b'//go:build darwin\npackage main\n', True),
])
def test_d4_go_valid_license_header_preserves_explicit_selection(content, selected):
    assert _darwin_arm64_explicit_selected(content) is selected


@pytest.mark.parametrize("source", [
    b'// +build linux\npackage main\n',
    b'// +build windows\n// ordinary comment\npackage main\n',
    b'//go:build linux\n// +build linux\npackage main\n',
    b'/* Copyright\n//go:build linux\n*/\npackage main\n',
    b'/* Copyright\n// +build linux\n*/\npackage main\n',
    b'//go:build darwin\n/* unfinished\npackage main\n',
    b'//go:build linux\n\npackage main\n//go:build darwin\n',
])
def test_d4_go_unqualified_build_header_never_silently_omits_actual_source(source):
    with pytest.raises(D4GoImportSourceDenied):
        _darwin_arm64_explicit_selected(source)
