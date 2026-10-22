package parser

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEOFPhysicalPositions(t *testing.T) {
	cases := []struct {
		name, source         string
		offset, line, column int
	}{
		{"empty", "", 0, 1, 1},
		{"lone_lf", "\n", 1, 1, 2},
		{"eof_lf", "package p\nfunc f() {\n", 21, 2, 12},
		{"eof_crlf", "package p\r\nfunc f() {\r\n", 23, 2, 13},
		{"no_trailing_lf", "package p\nfunc f() {", 20, 2, 11},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseBytes([]byte(tc.source))
			if result.Status != "parser_rejected" || len(result.Diagnostics) == 0 {
				t.Fatalf("expected parser_rejected and diagnostic, got %#v", result)
			}
			got := result.Diagnostics[len(result.Diagnostics)-1]
			if got.OffsetByte != tc.offset || got.Line != tc.line || got.ColumnByte != tc.column {
				t.Fatalf("last diagnostic = %#v; want offset/line/col %d/%d/%d", got, tc.offset, tc.line, tc.column)
			}
		})
	}
}

func TestParserAcceptedIsNotGoSpecValidity(t *testing.T) {
	cases := []string{
		"package p\nfunc f() {}\n",
		"package p\ntype T struct{}\nfunc (a T, b T) M() {}\n",
		"package p\nvar _ = notDeclared\n",
	}
	for _, source := range cases {
		result := ParseBytes([]byte(source))
		if result.Status != "parser_accepted" {
			t.Fatalf("unexpected parser status for %q: %#v", source, result)
		}
	}
}

func TestLineDirectiveDoesNotControlLocationOrOutput(t *testing.T) {
	for _, lineDirective := range []string{
		"//line /other/workspace/password=topsecret.go:900:77",
		"/*line /other/workspace/password=topsecret.go:900:77*/",
		"//line ../other/password=topsecret.go:900:77",
	} {
		source := "package p\n" + lineDirective + "\nfunc f() { x := }\n"
		result := ParseBytes([]byte(source))
		if result.Status != "parser_rejected" || len(result.Diagnostics) == 0 {
			t.Fatalf("expected parser error: %#v", result)
		}
		for _, diag := range result.Diagnostics {
			if diag.Line <= 0 || diag.Line > 3 || diag.OffsetByte > len(source) {
				t.Fatalf("forged position: %#v", diag)
			}
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("topsecret")) || bytes.Contains(encoded, []byte("other/workspace")) {
			t.Fatalf("untrusted paths/tokens leaked in result: %s", encoded)
		}
	}
}

func TestUTF8AndCRLFPhysicalByteColumns(t *testing.T) {
	source := "package p\r\n// 雪花\r\nfunc f() { _ = }\r\n"
	result := ParseBytes([]byte(source))
	if result.Status != "parser_rejected" || len(result.Diagnostics) == 0 {
		t.Fatalf("expected parser rejection: %#v", result)
	}
	for _, d := range result.Diagnostics {
		if d.OffsetByte < 0 || d.OffsetByte > len([]byte(source)) || d.Line < 1 || d.ColumnByte < 1 {
			t.Fatalf("invalid physical byte location: %#v", d)
		}
	}
}

func TestInvalidInputsAndNoRawErrorLeak(t *testing.T) {
	cases := []struct {
		source       []byte
		status, code string
	}{
		{[]byte{0xff}, "input_rejected", "invalid_utf8"},
		{bytes.Repeat([]byte("x"), MaxSourceBytes+1), "input_rejected", "input_too_large"},
	}
	for _, tc := range cases {
		result := ParseBytes(tc.source)
		if result.Status != tc.status || result.ErrorCode != tc.code {
			t.Fatalf("result: %#v", result)
		}
	}
	source := "package p\nvar _ = password=synthetic_secret_123\n"
	raw, err := json.Marshal(ParseBytes([]byte(source)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "synthetic_secret_123") || strings.Contains(string(raw), "password") {
		t.Fatalf("error result contains source text: %s", raw)
	}
}

func TestAllErrorsOutputIsBounded(t *testing.T) {
	var source strings.Builder
	source.WriteString("package p\n")
	for i := 0; i < 300; i++ {
		source.WriteString("var _ = )\n")
	}
	result := ParseBytes([]byte(source.String()))
	if result.Status != "parser_rejected" || !result.Truncated || len(result.Diagnostics) != MaxDiagnostics {
		t.Fatalf("expected bounded AllErrors result, got %#v", result)
	}
}
