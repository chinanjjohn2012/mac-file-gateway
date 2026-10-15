// Package parser implements the deliberately narrow go_parse_file_v1 contract.
// It never opens files, resolves imports, compiles code, or runs user input.
package parser

import (
	"go/parser"
	"go/scanner"
	"go/token"
	"sort"
	"unicode/utf8"
)

const (
	MaxSourceBytes = 1 << 20
	MaxDiagnostics = 20
	Mode           = parser.SkipObjectResolution | parser.AllErrors
)

type Diagnostic struct {
	Code       string `json:"code"`
	OffsetByte int    `json:"offset_byte"`
	Line       int    `json:"line"`
	ColumnByte int    `json:"column_byte"`
}

type Result struct {
	Status      string       `json:"status"`
	ErrorCode   string       `json:"error_code,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
	Truncated   bool         `json:"truncated,omitempty"`
}

// ParseBytes reports acceptance by exactly go/parser with Mode, NOT Go spec
// validity, successful compilation, type correctness, or build success.
// Diagnostics never include source text, parser messages, or source paths.
func ParseBytes(source []byte) Result {
	if len(source) > MaxSourceBytes {
		return Result{Status: "input_rejected", ErrorCode: "input_too_large"}
	}
	if !utf8.Valid(source) {
		return Result{Status: "input_rejected", ErrorCode: "invalid_utf8"}
	}

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "gateway-input.go", source, Mode)
	if err == nil {
		return Result{Status: "parser_accepted"}
	}

	errors, ok := err.(scanner.ErrorList)
	if !ok || len(errors) == 0 {
		return Result{Status: "diagnostic_unavailable"}
	}
	var file *token.File
	fileCount := 0
	fset.Iterate(func(candidate *token.File) bool {
		fileCount++
		file = candidate
		return true
	})
	if fileCount != 1 || file == nil || file.Size() != len(source) {
		return Result{Status: "diagnostic_unavailable"}
	}

	// Match go/token.File.AddLine: a new line start must be strictly below
	// the source size. In particular, trailing LF/CRLF does NOT open a new
	// line at EOF; the empty file uses 1:1.
	lineStarts := []int{0}
	for i, b := range source {
		if b == '\n' && i+1 < len(source) {
			lineStarts = append(lineStarts, i+1)
		}
	}
	output := make([]Diagnostic, 0, min(len(errors), MaxDiagnostics))
	for _, item := range errors {
		offset := item.Pos.Offset // Never trust adjusted filename/line/column.
		if offset < 0 || offset > len(source) {
			return Result{Status: "diagnostic_unavailable"}
		}
		physical := file.PositionFor(file.Pos(offset), false)
		startIndex := sort.Search(len(lineStarts), func(i int) bool { return lineStarts[i] > offset }) - 1
		if startIndex < 0 || physical.Offset != offset || physical.Line != startIndex+1 ||
			physical.Column != offset-lineStarts[startIndex]+1 {
			return Result{Status: "diagnostic_unavailable"}
		}
		if len(output) < MaxDiagnostics {
			output = append(output, Diagnostic{
				Code: "parser_rejected", OffsetByte: offset,
				Line: physical.Line, ColumnByte: physical.Column,
			})
		}
	}
	return Result{Status: "parser_rejected", Diagnostics: output, Truncated: len(errors) > MaxDiagnostics}
}
