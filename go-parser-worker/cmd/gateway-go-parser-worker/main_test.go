package main

import (
    "bytes"
    "encoding/json"
    "strings"
    "testing"

    checked "github.com/chinanjjohn2012/mac-file-gateway/go-parser-worker/internal/parser"
)

func TestWorkerRejectsArguments(t *testing.T) {
    source := strings.NewReader("source-must-remain-unread")
    err := run([]string{"extra"}, source, &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil), bytes.NewReader(nil))
    if err == nil || source.Len() != len("source-must-remain-unread") {
        t.Fatalf("expected fail closed")
    }
}

func TestWorkerRejectsMissingChallenge(t *testing.T) {
    source := strings.NewReader("source-must-remain-unread")
    err := run(nil, source, &bytes.Buffer{}, &bytes.Buffer{}, bytes.NewReader(nil), bytes.NewReader(nil))
    if err == nil || source.Len() != len("source-must-remain-unread") {
        t.Fatalf("expected fail closed")
    }
}

func TestBoundedResult(t *testing.T) {
    var buffer bytes.Buffer
    err := emitResult(&buffer, checked.ParseBytes([]byte("package p\nfunc f() {\n")))
    if err != nil || buffer.Len() > maxResultBytes {
        t.Fatalf("result unavailable")
    }
    var parsed checked.Result
    if json.Unmarshal(buffer.Bytes(), &parsed) != nil || parsed.Status != "parser_rejected" {
        t.Fatalf("unexpected result")
    }
}
