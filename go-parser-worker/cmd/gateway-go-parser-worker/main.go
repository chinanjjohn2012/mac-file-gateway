// gateway-go-parser-worker is a private fail-closed protocol worker.
// It is NOT a CLI parser or a Gateway-exposed execution profile. A trusted
// Supervisor, signed manifest and macOS native tests are required first.
package main

import (
    "encoding/hex"
    "encoding/json"
    "errors"
    "io"
    "os"
    "runtime"
    checked "github.com/chinanjjohn2012/mac-file-gateway/go-parser-worker/internal/parser"
)

const (
    profileID = "go_parse_file_v1"
    mechanismID = "darwin_named_pure_computation_v1"
    readyProtocolVersion = 1
    maxResultBytes = 8 << 10
    nonceBytes = 32
    startByte = 0xa5
)

type readyMessage struct {
    Protocol int `json:"protocol"`
    Kind string `json:"kind"`
    Nonce string `json:"nonce"`
    PID int `json:"pid"`
    Profile string `json:"profile"`
    Mechanism string `json:"mechanism"`
    GoVersion string `json:"go_version"`
}

func emitResult(out io.Writer, result checked.Result) error {
    data, err := json.Marshal(result)
    if err != nil || len(data)+1 > maxResultBytes {
        return errors.New("result_unavailable")
    }
    data = append(data, '\n')
    n, err := out.Write(data)
    if err != nil || n != len(data) {
        return errors.New("result_unavailable")
    }
    return nil
}

// FDs 3=read-only source, 4=READY pipe, 5=result pipe,
// 6=32-byte private challenge, 7=one-byte start permission.
// Project source is read only after sandbox init and start permission.
func run(args []string, source io.Reader, ready io.Writer, result io.Writer, challenge io.Reader, start io.Reader) error {
    if len(args) != 0 {
        return errors.New("invalid_invocation")
    }
    nonce := make([]byte, nonceBytes)
    if _, err := io.ReadFull(challenge, nonce); err != nil {
        return errors.New("invalid_challenge")
    }
    if err := initializeSandbox(); err != nil {
        return errors.New("sandbox_unavailable")
    }
    readyBytes, err := json.Marshal(readyMessage{
        Protocol: readyProtocolVersion, Kind: "worker_ready_untrusted",
        Nonce: hex.EncodeToString(nonce), PID: os.Getpid(),
        Profile: profileID, Mechanism: mechanismID, GoVersion: runtime.Version(),
    })
    if err != nil || len(readyBytes) > 1024 {
        return errors.New("ready_unavailable")
    }
    readyBytes = append(readyBytes, '\n')
    n, err := ready.Write(readyBytes)
    if err != nil || n != len(readyBytes) {
        return errors.New("ready_unavailable")
    }
    ack := []byte{0}
    if _, err := io.ReadFull(start, ack); err != nil || ack[0] != startByte {
        return errors.New("start_not_authorized")
    }
    bytes, err := io.ReadAll(io.LimitReader(source, checked.MaxSourceBytes+1))
    if err != nil {
        return errors.New("source_unavailable")
    }
    return emitResult(result, checked.ParseBytes(bytes))
}

func main() {
    input := os.NewFile(3, "source-fd")
    ready := os.NewFile(4, "ready-fd")
    result := os.NewFile(5, "result-fd")
    challenge := os.NewFile(6, "challenge-fd")
    start := os.NewFile(7, "start-fd")
    if err := run(os.Args[1:], input, ready, result, challenge, start); err != nil {
        _, _ = os.Stderr.WriteString("worker_unavailable\n")
        os.Exit(70)
    }
}
