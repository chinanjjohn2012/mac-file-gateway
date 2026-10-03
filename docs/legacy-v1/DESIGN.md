# Mac File Gateway design

Goal: let an authorized ChatGPT web MCP connection list, read, and search a
user-selected macOS project without a desktop Work/Codex application or cloud
drive synchronization. This is a read-only text/code gateway, not a local LLM.

Use the official Python MCP SDK with stateless Streamable HTTP at /mcp.
Provide GET /health, /list, /read, and /search for local inspection. Bind only
to 127.0.0.1. Use OpenAI Secure MCP Tunnel for authenticated external access;
never recommend publishing this loopback-only service without authentication.

One explicit existing root is selected at process start. Refuse / and the
current home directory. All tool paths are relative to the root. Use POSIX
openat-style directory file descriptors with O_NOFOLLOW at every component;
reject symbolic links, multiply-linked files, non-regular files, hidden path
components, known secret filenames, and dependency/build directories. Do not
execute subprocesses or import code from the selected project. Restrict content
to allowlisted text extensions and UTF-8. Add bounded file sizes, response
sizes, directory walks, and literal (not regex) search. Best-effort content
redaction is a secondary precaution, not a secret-scanning guarantee.

Local HTTP validates Host, Origin and Fetch Metadata; does not enable CORS;
rejects oversized request bodies; sets no-store and nosniff response headers.
The base trust model is a trusted single-user Mac and an authorized private
tunnel. Other local programs already have the same user's filesystem access.
Root access is pinned at startup, but this is not a full OS sandbox against a
malicious local process renaming directories or altering mount points.

Validation: real temporary filesystem tests, REST integration tests, and real
SDK transport tests when MCP is available. The build container is Linux and
has no MCP package or working package-index network. Do not claim native macOS
or actual ChatGPT/tunnel end-to-end validation. Ship integration tests so they
can run after dependency installation on the user's Mac.
