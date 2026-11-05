# LBE five-day D2: Go/Pipenv closed environment candidate (T0)

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
REVIEW_STAGE: D2_DEVELOPMENT_CONTINUATION
STATUS: NONOPERATIVE_SOURCE_AND_T0 / NATIVE_NOT_RUN
PARENT: PR113 r001 same-Base/Head/Tree dual B/C TARGETED_REVIEW_PASS for D1 only.
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

## Intent

D2 builds real first-party *proposed* closed environment checks for a future
trusted product Go/Pipenv launcher. This is one component of the prelaunch
contract; it does NOT create an execution capability. It is deliberately NOT
wired into existing WorkspaceService positive apply, which stays F1 denied,
or the old Python-only internal trusted native launcher, which continues to
reject Go/Pipenv before any Popen.

Design inputs: PR98 r002 local_best_effort
GitBlob 9e6622401b198138039c692efe91fba1a8d06891;
PR102 r002 Gate B precise Go GOFLAGS/toolhooks and Pipenv redirects
GitBlob 7db3b77aadca8b0c284e28fa5ee64e315e9275d2 section 5.1/5.2;
PR113 r001 proposed separate trusted-code PRODUCT_T1
GitBlob 3b9aa056f67008aa825da5c95b6ca71b0b25a84d.
Current user authorized five-day development direction and safe T0, NOT
the alternative native Go/Pipenv test profile or Gate B waiver.

## Closed Go proposed child input

Fix proposed staged Go entry at GOROOT/bin/go and distinct lowercase SHA256
source/tool digests. Require exact primitive strings, canonical absolute
paths and private HOME/TMPDIR/GOPATH/GOMODCACHE/GOCACHE/GOTMPDIR. The entire
effective proposed mapping is exactly HOME, TMPDIR, LANG=C, LC_ALL=C,
GOROOT, PATH, GOTOOLCHAIN=local, GOENV=off, GOFLAGS empty, GOPROXY=off,
GOSUMDB=off, GOWORK=off, GO111MODULE=on, CGO_ENABLED=0, GOPATH,
GOMODCACHE, GOCACHE, GOTMPDIR. Reject any extra key or mutated value.

The input model also rejects inherited nonempty GO*/CGO/toolchain, CC/CXX,
PKG_CONFIG, Python, Pipenv, dynamic linker and shell selectors and changed
PATH. It never copies os.environ or reads actual environment and therefore
cannot attest any real staged compiler, module cache or loaded executable.

## Closed Pipenv proposed child input

Fix exact project/Pipfile and PROJECT/.venv/bin/python under the proposed
private root, exact Pipenv entrypoint, three distinct digest-shaped inputs,
HOME/TMPDIR and fixed PATH. Effective proposed child mapping has exact
PIPENV_PIPFILE, PIPENV_VENV_IN_PROJECT=1, DONT_LOAD_ENV=1,
IGNORE_VIRTUALENVS=1, PIP_NO_INDEX=1, PIPENV_SKIP_LOCK=1 and Python
user-site / bytecode disables. Inherited WORKON_HOME, VIRTUAL_ENV,
PIPENV_PYTHON, PYTHONPATH and arbitrary selecting variables deny.

This checks only spelled paths and declared digests. It does NOT stat
or certify the .venv inode (regular-file pointer redirect, symlink, owner),
actual Python interpreter, pyvenv.cfg, Pipfile.lock bytes, seed/RECORD,
site startup, importable shadow paths or source publisher. Those checks
must be independently observed and fail closed BEFORE any future approved
native Pipenv entrypoint. A forged string or altered frozen record never
grants launch; the execution stub unconditionally denies.

## Coverage and release boundary

Pure T0 tests cover good profile structure, inherited GOFLAGS/toolexec and
Go selector injections, changed effective PATH/source/cache keys, Pipenv
redirect/pointer-path and virtualenv selector overrides, malformed SHA,
unsafe path, extra/missing variables, exact built-in types and fake receipt
mutation. No OS process, socket, network, filesystem mutation, sandbox,
macOS native Canary, Go/Pipenv or product positive apply is executed.

A continues concentrated development and may add safe D2/D3 commits on
a NEW branch, keeping PR113 frozen and keeping each interim candidate
unreviewed. New B/C FULL milestone signoff will require current Base/Head,
real original CI and applicable native/integration evidence. Earlier D1
targeted PASS is not a PASS for this new commit.

INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
GO_PIPENV_NATIVE: NOT_RUN
PENDING_CONTRACT: NEW B/C + owner review of the precise trusted-network-risk
and test envelope; existing Gate B OFFLINE_ONLY is not replaced.


## D3 safe file-selection adjunct (in same concentrated development PR)

New gateway/lbe_pipenv_fixture_t0.py provides actual READ-ONLY FILE
observation from an independently supplied absolute fixture directory.
It walks each ancestor using O_DIRECTORY/O_NOFOLLOW file descriptors;
opens each required file with O_NOFOLLOW|O_NONBLOCK, checks regular file,
one link, same UID, non-group/world-writable mode, bounded byte size,
no changed inode metadata during read and pinned SHA256 for Pipfile,
Pipfile.lock, .venv/pyvenv.cfg and .venv/bin/python; the latter must be
owner-executable. It requires a real .venv DIRECTORY and a minimally
well-formed Pipfile.lock hash metadata entry.

This is not physical selected-Python execution or installed site-source
qualification. It does NOT check all site, wheel/seed/record members,
network, loader, process resources, publisher or OS-domain confinement.
An external owner may still race trusted-path changes after descriptors
close. Any future real native Pipenv launch still needs new profile
authorization, actual loaded source verification, reviewed Head and
fresh pre-Popen safety checks; even a forged snapshot cannot permit launch.

New tests/test_lbe_pipenv_fixture_t0.py uses disposable fake bytes,
NOT an actual Python binary. It checks harmless valid read-only snapshot
and rejection of .venv pointer-file, symlink, symlinked ancestor,
hardlinked leaf, mutated content, insufficient mode, malformed lock and
invalid fixed digests. No Go/Pipenv/Python interpreter/OS processes run,
no signals/kill, no native Canary, and no product positive apply.
