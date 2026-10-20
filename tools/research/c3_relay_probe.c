/* C3 research-only synthetic Owner + Relay + Worker on Darwin ARM64.
 * No PID/PGID or executable is accepted from callers; all children are ours.
 * Not a production supervisor, sandbox, or G2 qualification.
 */
#if !defined(__APPLE__)
#include <stdio.h>
int main(void) { fputs("C3_NOT_RUN_NON_DARWIN\n", stderr); return 77; }
#else
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
#define CONTROL_FD 20
#define WORKER_READY_FD 21
#define LINE_MAXIMUM 160
typedef struct {
    pid_t pid;
    int reaped;
    int status;
    int lost;
    int group_signals;
    int after_loss_signals;
    int signals_closed;
} NativeOwner;
typedef struct {
    pid_t pid;
    pid_t result;
    int status;
} RogueWaiter;

static long long millis_now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) < 0) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static long remaining(long long deadline) {
    long long rem = deadline - millis_now();
    return rem > 0 ? (rem > LONG_MAX ? LONG_MAX : (long)rem) : 0;
}
static void pause_ms(long ms) {
    struct timespec t = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) < 0 && errno == EINTR) {}
}
static int blocked(const char *phase) {
    fprintf(stderr, "C3_BLOCK phase=%s\n", phase);
    return 70;
}
static int close_fd(int *fd) {
    if (*fd < 0) return 1;
    int owned = *fd;
    *fd = -1;
    return close(owned) == 0;
}
static int close_on_exec(int fd) {
    return fcntl(fd, F_SETFD, FD_CLOEXEC) == 0;
}
static int owned_pipe(int p[2]) {
    if (pipe(p) != 0) return 0;
    if (!close_on_exec(p[0]) || !close_on_exec(p[1])) {
        close(p[0]); close(p[1]); p[0] = p[1] = -1; return 0;
    }
    return 1;
}
static int waitable_sigchld(void) {
    struct sigaction wanted, got;
    memset(&wanted, 0, sizeof wanted);
    wanted.sa_handler = SIG_DFL;
    if (sigemptyset(&wanted.sa_mask) != 0 ||
        sigaction(SIGCHLD, &wanted, NULL) != 0 ||
        sigaction(SIGCHLD, NULL, &got) != 0) return 0;
    return got.sa_handler == SIG_DFL && !(got.sa_flags & SA_NOCLDWAIT);
}
static int write_one(int fd, char byte) {
    for (;;) {
        ssize_t n = write(fd, &byte, 1);
        if (n == 1) return 1;
        if (n < 0 && errno == EINTR) continue;
        return 0;
    }
}
static int write_message(int fd, const char *message) {
    size_t left = strlen(message);
    while (left) {
        ssize_t n = write(fd, message, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        message += n;
        left -= (size_t)n;
    }
    return 1;
}
static int read_line(int fd, char *line, size_t cap, long long deadline) {
    size_t len = 0;
    if (cap < 2) return 0;
    while (remaining(deadline) > 0 && len < cap - 1) {
        struct pollfd p = {.fd = fd, .events = POLLIN | POLLHUP};
        long wait_ms = remaining(deadline);
        int r = poll(&p, 1, wait_ms < 100 ? (int)wait_ms : 100);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return 0;
        if (!r) continue;
        char ch;
        ssize_t n = read(fd, &ch, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n != 1) return 0;
        if (ch == '\n') { line[len] = '\0'; return len > 0; }
        if ((unsigned char)ch < 0x20 || (unsigned char)ch > 0x7e) return 0;
        line[len++] = ch;
    }
    return 0;
}
static int parse_ready(const char *line, pid_t *worker) {
    long pid = 0;
    char trailing;
    if (sscanf(line, "C3_READY worker=%ld%c", &pid, &trailing) != 1 ||
        pid <= 0 || pid > INT_MAX) return 0;
    *worker = (pid_t)pid;
    return 1;
}
static int parse_reaped(const char *line, pid_t expected, const char *kind, int code) {
    long pid = 0;
    char observed_kind[16], trailing;
    int observed_code = -1;
    int n = sscanf(line, "C3_REAPED worker=%ld kind=%15s code=%d%c",
                   &pid, observed_kind, &observed_code, &trailing);
    return n == 3 && pid == (long)expected &&
           strcmp(observed_kind, kind) == 0 && observed_code == code;
}
static int valid_root(const char *root, int *dirfd, const char *binary) {
    if (!root || root[0] != '/') return 0;
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077)) goto invalid;
    int marker = openat(fd, "C3_TEST_MARKER", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (marker < 0) goto invalid;
    char bytes[16];
    ssize_t length = read(marker, bytes, sizeof bytes);
    int good = fstat(marker, &st) == 0 && S_ISREG(st.st_mode) &&
               st.st_uid == geteuid() && st.st_nlink == 1 &&
               length == 9 && memcmp(bytes, "synthetic", 9) == 0;
    close(marker);
    if (!good) goto invalid;
    if (binary) {
        size_t root_length = strlen(root);
        if (strncmp(binary, root, root_length) != 0 ||
            strcmp(binary + root_length, "/c3_native") != 0) goto invalid;
        int child = openat(fd, "c3_native", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0) goto invalid;
        good = fstat(child, &st) == 0 && S_ISREG(st.st_mode) &&
               st.st_uid == geteuid() && st.st_nlink == 1 &&
               (st.st_mode & 0111) != 0;
        close(child);
        if (!good) goto invalid;
    }
    *dirfd = fd;
    return 1;
invalid:
    close(fd);
    return 0;
}
static int worker_role(const char *mode) {
    /* Explicit worker readiness must precede Owner eligibility and every
       test signal. This is a synthetic readiness protocol, not generic IPC auth. */
    if (strcmp(mode, "term-default") == 0) {
        struct sigaction installed;
        sigset_t mask;
        if (sigaction(SIGTERM, NULL, &installed) != 0 ||
            sigprocmask(SIG_SETMASK, NULL, &mask) != 0 ||
            installed.sa_handler != SIG_DFL || sigismember(&mask, SIGTERM) != 0) return 14;
    } else if (strcmp(mode, "kill-unknown") == 0) {
        if (signal(SIGTERM, SIG_IGN) == SIG_ERR) return 15;
    }
    if (!write_one(WORKER_READY_FD, 'R')) return 18;
    close(WORKER_READY_FD);
    char byte;
    if (read(STDIN_FILENO, &byte, 1) != 1 || byte != 'A') return 13;
    if (strcmp(mode, "term-default") == 0) {
        pause_ms(4000);
    } else if (strcmp(mode, "kill-unknown") == 0) {
        pause_ms(4000);
    } else if (strcmp(mode, "ipc-forgery") == 0) {
        if (!write_message(STDOUT_FILENO, "FINAL ticket=forged worker=OBSERVED_EXIT\n")) return 16;
    } else if (strcmp(mode, "leader-exit") == 0 ||
               strcmp(mode, "competing-reap") == 0) {
        pause_ms(1200);
    } else if (strcmp(mode, "identity-loss") == 0) {
        pause_ms(300);
    } else {
        return 17;
    }
    return 0;
}
static int relay_role(const char *mode, const char *binary, const char *root) {
    if (!waitable_sigchld() || signal(SIGTERM, SIG_IGN) == SIG_ERR ||
        !close_on_exec(CONTROL_FD)) return 20;
    int gate[2] = {-1, -1}, ready_pipe[2] = {-1, -1};
    if (!owned_pipe(gate) || !owned_pipe(ready_pipe)) return 21;
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    int made_fa = 0, made_attr = 0, failure = 22;
    if (posix_spawn_file_actions_init(&fa) != 0) goto finish;
    made_fa = 1;
    if (posix_spawn_file_actions_adddup2(&fa, gate[0], STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, ready_pipe[1], WORKER_READY_FD) != 0 ||
        posix_spawn_file_actions_addclose(&fa, gate[1]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, gate[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, ready_pipe[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, ready_pipe[1]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, CONTROL_FD) != 0) goto finish;
    if (posix_spawnattr_init(&attr) != 0) goto finish;
    made_attr = 1;
    sigset_t defaults, mask;
    if (sigemptyset(&defaults) != 0 || sigaddset(&defaults, SIGTERM) != 0 ||
        sigemptyset(&mask) != 0 ||
        posix_spawnattr_setsigdefault(&attr, &defaults) != 0 ||
        posix_spawnattr_setsigmask(&attr, &mask) != 0 ||
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF |
                                          POSIX_SPAWN_SETSIGMASK) != 0) goto finish;
    pid_t worker = -1;
    char *const argv[] = {(char *)binary, "__worker", (char *)mode,
                          (char *)root, NULL};
    if (posix_spawn(&worker, binary, &fa, &attr, argv, environ) != 0) goto finish;
    close_fd(&gate[0]); close_fd(&ready_pipe[1]);
    struct pollfd readiness = {.fd = ready_pipe[0], .events = POLLIN | POLLHUP};
    if (poll(&readiness, 1, 1500) <= 0) goto finish;
    char worker_ready = '\0';
    if (read(ready_pipe[0], &worker_ready, 1) != 1 || worker_ready != 'R')
        goto finish;
    close_fd(&ready_pipe[0]);
    char ready[LINE_MAXIMUM];
    int n = snprintf(ready, sizeof ready, "C3_READY worker=%ld\n", (long)worker);
    if (n <= 0 || (size_t)n >= sizeof ready ||
        !write_message(CONTROL_FD, ready)) goto finish;
    char arm;
    if (read(STDIN_FILENO, &arm, 1) != 1 || arm != 'A' ||
        !write_one(gate[1], 'A')) goto finish;
    close_fd(&gate[1]);
    if (!write_message(CONTROL_FD, "C3_ARMED\n")) goto finish;

    /* The deliberately exiting leader leaves a bounded, cooperative worker
       for NOTE_EXIT observation. This intentionally does not clean its group. */
    if (strcmp(mode, "leader-exit") == 0 ||
        strcmp(mode, "competing-reap") == 0) _exit(0);

    int status = 0;
    pid_t reaped;
    do { reaped = waitpid(worker, &status, 0); }
    while (reaped < 0 && errno == EINTR);
    if (reaped != worker) goto finish;
    const char *kind = WIFSIGNALED(status) ? "SIGNAL" : "EXIT";
    int code = WIFSIGNALED(status) ? WTERMSIG(status) :
               WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    n = snprintf(ready, sizeof ready, "C3_REAPED worker=%ld kind=%s code=%d\n",
                 (long)worker, kind, code);
    if (code < 0 || n <= 0 || (size_t)n >= sizeof ready ||
        !write_message(CONTROL_FD, ready)) goto finish;
    char done;
    if (read(STDIN_FILENO, &done, 1) != 1 || done != 'Q') goto finish;
    failure = 0;
finish:
    if (made_attr) posix_spawnattr_destroy(&attr);
    if (made_fa) posix_spawn_file_actions_destroy(&fa);
    close_fd(&gate[0]); close_fd(&gate[1]);
    close_fd(&ready_pipe[0]); close_fd(&ready_pipe[1]);
    return failure;
}
static int owner_is_live(NativeOwner *owner) {
    if (owner->pid <= 0 || owner->reaped || owner->lost || owner->signals_closed)
        return 0;
    pid_t p = waitpid(owner->pid, &owner->status, WNOHANG);
    if (p == owner->pid) { owner->reaped = 1; owner->lost = 1; return 0; }
    if (p < 0) { owner->lost = 1; return 0; }
    if (getpgid(owner->pid) != owner->pid) { owner->lost = 1; return 0; }
    return 1;
}
static int signal_owned_group(NativeOwner *owner, int signal_number, long long deadline) {
    if (!owner_is_live(owner) || remaining(deadline) <= 0) return 0;
    /* A user-space check is not an atomic kernel PGID capability. G2 BLOCK. */
    if (kill(-owner->pid, signal_number) != 0) return 0;
    owner->group_signals++;
    if (signal_number == SIGKILL) owner->signals_closed = 1;
    return 1;
}
static int watch_worker(int *watcher, pid_t worker) {
    int fd = kqueue();
    if (fd < 0 || !close_on_exec(fd)) { if (fd >= 0) close(fd); return 0; }
    struct kevent change;
    EV_SET(&change, (uintptr_t)worker, EVFILT_PROC, EV_ADD | EV_ONESHOT,
           NOTE_EXIT, 0, NULL);
    if (kevent(fd, &change, 1, NULL, 0, NULL) != 0) { close(fd); return 0; }
    *watcher = fd;
    return 1;
}
static int witness_worker(int watcher, pid_t worker, long long deadline) {
    while (remaining(deadline) > 0) {
        long wait_ms = remaining(deadline);
        struct timespec timeout = {.tv_sec = wait_ms / 1000,
                                   .tv_nsec = (wait_ms % 1000) * 1000000L};
        struct kevent event;
        int n = kevent(watcher, NULL, 0, &event, 1, &timeout);
        if (n < 0 && errno == EINTR) continue;
        if (n != 1 || (event.flags & EV_ERROR) ||
            event.filter != EVFILT_PROC ||
            event.ident != (uintptr_t)worker ||
            !(event.fflags & NOTE_EXIT)) return 0;
        return 1;
    }
    return 0;
}
static int bounded_reap(NativeOwner *owner, long long deadline) {
    if (owner->reaped) return 1;
    while (remaining(deadline) > 0) {
        pid_t p = waitpid(owner->pid, &owner->status, WNOHANG);
        if (p == owner->pid) { owner->reaped = 1; return 1; }
        if (p < 0 && errno == EINTR) continue;
        if (p < 0) { owner->lost = 1; return 0; }
        pause_ms(20);
    }
    return 0;
}
static void *competing_waiter(void *opaque) {
    RogueWaiter *waiter = (RogueWaiter *)opaque;
    do { waiter->result = waitpid(waiter->pid, &waiter->status, 0); }
    while (waiter->result < 0 && errno == EINTR);
    return NULL;
}
static int drain_output(int fd, long long deadline, int *saw_forgery) {
    if (fd < 0) return 0;
    char bytes[128];
    char recorded[256] = {0};
    size_t count = 0;
    while (remaining(deadline) > 0) {
        struct pollfd p = {.fd = fd, .events = POLLIN | POLLHUP};
        long wait_ms = remaining(deadline);
        int n = poll(&p, 1, wait_ms < 100 ? (int)wait_ms : 100);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return 0;
        if (!n) continue;
        ssize_t received = read(fd, bytes, sizeof bytes);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) return 0;
        if (received == 0) {
            if (saw_forgery && strstr(recorded, "FINAL ticket=forged") != NULL)
                *saw_forgery = 1;
            return 1;
        }
        if (saw_forgery && count + (size_t)received < sizeof recorded) {
            memcpy(recorded + count, bytes, (size_t)received);
            count += (size_t)received;
            recorded[count] = '\0';
        }
    }
    return 0;
}

static int owner_role(const char *mode, const char *root, const char *binary) {
    int dirfd = -1;
    if (!valid_root(root, &dirfd, binary) || !waitable_sigchld())
        return blocked("private_root_or_sigchld");
    int gate[2] = {-1,-1}, ctrl[2] = {-1,-1}, out[2] = {-1,-1},
        err[2] = {-1,-1}, watcher = -1;
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    int has_fa=0, has_attr=0, complete=0, forgery_seen=0;
    NativeOwner owner = {.pid=-1};
    pid_t worker = -1;
    const char *failure = "initialization";
    if (!owned_pipe(gate) || !owned_pipe(ctrl) || !owned_pipe(out) ||
        !owned_pipe(err)) goto finish;
    if (posix_spawn_file_actions_init(&fa) != 0) goto finish;
    has_fa=1;
    if (posix_spawn_file_actions_addfchdir_np(&fa, dirfd) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, gate[0], STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, ctrl[1], CONTROL_FD) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, out[1], STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, err[1], STDERR_FILENO) != 0 ||
        posix_spawn_file_actions_addclose(&fa, gate[1]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, ctrl[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, out[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, err[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, gate[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, ctrl[1]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, out[1]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, err[1]) != 0) goto finish;
    if (posix_spawnattr_init(&attr) != 0) goto finish;
    has_attr=1;
    if (posix_spawnattr_setpgroup(&attr, 0) != 0 ||
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP) != 0) goto finish;
    char *const relay_argv[] = {(char *)binary, "__relay", (char *)mode,
                                (char *)root, NULL};
    failure="relay_spawn";
    if (posix_spawn(&owner.pid, binary, &fa, &attr, relay_argv, environ) != 0)
        goto finish;
    close_fd(&gate[0]); close_fd(&ctrl[1]);
    close_fd(&out[1]); close_fd(&err[1]);
    close_fd(&dirfd);
    if (has_fa) { posix_spawn_file_actions_destroy(&fa); has_fa=0; }
    if (has_attr) { posix_spawnattr_destroy(&attr); has_attr=0; }

    long long deadline = millis_now() + 7800;
    char line[LINE_MAXIMUM];
    failure="relay_ready";
    if (!read_line(ctrl[0], line, sizeof line, deadline) ||
        !parse_ready(line, &worker)) goto finish;
    failure="worker_group_or_session";
    if (getpgid(worker) != owner.pid || getpgid(owner.pid) != owner.pid ||
        getsid(worker) != getsid(owner.pid)) goto finish;
    failure="worker_witness";
    if (!watch_worker(&watcher, worker)) goto finish;
    failure="synthetic_arm";
    if (!write_one(gate[1], 'A') ||
        !read_line(ctrl[0], line, sizeof line, deadline) ||
        strcmp(line, "C3_ARMED") != 0) goto finish;

    if (strcmp(mode, "term-default") == 0) {
        failure="term_eligibility";
        if (!signal_owned_group(&owner, SIGTERM, deadline)) goto finish;
        failure="observed_worker_signal";
        if (!read_line(ctrl[0], line, sizeof line, deadline) ||
            !parse_reaped(line, worker, "SIGNAL", SIGTERM)) goto finish;
        owner.signals_closed = 1;
        if (!write_one(gate[1], 'Q')) goto finish;
    } else if (strcmp(mode, "kill-unknown") == 0) {
        failure="term_eligibility";
        if (!signal_owned_group(&owner, SIGTERM, deadline)) goto finish;
        pause_ms(180);
        failure="kill_eligibility";
        if (getpgid(worker) != owner.pid ||
            !signal_owned_group(&owner, SIGKILL, deadline)) goto finish;
    } else if (strcmp(mode, "leader-exit") == 0) {
        failure="intentional_relay_exit";
        if (!bounded_reap(&owner, deadline) || !WIFEXITED(owner.status))
            goto finish;
        if (owner_is_live(&owner)) goto finish;
        owner.lost=1; owner.signals_closed=1;
        if (signal_owned_group(&owner, SIGTERM, deadline) != 0) goto finish;
    } else if (strcmp(mode, "competing-reap") == 0) {
        failure="rogue_waiter";
        RogueWaiter w = {.pid=owner.pid, .result=-1};
        pthread_t thread;
        if (pthread_create(&thread, NULL, competing_waiter, &w) != 0) goto finish;
        if (pthread_join(thread, NULL) != 0 || w.result != owner.pid)
            goto finish;
        int status;
        errno = 0;
        if (waitpid(owner.pid, &status, WNOHANG) != -1 || errno != ECHILD)
            goto finish;
        owner.lost=1; owner.reaped=1; owner.signals_closed=1;
        if (signal_owned_group(&owner, SIGTERM, deadline) != 0) goto finish;
    } else if (strcmp(mode, "identity-loss") == 0) {
        owner.lost=1; owner.signals_closed=1; /* Explicit negative admission gate. */
        if (owner_is_live(&owner) ||
            signal_owned_group(&owner, SIGTERM, deadline) != 0) goto finish;
        failure="identity_worker_natural";
        if (!read_line(ctrl[0], line, sizeof line, deadline) ||
            !parse_reaped(line, worker, "EXIT", 0)) goto finish;
        if (!write_one(gate[1], 'Q')) goto finish;
    } else if (strcmp(mode, "ipc-forgery") == 0) {
        failure="actual_worker_wait";
        if (!read_line(ctrl[0], line, sizeof line, deadline) ||
            !parse_reaped(line, worker, "EXIT", 0)) goto finish;
        owner.signals_closed = 1;
        if (!write_one(gate[1], 'Q')) goto finish;
    } else {
        failure="mode_not_allowed";
        goto finish;
    }

    failure="independent_worker_exit";
    if (!witness_worker(watcher, worker, deadline)) goto finish;
    failure="owned_relay_reap";
    if (strcmp(mode, "competing-reap") != 0 &&
        !bounded_reap(&owner, deadline)) goto finish;
    failure="drain_stdout";
    if (!drain_output(out[0], deadline,
                      strcmp(mode, "ipc-forgery") == 0 ? &forgery_seen : NULL))
        goto finish;
    failure="drain_stderr";
    if (!drain_output(err[0], deadline, NULL)) goto finish;
    if (strcmp(mode, "ipc-forgery") == 0 && !forgery_seen) {
        failure="stdout_fake_not_exercised"; goto finish;
    }
    if (strcmp(mode, "term-default") == 0 &&
        (!WIFEXITED(owner.status) || WEXITSTATUS(owner.status) != 0)) {
        failure="relay_term_cleanup"; goto finish;
    }
    if (strcmp(mode, "kill-unknown") == 0 &&
        (!WIFSIGNALED(owner.status) || WTERMSIG(owner.status) != SIGKILL)) {
        failure="relay_kill_cleanup"; goto finish;
    }
    if (strcmp(mode, "competing-reap") == 0 && owner.group_signals != 0) {
        failure="signal_after_rogue_reap"; goto finish;
    }
    complete = 1;
finish:
    if (has_attr) posix_spawnattr_destroy(&attr);
    if (has_fa) posix_spawn_file_actions_destroy(&fa);
    close_fd(&dirfd); close_fd(&gate[0]); close_fd(&gate[1]);
    close_fd(&ctrl[0]); close_fd(&ctrl[1]);
    close_fd(&out[0]); close_fd(&out[1]);
    close_fd(&err[0]); close_fd(&err[1]); close_fd(&watcher);
    if (!complete) {
        /* Never issue a negative PGID signal on failure. A still-owned direct
           unreaped synthetic child PID may be used only for bounded cleanup. */
        if (owner.pid > 0 && !owner.reaped) {
            int status;
            pid_t r = waitpid(owner.pid, &status, WNOHANG);
            if (r == 0) {
                (void)kill(owner.pid, SIGKILL);
                while (waitpid(owner.pid, &status, 0) < 0 && errno == EINTR) {}
            }
        }
        /* All synthetic workers have a strict self-expiry if orphaned. */
        return blocked(failure);
    }
    const char *worker_kind, *cleanup, *state;
    int term=0, kill_sent=0, ipc=1;
    if (strcmp(mode, "term-default") == 0) {
        worker_kind="OBSERVED_SIGNAL"; cleanup="VERIFIED"; term=1;
        state="SIGNALS_CLOSED";
    } else if (strcmp(mode, "kill-unknown") == 0) {
        worker_kind="UNKNOWN"; cleanup="UNRESOLVED"; term=1; kill_sent=1;
        state="SIGNALS_CLOSED";
    } else if (strcmp(mode, "ipc-forgery") == 0) {
        worker_kind="OBSERVED_EXIT"; cleanup="VERIFIED";
        state="SIGNALS_CLOSED";
    } else {
        worker_kind="UNKNOWN"; cleanup="UNRESOLVED"; state="QUARANTINED";
        ipc=strcmp(mode, "leader-exit") == 0 ? 1 : 0;
    }
    printf("C3_RESULT mode=%s worker=%s cleanup=%s term=%d kill=%d "
           "owner_reaped=%d after_loss_signals=%d ipc_proven=%d state=%s\n",
           mode, worker_kind, cleanup, term, kill_sent, owner.reaped,
           owner.after_loss_signals, ipc, state);
    return 0;
}

int main(int argc, char **argv) {
    const char *role, *mode, *root;
    if (argc == 3) {
        role = "__owner"; mode = argv[1]; root = argv[2];
    } else if (argc == 4) {
        role = argv[1]; mode = argv[2]; root = argv[3];
        if (strcmp(role, "__relay") != 0 && strcmp(role, "__worker") != 0)
            return blocked("internal_role");
    } else {
        return blocked("usage");
    }
    if (strcmp(mode, "term-default") != 0 &&
        strcmp(mode, "kill-unknown") != 0 &&
        strcmp(mode, "leader-exit") != 0 &&
        strcmp(mode, "competing-reap") != 0 &&
        strcmp(mode, "ipc-forgery") != 0 &&
        strcmp(mode, "identity-loss") != 0) return blocked("mode");
    if (root[0] != '/') return blocked("synthetic_only");
    int dirfd = -1;
    if (!valid_root(root, &dirfd, argv[0])) return blocked("synthetic_marker");
    close_fd(&dirfd);
    if (strcmp(role, "__relay") == 0) return relay_role(mode, argv[0], root);
    if (strcmp(role, "__worker") == 0) return worker_role(mode);
    return owner_role(mode, root, argv[0]);
}
#endif
