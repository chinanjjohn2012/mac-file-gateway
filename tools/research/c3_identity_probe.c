/* C3-05/06/13 research: fresh, disposable, privately owned Darwin groups ONLY.
 * This cannot run arbitrary commands or address an existing external PID/PGID.
 * A user-space group-signal check is NOT an atomic kernel identity guarantee.
 */
#if !defined(__APPLE__)
#include <stdio.h>
int main(void) { fputs("C3_ID_NOT_RUN_NON_DARWIN\n", stderr); return 77; }
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
typedef struct {
    pid_t pid;
    int input, output;
    int reaped, lost, status;
    int group_signals, after_loss_signals;
    /* P2-01: count syscall ATTEMPTS before Darwin kill, even on ESRCH. */
    int group_attempts, after_loss_attempts;
    int pid_signals, ownership_contested;
} Owned;
typedef struct {
    pid_t pid;
    int ready_fd, result_fd;
} WaiterContext; /* Heap-owned and released by detached waiter itself. */
typedef struct {
    pid_t result;
    int status, error_code;
} WaiterResult; /* Sent by real waiter through a bounded private pipe. */

static long long clock_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static long ms_left(long long deadline) {
    long long delta = deadline - clock_ms();
    return delta <= 0 ? 0 : delta > LONG_MAX ? LONG_MAX : (long)delta;
}
static void delay_ms(long ms) {
    struct timespec ts = {.tv_sec = ms / 1000,
                          .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}
static int block(const char *reason) {
    fprintf(stderr, "C3_ID_BLOCK phase=%s\n", reason);
    return 70;
}
static int close_owned(int *fd) {
    if (*fd < 0) return 1;
    int old = *fd;
    *fd = -1;
    return close(old) == 0;
}
static int pipe_owned(int fd[2]) {
    if (pipe(fd) != 0) return 0;
    if (fcntl(fd[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(fd[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(fd[0]); close(fd[1]);
        fd[0] = fd[1] = -1;
        return 0;
    }
    return 1;
}
static int ignore_sigpipe_for_owner(void) {
    struct sigaction action, verify;
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_IGN;
    return sigemptyset(&action.sa_mask) == 0 &&
           sigaction(SIGPIPE, &action, NULL) == 0 &&
           sigaction(SIGPIPE, NULL, &verify) == 0 &&
           verify.sa_handler == SIG_IGN;
}

static int write_byte(int fd, char byte) {
    while (1) {
        ssize_t n = write(fd, &byte, 1);
        if (n == 1) return 1;
        if (n < 0 && errno == EINTR) continue;
        return 0;
    }
}
static int read_byte(int fd, char expected, long long deadline) {
    while (ms_left(deadline) > 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
        int wait_ms = (int)(ms_left(deadline) > 200 ? 200 : ms_left(deadline));
        int ready = poll(&pfd, 1, wait_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return 0;
        if (!ready) continue;
        char actual = 0;
        ssize_t n = read(fd, &actual, 1);
        if (n < 0 && errno == EINTR) continue;
        return n == 1 && actual == expected;
    }
    return 0;
}
static int read_waiter_result(int fd, WaiterResult *result, long long deadline) {
    unsigned char *buffer = (unsigned char *)result;
    size_t read_total = 0;
    while (read_total < sizeof *result && ms_left(deadline) > 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
        int timeout = (int)(ms_left(deadline) > 100 ? 100 : ms_left(deadline));
        int ready = poll(&pfd, 1, timeout);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return 0;
        if (!ready) continue;
        ssize_t got = read(fd, buffer + read_total, sizeof *result - read_total);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return 0;
        read_total += (size_t)got;
    }
    return read_total == sizeof *result;
}

static int waitable_sigchld(void) {
    struct sigaction wanted, actual;
    memset(&wanted, 0, sizeof wanted);
    wanted.sa_handler = SIG_DFL;
    if (sigemptyset(&wanted.sa_mask) != 0 ||
        sigaction(SIGCHLD, &wanted, NULL) != 0 ||
        sigaction(SIGCHLD, NULL, &actual) != 0) return 0;
    return actual.sa_handler == SIG_DFL &&
           (actual.sa_flags & SA_NOCLDWAIT) == 0;
}
static int private_root(const char *root, const char *executable, int *fd) {
    if (!root || root[0] != '/' || !executable) return 0;
    size_t len = strlen(root);
    if (strncmp(executable, root, len) != 0 ||
        strcmp(executable + len, "/c3_identity_native") != 0) return 0;
    int dir = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return 0;
    struct stat st;
    if (fstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077) != 0) goto invalid;
    int mark = openat(dir, "C3_ID_TEST_MARKER",
                      O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (mark < 0) goto invalid;
    char bytes[16] = {0};
    ssize_t size = read(mark, bytes, sizeof bytes);
    int good = fstat(mark, &st) == 0 && S_ISREG(st.st_mode) &&
               st.st_uid == geteuid() && st.st_nlink == 1 &&
               size == 9 && memcmp(bytes, "synthetic", 9) == 0;
    close(mark);
    if (!good) goto invalid;
    int exe = openat(dir, "c3_identity_native",
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (exe < 0) goto invalid;
    good = fstat(exe, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == geteuid() && st.st_nlink == 1 &&
           (st.st_mode & 0111) != 0;
    close(exe);
    if (!good) goto invalid;
    *fd = dir;
    return 1;
invalid:
    close(dir);
    return 0;
}
static int synthetic_child(const char *behavior) {
#ifndef C3_ID_TEST_FAULTS
    (void)behavior;
#endif
    /* Private synthetic child only. Parent gets explicit readiness first.
       Children restore SIGPIPE default after Owner ignored it locally. */
    alarm(8);
    if (getpgid(0) != getpid()) return 41;
#ifdef C3_ID_TEST_FAULTS
    if (strcmp(behavior, "fault-broken-pipe") == 0) {
        close(STDIN_FILENO);
        if (!write_byte(STDOUT_FILENO, 'R')) return 42;
        delay_ms(400); /* Owner observes READY while the old read end is closed. */
        return 0;
    }
#endif
    if (!write_byte(STDOUT_FILENO, 'R')) return 42;
    char code = 0;
    ssize_t n;
    do { n = read(STDIN_FILENO, &code, 1); }
    while (n < 0 && errno == EINTR);
#ifdef C3_ID_TEST_FAULTS
    if (n == 0 && strcmp(behavior, "fault-waiter-timeout") == 0) {
        delay_ms(2500); /* Longer than the injected bounded wait budget. */
        return 0;
    }
#endif
    if (n == 0) return 0; /* Parent closed gate on failure. */
    if (n != 1 || (code != 'E' && code != 'Q')) return 43;
    return 0;
}
static int spawn_owned(const char *binary, const char *root,
                       int dirfd, Owned *o, long long deadline,
                       const char *behavior) {
    int in[2] = {-1,-1}, out[2] = {-1,-1};
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    int made_fa = 0, made_attr = 0, success = 0;
    if (!pipe_owned(in) || !pipe_owned(out)) goto finish;
    if (posix_spawn_file_actions_init(&fa) != 0) goto finish;
    made_fa = 1;
    if (posix_spawn_file_actions_addfchdir_np(&fa, dirfd) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, in[0], STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, out[1], STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_addclose(&fa, in[1]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, out[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, in[0]) != 0 ||
        posix_spawn_file_actions_addclose(&fa, out[1]) != 0 ||
        posix_spawn_file_actions_addopen(&fa, STDERR_FILENO,
                                          "/dev/null", O_WRONLY, 0) != 0)
        goto finish;
    if (posix_spawnattr_init(&attr) != 0) goto finish;
    made_attr = 1;
    sigset_t defaults, mask;
    if (sigemptyset(&defaults) != 0 ||
        sigaddset(&defaults, SIGTERM) != 0 ||
        sigaddset(&defaults, SIGPIPE) != 0 ||
        sigemptyset(&mask) != 0 ||
        posix_spawnattr_setsigdefault(&attr, &defaults) != 0 ||
        posix_spawnattr_setsigmask(&attr, &mask) != 0 ||
        posix_spawnattr_setpgroup(&attr, 0) != 0 ||
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP |
                                       POSIX_SPAWN_SETSIGDEF |
                                       POSIX_SPAWN_SETSIGMASK) != 0)
        goto finish;
    char *const args[] = {(char *)binary, "__child", (char *)root,
                          (char *)behavior, NULL};
    if (posix_spawn(&o->pid, binary, &fa, &attr, args, environ) != 0)
        goto finish;
    close_owned(&in[0]); close_owned(&out[1]);
    o->input = in[1]; in[1] = -1;
    o->output = out[0]; out[0] = -1;
    if (!read_byte(o->output, 'R', deadline)) goto finish;
    if (getpgid(o->pid) != o->pid ||
        getsid(o->pid) != getsid(getpid())) goto finish;
    success = 1;
finish:
    if (made_attr) posix_spawnattr_destroy(&attr);
    if (made_fa) posix_spawn_file_actions_destroy(&fa);
    close_owned(&in[0]); close_owned(&in[1]);
    close_owned(&out[0]); close_owned(&out[1]);
    return success;
}
static int live_owned(Owned *o, long long deadline) {
    if (o->pid <= 0 || o->lost || o->reaped || ms_left(deadline) <= 0)
        return 0;
    int status = 0;
    pid_t got;
    do { got = waitpid(o->pid, &status, WNOHANG); }
    while (got < 0 && errno == EINTR && ms_left(deadline) > 0);
    if (got == o->pid) {
        o->status = status; o->reaped = 1; o->lost = 1;
        return 0;
    }
    if (got != 0 || getpgid(o->pid) != o->pid) {
        o->lost = 1;
        return 0;
    }
    return 1;
}
/* All real negative-PGID syscalls go through this wrapper. Fault builds
 * intercept the syscall and return ESRCH, never signal a stale numeric group.
 * Counter increments occur BEFORE the system call and cannot be inferred
 * from a successful kill result. A deliberate test mutant proves detection.
 */
static int group_signal_attempt(Owned *o, int signum) {
#ifndef C3_ID_TEST_SUPPRESS_ATTEMPT_ACCOUNTING
    o->group_attempts++;
    if (o->lost || o->reaped || o->ownership_contested)
        o->after_loss_attempts++;
#endif
#ifdef C3_ID_TEST_KILL_STUB
    (void)o;
    (void)signum;
    errno = ESRCH;
    return -1;
#else
    return kill(-o->pid, signum);
#endif
}
static int signal_owned_group(Owned *o, long long deadline) {
    if (!live_owned(o, deadline) || ms_left(deadline) <= 0) return 0;
    /* Deliberate research-only window: this check and the Darwin syscall
       are NOT atomic; identity under arbitrary scheduling remains G2 BLOCK. */
    if (group_signal_attempt(o, SIGTERM) != 0) return 0;
    o->group_signals++;
    if (o->lost) o->after_loss_signals++;
    return 1;
}
static int reap_owned(Owned *o, long long deadline) {
    if (o->reaped) return 1;
    if (o->lost || o->pid <= 0) return 0;
    while (ms_left(deadline) > 0) {
        int st = 0;
        pid_t got = waitpid(o->pid, &st, WNOHANG);
        if (got == o->pid) { o->reaped = 1; o->status = st; return 1; }
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) { o->lost = 1; return 0; }
        delay_ms(20);
    }
    return 0;
}
static int register_exit_note(int *watcher, pid_t pid) {
    int fd = kqueue();
    if (fd < 0) return 0;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) { close(fd); return 0; }
    struct kevent change;
    EV_SET(&change, (uintptr_t)pid, EVFILT_PROC,
           EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent(fd, &change, 1, NULL, 0, NULL) != 0) {
        close(fd); return 0;
    }
    *watcher = fd;
    return 1;
}
static int wait_exit_note(int watcher, pid_t pid, long long deadline) {
    while (ms_left(deadline) > 0) {
        long ms = ms_left(deadline);
        struct timespec timeout = {.tv_sec = ms / 1000,
                                   .tv_nsec = (ms % 1000) * 1000000L};
        struct kevent event;
        int n = kevent(watcher, NULL, 0, &event, 1, &timeout);
        if (n < 0 && errno == EINTR) continue;
        if (n != 1 || (event.flags & EV_ERROR) ||
            event.filter != EVFILT_PROC || event.ident != (uintptr_t)pid ||
            !(event.fflags & NOTE_EXIT)) return 0;
        return 1;
    }
    return 0;
}
static void *competing_waiter(void *opaque) {
    WaiterContext *w = (WaiterContext *)opaque;
    WaiterResult event = {.result = -1, .status = 0, .error_code = 0};
    (void)write_byte(w->ready_fd, 'W');
    do { event.result = waitpid(w->pid, &event.status, 0); }
    while (event.result < 0 && errno == EINTR);
    if (event.result < 0) event.error_code = errno;
    /* A single struct fits PIPE_BUF. If Owner timed out or closed the reader,
       SIGPIPE was ignored and no thread accesses Owner's stack memory. */
    (void)write(w->result_fd, &event, sizeof event);
    (void)close(w->ready_fd);
    (void)close(w->result_fd);
    free(w);
    return NULL;
}
static int canary_still_owned(Owned *b, long long deadline) {
    return b->pid > 0 && live_owned(b, deadline);
}
static void safe_owned_cleanup(Owned *o) {
    close_owned(&o->input);
    close_owned(&o->output);
    if (o->pid <= 0 || o->lost || o->reaped || o->ownership_contested) return;
    int st = 0;
    pid_t result;
    do { result = waitpid(o->pid, &st, WNOHANG); }
    while (result < 0 && errno == EINTR);
    if (result == o->pid) {
        o->reaped = 1; o->status = st; return;
    }
    if (result < 0) { o->lost = 1; return; }
    /* Direct-child-only failure cleanup, never negative PGID after uncertainty. */
    o->pid_signals++; /* Count direct-child PID attempts as well. */
    (void)kill(o->pid, SIGKILL);
    long long deadline = clock_ms() + 1500;
    (void)reap_owned(o, deadline);
}
static int owner_run(const char *mode, const char *root, const char *binary) {
    int dirfd = -1, watcher = -1;
    Owned a = {.pid=-1,.input=-1,.output=-1};
    Owned b = {.pid=-1,.input=-1,.output=-1};
    WaiterResult waiter_event = {.result=-1, .status=0, .error_code=0};
    int sync[2] = {-1,-1}, result[2] = {-1,-1};
    int exit_observed = 0, refused = 0, canary_alive = 0;
    int success = 0, owned_reap_at_barrier = 0;
    int waiter_active = 0, waiter_done = 0;
#ifdef C3_ID_TEST_FAULTS
    int epipe = 0;
    int fault_mode = strncmp(mode, "fault-", 6) == 0;
#endif
    const char *failure = "private_root";
    if (!private_root(root, binary, &dirfd)) goto done;
    failure = "sigchld_or_sigpipe";
    if (!waitable_sigchld() || !ignore_sigpipe_for_owner()) goto done;
    long long deadline = clock_ms() + 5000;
    failure = "spawn_A";
    if (!spawn_owned(binary, root, dirfd, &a, deadline, mode) ||
        !live_owned(&a, deadline)) goto done;

#ifdef C3_ID_TEST_FAULTS
    if (strcmp(mode, "fault-unauthorized-esrch") == 0) {
        /* Test-only bypass of eligibility: stub MUST NOT call Darwin kill(-).
           The injected ESRCH has no chance to signal an unrelated group. */
        a.lost = 1;
        errno = 0;
        int injected = group_signal_attempt(&a, SIGTERM);
        int injected_errno = errno;
        failure = injected == -1 && injected_errno == ESRCH
                  ? "unauthorized_signal_attempt" : "fault_stub_incorrect";
        goto done;
    }
    if (strcmp(mode, "fault-broken-pipe") == 0) {
        /* Child closes stdin before exit; reap before writing so EPIPE is
           certain and does not depend on a scheduler sleep. */
        failure = "fault_child_reap";
        if (!reap_owned(&a, deadline)) goto done;
        errno = 0;
        int sent = write_byte(a.input, 'E');
        epipe = !sent && errno == EPIPE;
        failure = epipe ? "broken_pipe_epipe" : "broken_pipe_not_epipe";
        goto done;
    }
#endif

    if (strcmp(mode, "exit-unreaped") == 0) {
        failure = "register_note_exit";
        if (!register_exit_note(&watcher, a.pid)) goto done;
        /* C3-05: owner-live BEFORE exit; observe NOTE_EXIT while still not
           reaped by Owner, THEN final eligibility check must safely refuse. */
        failure = "controlled_exit";
        if (!write_byte(a.input, 'E') ||
            !wait_exit_note(watcher, a.pid, deadline)) goto done;
        exit_observed = 1;
        owned_reap_at_barrier = a.reaped;
        failure = "post_exit_admission";
        refused = !signal_owned_group(&a, deadline);
        if (!refused || a.group_signals != 0 ||
            owned_reap_at_barrier != 0 || !a.reaped) goto done;
    } else if (strcmp(mode, "competing-reap") == 0
#ifdef C3_ID_TEST_FAULTS
               || strcmp(mode, "fault-waiter-ready") == 0
               || strcmp(mode, "fault-waiter-timeout") == 0
               || strcmp(mode, "fault-waiter-result") == 0
#endif
              ) {
        /* C3-06 intentionally violates the sole-owner contract. Mark PID
           ownership contested BEFORE another waiter can call waitpid. */
        failure = "competing_thread";
        if (!pipe_owned(sync) || !pipe_owned(result)) goto done;
        WaiterContext *context = calloc(1, sizeof *context);
        if (!context) goto done;
        context->pid = a.pid;
        context->ready_fd = dup(sync[1]);
        context->result_fd = dup(result[1]);
        if (context->ready_fd < 0 || context->result_fd < 0) {
            if (context->ready_fd >= 0) close(context->ready_fd);
            if (context->result_fd >= 0) close(context->result_fd);
            free(context);
            goto done;
        }
        pthread_attr_t attributes;
        int attr_ready = pthread_attr_init(&attributes) == 0;
        if (!attr_ready) {
            close(context->ready_fd); close(context->result_fd); free(context);
            goto done;
        }
        int detached = pthread_attr_setdetachstate(
                           &attributes, PTHREAD_CREATE_DETACHED) == 0;
        /* No direct PID fallback is allowed once a waiter might race. */
        a.ownership_contested = 1;
        a.lost = 1;
        pthread_t thread;
        int created = detached &&
            pthread_create(&thread, &attributes, competing_waiter, context) == 0;
        (void)pthread_attr_destroy(&attributes);
        if (!created) {
            close(context->ready_fd); close(context->result_fd); free(context);
            goto done;
        }
        waiter_active = 1;
        close_owned(&sync[1]); close_owned(&result[1]);

#ifdef C3_ID_TEST_FAULTS
        if (strcmp(mode, "fault-waiter-ready") == 0) {
            failure = "fault_waiter_ready"; /* Close gate before bounded wait. */
            goto done;
        }
#endif
        failure = "competing_handshake";
        if (!read_byte(sync[0], 'W', deadline)) goto done;
#ifdef C3_ID_TEST_FAULTS
        if (strcmp(mode, "fault-waiter-timeout") == 0) {
            /* Synthetic shorter deadline, then release the gate and do not
               wait indefinitely for a delayed cooperative child. */
            deadline = clock_ms() + 150;
            failure = "fault_waiter_timeout";
            goto done;
        }
#endif
        if (!write_byte(a.input, 'E')) goto done;
#ifdef C3_ID_TEST_FAULTS
        if (strcmp(mode, "fault-waiter-result") == 0) {
            close_owned(&result[0]);
            failure = "fault_waiter_result";
            goto done;
        }
#endif
        if (!read_waiter_result(result[0], &waiter_event, deadline))
            goto done;
        waiter_done = 1;
        if (waiter_event.result != a.pid ||
            !WIFEXITED(waiter_event.status) ||
            WEXITSTATUS(waiter_event.status) != 0) goto done;
        exit_observed = 1;
        int own_status = 0;
        errno = 0;
        failure = "competing_echild";
        if (waitpid(a.pid, &own_status, WNOHANG) != -1 ||
            errno != ECHILD) goto done;
        refused = !signal_owned_group(&a, deadline);
        if (!refused || a.group_signals != 0 || a.reaped) goto done;
    } else if (strcmp(mode, "group-isolation") == 0 ||
               strcmp(mode, "stale-after-reap") == 0) {
        failure = "spawn_canary";
        if (!spawn_owned(binary, root, dirfd, &b, deadline, "canary") ||
            !live_owned(&b, deadline) ||
            a.pid == b.pid || getsid(a.pid) != getsid(b.pid)) goto done;
        if (strcmp(mode, "group-isolation") == 0) {
            failure = "owned_target_term";
            if (!signal_owned_group(&a, deadline) ||
                !reap_owned(&a, deadline) ||
                !WIFSIGNALED(a.status) || WTERMSIG(a.status) != SIGTERM)
                goto done;
        } else {
            failure = "stale_reaped_target";
            if (!write_byte(a.input, 'E') ||
                !reap_owned(&a, deadline) ||
                !WIFEXITED(a.status) || WEXITSTATUS(a.status) != 0)
                goto done;
            refused = !signal_owned_group(&a, deadline);
            if (!refused || a.group_signals != 0) goto done;
        }
        exit_observed = 1;
        failure = "canary_survives";
        canary_alive = canary_still_owned(&b, deadline);
        if (!canary_alive) goto done;
        failure = "cooperative_canary_cleanup";
        if (!write_byte(b.input, 'Q') ||
            !reap_owned(&b, deadline) ||
            !WIFEXITED(b.status) || WEXITSTATUS(b.status) != 0) goto done;
    } else {
        failure = "unknown_mode";
        goto done;
    }
    failure = "final_evidence";
    if (!exit_observed ||
        (!b.reaped &&
         (strcmp(mode, "group-isolation") == 0 ||
          strcmp(mode, "stale-after-reap") == 0)) ||
        a.group_signals > 1 || a.after_loss_signals != 0 ||
        b.group_signals != 0) goto done;
    success = 1;
done:
    /* P2-03: close the child's input FIRST, releasing its own wait path.
       The competing detached waiter owns its heap context, so the Owner can
       bound observation by the existing monotonic budget (no pthread_join).
       A contested PID is NEVER eligible for direct-PID SIGKILL fallback. */
    if (waiter_active && !waiter_done) {
        close_owned(&a.input);
        if (result[0] >= 0 && ms_left(deadline) > 0 &&
            read_waiter_result(result[0], &waiter_event, deadline))
            waiter_done = waiter_event.result == a.pid &&
                          WIFEXITED(waiter_event.status) &&
                          WEXITSTATUS(waiter_event.status) == 0;
    }
    close_owned(&watcher);
    close_owned(&sync[0]); close_owned(&sync[1]);
    close_owned(&result[0]); close_owned(&result[1]);
    close_owned(&dirfd);
    safe_owned_cleanup(&a);
    safe_owned_cleanup(&b);
#ifdef C3_ID_TEST_FAULTS
    if (fault_mode) {
        int complete = waiter_active ? waiter_done : a.reaped;
        printf("C3_ID_FAULT mode=%s attempts=%d after_loss_attempts=%d "
               "pid_signals=%d epipe=%d waiter_contested=%d "
               "waiter_done=%d cleanup_complete=%d reuse_proven=0\n",
               mode, a.group_attempts, a.after_loss_attempts,
               a.pid_signals, epipe, a.ownership_contested,
               waiter_done, complete);
        fflush(stdout);
        if (success) return block("fault_must_never_succeed");
        return block(failure);
    }
#endif
    if (!success) return block(failure);
    if (strcmp(mode, "competing-reap") == 0 && a.reaped) return block("rogue_owner_reap");
    printf("C3_ID_RESULT mode=%s exit_observed=%d owner_reaped=%d "
           "group_signals=%d group_attempts=%d after_loss_attempts=%d "
           "after_loss_signals=%d canary_alive=%d "
           "refused=%d reuse_proven=0\n",
           mode, exit_observed, a.reaped, a.group_signals,
           a.group_attempts, a.after_loss_attempts,
           a.after_loss_signals, canary_alive, refused);
    return 0;
}
int main(int argc, char **argv) {
    const char *mode, *root, *behavior = "regular";
    if (argc == 3) {
        mode = argv[1]; root = argv[2];
    } else if (argc == 4 && strcmp(argv[1], "__child") == 0) {
        mode = argv[1]; root = argv[2]; behavior = argv[3];
    } else {
        return block("usage");
    }
    int child = strcmp(mode, "__child") == 0;
    if (root[0] != '/') return block("non_private_root");
    int fd = -1;
    if (!private_root(root, argv[0], &fd)) return block("non_synthetic_root");
    close_owned(&fd);
    if (child) return synthetic_child(behavior);
    if (strcmp(mode, "exit-unreaped") != 0 &&
        strcmp(mode, "competing-reap") != 0 &&
        strcmp(mode, "group-isolation") != 0 &&
        strcmp(mode, "stale-after-reap") != 0
#ifdef C3_ID_TEST_FAULTS
        && strcmp(mode, "fault-unauthorized-esrch") != 0
        && strcmp(mode, "fault-broken-pipe") != 0
        && strcmp(mode, "fault-waiter-ready") != 0
        && strcmp(mode, "fault-waiter-timeout") != 0
        && strcmp(mode, "fault-waiter-result") != 0
#endif
       ) return block("unknown_mode");
    return owner_run(mode, root, argv[0]);
}
#endif
