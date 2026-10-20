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
    int reaped, lost, status, group_signals, after_loss_signals;
} Owned;
typedef struct {
    pid_t pid;
    int ready_fd, result_fd;
    pid_t wait_result;
    int status;
} CompetingWait;

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
static int synthetic_child(void) {
    /* A child uses only its own stdin handshakes; group membership was set
       atomically by posix_spawn attributes, before any workload code. */
    alarm(8);
    if (getpgid(0) != getpid()) return 41;
    if (!write_byte(STDOUT_FILENO, 'R')) return 42;
    char code = 0;
    ssize_t n;
    do { n = read(STDIN_FILENO, &code, 1); }
    while (n < 0 && errno == EINTR);
    if (n == 0) return 0; /* Parent closed gate on failure. */
    if (n != 1 || (code != 'E' && code != 'Q')) return 43;
    return 0;
}
static int spawn_owned(const char *binary, const char *root,
                       int dirfd, Owned *o, long long deadline) {
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
        sigemptyset(&mask) != 0 ||
        posix_spawnattr_setsigdefault(&attr, &defaults) != 0 ||
        posix_spawnattr_setsigmask(&attr, &mask) != 0 ||
        posix_spawnattr_setpgroup(&attr, 0) != 0 ||
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP |
                                       POSIX_SPAWN_SETSIGDEF |
                                       POSIX_SPAWN_SETSIGMASK) != 0)
        goto finish;
    char *const args[] = {(char *)binary, "__child", (char *)root, NULL};
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
static int signal_owned_group(Owned *o, long long deadline) {
    if (!live_owned(o, deadline) || ms_left(deadline) <= 0) return 0;
    /* Deliberate research-only window: this check and the Darwin syscall
       are NOT atomic; identity under arbitrary scheduling remains G2 BLOCK. */
    if (kill(-o->pid, SIGTERM) != 0) return 0;
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
    CompetingWait *w = (CompetingWait *)opaque;
    (void)write_byte(w->ready_fd, 'W');
    do { w->wait_result = waitpid(w->pid, &w->status, 0); }
    while (w->wait_result < 0 && errno == EINTR);
    (void)write_byte(w->result_fd, 'D');
    return NULL;
}
static int canary_still_owned(Owned *b, long long deadline) {
    return b->pid > 0 && live_owned(b, deadline);
}
static void safe_owned_cleanup(Owned *o) {
    close_owned(&o->input);
    close_owned(&o->output);
    if (o->pid <= 0 || o->lost || o->reaped) return;
    int st = 0;
    pid_t result;
    do { result = waitpid(o->pid, &st, WNOHANG); }
    while (result < 0 && errno == EINTR);
    if (result == o->pid) {
        o->reaped = 1; o->status = st; return;
    }
    if (result < 0) { o->lost = 1; return; }
    /* Direct-child-only failure cleanup, never negative PGID after uncertainty. */
    (void)kill(o->pid, SIGKILL);
    long long deadline = clock_ms() + 1500;
    (void)reap_owned(o, deadline);
}
static int owner_run(const char *mode, const char *root, const char *binary) {
    int dirfd = -1, watcher = -1;
    Owned a = {.pid=-1,.input=-1,.output=-1};
    Owned b = {.pid=-1,.input=-1,.output=-1};
    CompetingWait w = {.pid=-1,.ready_fd=-1,.result_fd=-1,.wait_result=-1};
    int sync[2] = {-1,-1}, result[2] = {-1,-1};
    int exit_observed = 0, refused = 0, canary_alive = 0;
    int success = 0, owned_reap_at_barrier = 0;
    const char *failure = "private_root";
    if (!private_root(root, binary, &dirfd)) goto done;
    failure = "sigchld";
    if (!waitable_sigchld()) goto done;
    long long deadline = clock_ms() + 5000;
    failure = "spawn_A";
    if (!spawn_owned(binary, root, dirfd, &a, deadline) ||
        !live_owned(&a, deadline)) goto done;

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
    } else if (strcmp(mode, "competing-reap") == 0) {
        /* C3-06 intentionally violates production's exclusive-wait invariant
           ONLY in this isolated test. The other thread really calls waitpid. */
        failure = "competing_thread";
        if (!pipe_owned(sync) || !pipe_owned(result)) goto done;
        w.pid = a.pid; w.ready_fd = sync[1]; w.result_fd = result[1];
        pthread_t thread;
        if (pthread_create(&thread, NULL, competing_waiter, &w) != 0) goto done;
        failure = "competing_handshake";
        int ready = read_byte(sync[0], 'W', deadline);
        int sent = ready && write_byte(a.input, 'E');
        int witnessed = sent && read_byte(result[0], 'D', deadline);
        if (pthread_join(thread, NULL) != 0 || !ready || !sent ||
            !witnessed || w.wait_result != a.pid ||
            !WIFEXITED(w.status) || WEXITSTATUS(w.status) != 0) goto done;
        exit_observed = 1;
        int own_status = 0;
        errno = 0;
        failure = "competing_echild";
        if (waitpid(a.pid, &own_status, WNOHANG) != -1 ||
            errno != ECHILD) goto done;
        a.lost = 1;
        refused = !signal_owned_group(&a, deadline);
        if (!refused || a.group_signals != 0 || a.reaped) goto done;
    } else if (strcmp(mode, "group-isolation") == 0 ||
               strcmp(mode, "stale-after-reap") == 0) {
        failure = "spawn_canary";
        if (!spawn_owned(binary, root, dirfd, &b, deadline) ||
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
    close_owned(&watcher);
    close_owned(&sync[0]); close_owned(&sync[1]);
    close_owned(&result[0]); close_owned(&result[1]);
    close_owned(&dirfd);
    safe_owned_cleanup(&a);
    safe_owned_cleanup(&b);
    if (!success) return block(failure);
    if (strcmp(mode, "competing-reap") == 0 && a.reaped) return block("rogue_owner_reap");
    printf("C3_ID_RESULT mode=%s exit_observed=%d owner_reaped=%d "
           "group_signals=%d after_loss_signals=%d canary_alive=%d "
           "refused=%d reuse_proven=0\n",
           mode, exit_observed, a.reaped, a.group_signals,
           a.after_loss_signals, canary_alive, refused);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return block("usage");
    const char *mode = argv[1], *root = argv[2];
    int child = strcmp(mode, "__child") == 0;
    if (root[0] != '/') return block("non_private_root");
    int fd = -1;
    if (!private_root(root, argv[0], &fd)) return block("non_synthetic_root");
    close_owned(&fd);
    if (child) return synthetic_child();
    if (strcmp(mode, "exit-unreaped") != 0 &&
        strcmp(mode, "competing-reap") != 0 &&
        strcmp(mode, "group-isolation") != 0 &&
        strcmp(mode, "stale-after-reap") != 0) return block("unknown_mode");
    return owner_run(mode, root, argv[0]);
}
#endif
