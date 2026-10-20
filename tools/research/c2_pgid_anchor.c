/* Phase 2 Lite C2: native synthetic group experiment ONLY, never product code. */
#if !defined(__APPLE__)
#include <stdio.h>
int main(void) { fputs("C2_NOT_RUN_NON_DARWIN\n", stderr); return 77; }
#else
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/event.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
typedef struct { pid_t pid; int reaped; int status; int group_signals; } Owner;

static long long monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static int block(const char *phase) {
    fprintf(stderr, "C2_BLOCK phase=%s\n", phase);
    return 70;
}
static void pause_ms(long millis) {
    struct timespec ts = { .tv_sec = millis / 1000, .tv_nsec = (millis % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

/* Standalone research helper owns its own SIGCHLD policy; never change Gateway's. */
static int configure_waitable_sigchld(void) {
    struct sigaction wanted, actual;
    memset(&wanted, 0, sizeof wanted);
    wanted.sa_handler = SIG_DFL;
    if (sigemptyset(&wanted.sa_mask) != 0) return -1;
    wanted.sa_flags = 0;
    if (sigaction(SIGCHLD, &wanted, NULL) != 0) return -1;
    if (sigaction(SIGCHLD, NULL, &actual) != 0) return -1;
    return (actual.sa_handler == SIG_DFL &&
            (actual.sa_flags & SA_NOCLDWAIT) == 0) ? 0 : -1;
}

static long remaining_ms(long long until);
static int inject_waitpid_eintr_once = 0;
static int inject_kevent_eintr_once = 0;
static int injected_waitpid_eintr_seen = 0;
static int injected_kevent_eintr_seen = 0;
/* Owned-child waitpid retries EINTR only while a bounded clock budget remains. */
static pid_t waitpid_with_eintr_retry(pid_t pid, int *status, int flags,
                                     long long deadline_at) {
    for (;;) {
        if (remaining_ms(deadline_at) <= 0) { errno = ETIMEDOUT; return -1; }
        pid_t result;
        if (inject_waitpid_eintr_once) {
            inject_waitpid_eintr_once = 0;
            injected_waitpid_eintr_seen = 1;
            errno = EINTR;
            result = -1;
        } else {
            result = waitpid(pid, status, flags);
        }
        if (result >= 0 || errno != EINTR) return result;
    }
}

/* The only owner of waitpid may reap this direct child. Never cache a PID as proof. */
static int owner_live(Owner *owner) {
    if (owner->reaped || owner->pid <= 0) return 0;
    int result = waitpid_with_eintr_retry(owner->pid, &owner->status, WNOHANG,
                                          monotonic_ms() + 750);
    if (result == owner->pid) { owner->reaped = 1; return 0; }
    if (result < 0) return 0;
    return getpgid(owner->pid) == owner->pid;
}

/* Group signal ONLY with a live, exclusively-owned leader; no numeric fallback. */
static int signal_owned_group(Owner *owner, pid_t expected, int signum,
                              long long deadline_at) {
    if (expected != owner->pid || !owner_live(owner)) return 0;
    /* Deliberately a user-space gate, not an atomic OS identity capability. */
    if (remaining_ms(deadline_at) <= 0) return -2;
    if (kill(-owner->pid, signum) != 0) return -1;
    owner->group_signals++;
    return 1;
}
static int bounded_reap(Owner *owner, long deadline_ms) {
    if (owner->pid <= 0) return -1;
    long long until = monotonic_ms() + deadline_ms;
    while (!owner->reaped && remaining_ms(until) > 0) {
        int result = waitpid_with_eintr_retry(owner->pid, &owner->status,
                                              WNOHANG, until);
        if (result == owner->pid) { owner->reaped = 1; break; }
        if (result < 0) return -1;
        pause_ms(20);
    }
    if (owner->reaped) return 0;
    /* Only a still-unreaped directly owned child may receive a PID fallback.
       Never signal a numeric PGID in a failure cleanup path. */
    long long retry_until = monotonic_ms() + 1000;
    int result = waitpid_with_eintr_retry(owner->pid, &owner->status,
                                          WNOHANG, retry_until);
    if (result == owner->pid) { owner->reaped = 1; return 0; }
    if (result != 0) return -1;
    if (kill(owner->pid, SIGKILL) != 0 && errno != ESRCH) return -1;
    while (remaining_ms(retry_until) > 0) {
        result = waitpid_with_eintr_retry(owner->pid, &owner->status,
                                         WNOHANG, retry_until);
        if (result == owner->pid) { owner->reaped = 1; break; }
        if (result < 0) return -1;
        pause_ms(20);
    }
    return -1; /* Forced direct-PID cleanup can never upgrade to success. */
}
static int read_ready(int fd, pid_t group, pid_t *descendant) {
    char line[160] = {0};
    size_t used = 0;
    long long until = monotonic_ms() + 3000;
    while (monotonic_ms() < until && used < sizeof(line) - 1) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
        int polled = poll(&pfd, 1, 100);
        if (polled < 0 && errno == EINTR) continue;
        if (polled <= 0) continue;
        char ch;
        ssize_t count = read(fd, &ch, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count != 1) return 0;
        line[used++] = ch;
        if (ch == '\n') break;
    }
    if (used == 0 || line[used - 1] != '\n') return 0;
    long descendant_id = 0, group_id = 0;
    int consumed = 0;
    if (sscanf(line, "C2_READY descendant=%ld group=%ld%n",
               &descendant_id, &group_id, &consumed) != 2) return 0;
    if (line[consumed] != '\n' || line[consumed + 1] != '\0') return 0;
    if (descendant_id <= 0 || descendant_id == group || group_id != group) return 0;
    *descendant = (pid_t)descendant_id;
    return getpgid(*descendant) == group;
}
/* NOTE_EXIT for a known synthetic descendant. This event is not a group identity handle. */
static long remaining_ms(long long until) {
    long long now = monotonic_ms();
    if (now < 0 || now >= until) return 0;
    long long left = until - now;
    return left > LONG_MAX ? LONG_MAX : (long)left;
}
/* Registration and NOTE_EXIT waits share an absolute bound across EINTR. */
static int kevent_with_eintr_retry(int fd, const struct kevent *changes, int nchanges,
                                  struct kevent *events, int nevents,
                                  long long deadline_at) {
    while (remaining_ms(deadline_at) > 0) {
        long left = remaining_ms(deadline_at);
        struct timespec timeout = {.tv_sec = left / 1000,
                                   .tv_nsec = (left % 1000) * 1000000L};
        int result;
        if (inject_kevent_eintr_once) {
            inject_kevent_eintr_once = 0;
            injected_kevent_eintr_seen = 1;
            errno = EINTR;
            result = -1;
        } else {
            result = kevent(fd, changes, nchanges, events, nevents,
                            nevents > 0 ? &timeout : NULL);
        }
        if (result < 0 && errno == EINTR) continue;
        return result;
    }
    errno = ETIMEDOUT;
    return -1;
}
static int register_descendant_exit(int *watcher, pid_t descendant) {
    if (descendant <= 0) return -1;
    int fd = kqueue();
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) { close(fd); return -1; }
    struct kevent change;
    EV_SET(&change, (uintptr_t)descendant, EVFILT_PROC,
           EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    if (kevent_with_eintr_retry(fd, &change, 1, NULL, 0,
                                 monotonic_ms() + 1000) != 0) {
        close(fd); return -1;
    }
    *watcher = fd;
    return 0;
}
/* 1=NOTE_EXIT, 0=no exit before deadline, -1=error; no status or group identity claim. */
static int wait_descendant_exit(int watcher, pid_t descendant, long budget_ms) {
    if (watcher < 0 || descendant <= 0 || budget_ms < 0) return -1;
    long long until = monotonic_ms() + budget_ms;
    do {
        struct kevent event;
        int count = kevent_with_eintr_retry(watcher, NULL, 0, &event, 1,
                                            until);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return -1;
        if (count == 0) return 0;
        if ((event.flags & EV_ERROR) != 0 ||
            event.filter != EVFILT_PROC || event.ident != (uintptr_t)descendant ||
            (event.fflags & NOTE_EXIT) == 0) return -1;
        return 1;
    } while (remaining_ms(until) > 0);
    return 0;
}
static int drain_to_eof(int fd, long timeout_ms) {
    char bytes[256];
    long long until = monotonic_ms() + timeout_ms;
    while (monotonic_ms() < until) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
        int polled = poll(&pfd, 1, 100);
        if (polled < 0 && errno == EINTR) continue;
        if (polled < 0) return 0;
        if (!polled) continue;
        ssize_t count = read(fd, bytes, sizeof(bytes));
        if (count == 0) return 1;
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return 0;
    }
    return 0;
}
/* Diagnostic FD accounting: never infer group/process ownership from a descriptor. */
static int close_owned_fd(int *fd, int *cleanup_fd_count) {
    if (*fd < 0) return 1;
    int original = *fd;
    *fd = -1;
    if (close(original) != 0) return 0;
    (*cleanup_fd_count)++;
    return 1;
}
static int cleanup_known_descendant(int watcher, pid_t descendant, long budget_ms) {
    if (descendant <= 0) return 1;
    if (watcher < 0) return 0; /* No independent witness, never claim complete cleanup. */
    return wait_descendant_exit(watcher, descendant, budget_ms) == 1;
}
static int synthetic_root(const char *root, int *directory, char *script, size_t capacity) {
    if (root[0] != '/') return 0;
    int dirfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) return 0;
    struct stat st;
    if (fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077) != 0) goto failed;
    int marker = openat(dirfd, "C2_TEST_MARKER", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (marker < 0) goto failed;
    char bytes[16] = {0};
    ssize_t size = read(marker, bytes, sizeof bytes);
    int valid = fstat(marker, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_nlink == 1 &&
        size == 9 && memcmp(bytes, "synthetic", 9) == 0;
    close(marker);
    if (!valid) goto failed;
    int scriptfd = openat(dirfd, "c2_group_child.py", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (scriptfd < 0) goto failed;
    valid = fstat(scriptfd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_nlink == 1;
    close(scriptfd);
    if (!valid) goto failed;
    int length = snprintf(script, capacity, "%s/c2_group_child.py", root);
    if (length < 0 || (size_t)length >= capacity) goto failed;
    *directory = dirfd;
    return 1;
failed:
    close(dirfd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) return block("usage");
    const char *mode = argv[1], *root = argv[2], *python = argv[3];
    if (strcmp(mode, "term") && strcmp(mode, "kill") &&
        strcmp(mode, "worker-first") && strcmp(mode, "leader-exit") &&
        strcmp(mode, "stale") && strcmp(mode, "close-stdout") &&
        strcmp(mode, "deadline-before-term") && strcmp(mode, "term-false-eof") &&
        strcmp(mode, "fault-register") && strcmp(mode, "fault-before-arm") &&
        strcmp(mode, "fault-after-arm") && strcmp(mode, "fault-waitpid-eintr") &&
        strcmp(mode, "fault-kevent-eintr")) return block("unknown_mode");
    if (python[0] != '/') return block("python_path");

    int dirfd = -1;
    char script[PATH_MAX];
    if (!synthetic_root(root, &dirfd, script, sizeof(script))) return block("non_synthetic_root");
    int gate[2] = {-1, -1}, output[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    int actions_ready = 0, attr_ready = 0, error = 0;
    Owner owner = {.pid = -1, .reaped = 0, .status = 0, .group_signals = 0};
    int exit_watcher = -1;
    pid_t descendant = -1;
    long long arm_deadline = -1;
    int armed = 0;
    int cleanup_fd_count = 0;
    int cleanup_fd_ok = 1;
    const char *failure = "setup";
    if (strcmp(mode, "fault-waitpid-eintr") == 0) inject_waitpid_eintr_once = 1;
    failure = "sigchld_policy";
    if (configure_waitable_sigchld() != 0) goto done;
    failure = "setup";
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) goto done;
    if (pipe(gate) != 0 || pipe(output) != 0) goto done;
    if ((error = posix_spawn_file_actions_init(&actions)) != 0) goto done;
    actions_ready = 1;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    error = posix_spawn_file_actions_addfchdir_np(&actions, dirfd);
#pragma clang diagnostic pop
    if (error != 0) goto done;
    if ((error = posix_spawn_file_actions_adddup2(&actions, gate[0], STDIN_FILENO)) != 0) goto done;
    if ((error = posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO)) != 0) goto done;
    if (gate[0] != STDIN_FILENO &&
        (error = posix_spawn_file_actions_addclose(&actions, gate[0])) != 0) goto done;
    if (output[1] != STDOUT_FILENO &&
        (error = posix_spawn_file_actions_addclose(&actions, output[1])) != 0) goto done;
    if ((error = posix_spawn_file_actions_addclose(&actions, gate[1])) != 0) goto done;
    if ((error = posix_spawn_file_actions_addclose(&actions, output[0])) != 0) goto done;
    if ((error = posix_spawnattr_init(&attr)) != 0) goto done;
    attr_ready = 1;
    if ((error = posix_spawnattr_setpgroup(&attr, 0)) != 0) goto done;
    if ((error = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP)) != 0) goto done;
    char *child_argv[] = {(char *)python, "-I", script, (char *)mode, NULL};
    error = posix_spawn(&owner.pid, python, &actions, &attr, child_argv, environ);
    if (error != 0) { owner.pid = -1; goto done; }
    posix_spawn_file_actions_destroy(&actions);
    actions_ready = 0;
    posix_spawnattr_destroy(&attr);
    attr_ready = 0;
    close(dirfd);
    dirfd = -1;
    close(gate[0]); gate[0] = -1;
    close(output[1]); output[1] = -1;

    failure = "creation_pgid";
    if (!owner_live(&owner)) goto done;
    failure = "release";
    if (write(gate[1], "R", 1) != 1) goto done;
    /* Keep stdin gate writable for the descendant arm barrier. */

    failure = "descendant_identity";
    if (!read_ready(output[0], owner.pid, &descendant)) goto done;
    failure = "descendant_exit_registration";
    if (strcmp(mode, "fault-register") == 0) { failure = "fault_register"; goto done; }
    if (register_descendant_exit(&exit_watcher, descendant) != 0) goto done;
    if (strcmp(mode, "fault-before-arm") == 0) {
        failure = "fault_before_arm";
        goto done;
    }
    /* The descendant cannot self-expire before this arm byte. */
    if (getpgid(descendant) != owner.pid) goto done;
    if (strcmp(mode, "fault-kevent-eintr") == 0) inject_kevent_eintr_once = 1;
    arm_deadline = monotonic_ms() +
        (strcmp(mode, "close-stdout") == 0 ? 7000 :
         (strcmp(mode, "leader-exit") == 0 || strcmp(mode, "stale") == 0) ? 4200 : 2500);
    failure = "descendant_arm";
    if (write(gate[1], "A", 1) != 1) goto done;
    armed = 1;
    close(gate[1]); gate[1] = -1;
    if (strcmp(mode, "fault-after-arm") == 0) {
        failure = "fault_after_arm";
        goto done;
    }
    int descendant_verified = 1, term_sent = 0, kill_sent = 0, refused = 0, held = 0;

    if (strcmp(mode, "leader-exit") == 0) {
        failure = "leader_exit_reap";
        if (bounded_reap(&owner, 2500) != 0 || !owner.reaped) goto done;
        failure = "leader_exit_descendant_still_alive";
        if (getpgid(descendant) != owner.pid) goto done;
        held = 0;
        failure = "leader_exit_refusal";
        refused = signal_owned_group(&owner, owner.pid, SIGTERM, arm_deadline) == 0;
        if (!refused) goto done;
    } else if (strcmp(mode, "close-stdout") == 0) {
        /* Adversarial control: leader dies, stdout EOF, but descendant ignores TERM. */
        failure = "close_stdout_anchor";
        if (!owner_live(&owner)) goto done;
        held = 1;
        failure = "close_stdout_term";
        if (signal_owned_group(&owner, owner.pid, SIGTERM, arm_deadline) != 1) goto done;
        term_sent = 1;
        failure = "close_stdout_eof";
        if (!drain_to_eof(output[0], 1000)) goto done;
        failure = "close_stdout_owner_reap";
        if (bounded_reap(&owner, 1200) != 0 || !owner.reaped ||
            !WIFSIGNALED(owner.status) || WTERMSIG(owner.status) != SIGTERM) goto done;
        failure = "close_stdout_early_exit";
        if (wait_descendant_exit(exit_watcher, descendant, 200) != 0) goto done;
        failure = "descendant_still_alive";
        if (getpgid(descendant) != owner.pid) goto done;
        failure = "negative_self_expiry_cleanup";
        if (wait_descendant_exit(exit_watcher, descendant,
                                 remaining_ms(arm_deadline)) != 1) goto done;
        /* This is a required BLOCK observation, never a positive termination. */
        fputs("C2_EXPECTED_BLOCK phase=descendant_still_alive stdout_eof=1 "
              "witness_before_eof=0 descendant_alive=1\n", stdout);
        close(exit_watcher); exit_watcher = -1;
        close(output[0]); output[0] = -1;
        return 0;
    } else if (strcmp(mode, "stale") == 0) {
        failure = "stale_anchor";
        if (!owner_live(&owner)) goto done;
        held = 1;
        refused = signal_owned_group(&owner, 0, SIGTERM, arm_deadline) == 0;
        if (!refused) goto done;
    } else {
        failure = "live_anchor";
        if (!owner_live(&owner)) goto done;
        held = 1;
        if (strcmp(mode, "deadline-before-term") == 0) pause_ms(3000);
        failure = "deadline_before_term";
        if (remaining_ms(arm_deadline) <= 0) goto done;
        failure = "term_signal";
        if (signal_owned_group(&owner, owner.pid, SIGTERM, arm_deadline) != 1) goto done;
        term_sent = 1;
        if (strcmp(mode, "kill") == 0) {
            pause_ms(350);
            failure = "deadline_before_kill";
            if (remaining_ms(arm_deadline) <= 0) goto done;
            failure = "kill_anchor_or_descendant";
            if (!owner_live(&owner) || getpgid(descendant) != owner.pid) goto done;
            if (signal_owned_group(&owner, owner.pid, SIGKILL, arm_deadline) != 1) goto done;
            kill_sent = 1;
        }
    }

    failure = "pipe_eof";
    long drain_budget_ms = refused ? 4000 : 2000;
    long left = remaining_ms(arm_deadline);
    if (left <= 0) goto done;
    if (drain_budget_ms > left) drain_budget_ms = left;
    if (!drain_to_eof(output[0], drain_budget_ms)) goto done;
    failure = "descendant_exit_witness";
#ifndef C2_TEST_OMIT_POSITIVE_WITNESS
    if (wait_descendant_exit(exit_watcher, descendant,
                             remaining_ms(arm_deadline)) != 1) goto done;
#endif
    failure = "owned_reap";
    left = remaining_ms(arm_deadline);
    if (left <= 0 || bounded_reap(&owner, left) != 0 || !owner.reaped) goto done;
    failure = "eintr_injection_not_observed";
    if ((strcmp(mode, "fault-waitpid-eintr") == 0 && !injected_waitpid_eintr_seen) ||
        (strcmp(mode, "fault-kevent-eintr") == 0 && !injected_kevent_eintr_seen)) goto done;
    failure = "owned_exit_status";
    if (term_sent && !kill_sent &&
        (!WIFSIGNALED(owner.status) || WTERMSIG(owner.status) != SIGTERM)) goto done;
    if (kill_sent &&
        (!WIFSIGNALED(owner.status) || WTERMSIG(owner.status) != SIGKILL)) goto done;
    if (!term_sent &&
        (!WIFEXITED(owner.status) || WEXITSTATUS(owner.status) != 0)) goto done;

    printf("C2_RESULT mode=%s term=%d kill=%d refused=%d held=%d reaped=1 drain=1 descendant_verified=%d\n",
           mode, term_sent, kill_sent, refused, held, descendant_verified);
    if (output[0] >= 0) close(output[0]);
    if (exit_watcher >= 0) close(exit_watcher);
    return 0;


done:
    /* Fault cleanup: acquire a witness while the known synthetic descendant
       still waits for stdin, if the first registration failed. Never manufacture
       proof of exit if this retry fails. */
    if (descendant > 0 && exit_watcher < 0 && !armed)
        (void)register_descendant_exit(&exit_watcher, descendant);
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    if (attr_ready) posix_spawnattr_destroy(&attr);
    if (!close_owned_fd(&gate[0], &cleanup_fd_count)) cleanup_fd_ok = 0;
    if (!close_owned_fd(&gate[1], &cleanup_fd_count)) cleanup_fd_ok = 0;
    if (!close_owned_fd(&output[0], &cleanup_fd_count)) cleanup_fd_ok = 0;
    if (!close_owned_fd(&output[1], &cleanup_fd_count)) cleanup_fd_ok = 0;
    if (!close_owned_fd(&dirfd, &cleanup_fd_count)) cleanup_fd_ok = 0;
    if (owner.pid > 0 && !owner.reaped) (void)bounded_reap(&owner, 600);
    /* An orphan is not waitpid-able. The previously registered NOTE_EXIT event
       observes only this known cooperative synthetic descendant. */
    int known_descendant_exit =
        cleanup_known_descendant(exit_watcher, descendant, 6500);
    if (!close_owned_fd(&exit_watcher, &cleanup_fd_count)) cleanup_fd_ok = 0;
    int owner_final_state = owner.pid <= 0 || owner.reaped;
    int cleanup_incomplete = !cleanup_fd_ok || !owner_final_state ||
                             !known_descendant_exit;
    if (!cleanup_incomplete && cleanup_fd_count > 0) {
        if (strcmp(mode, "deadline-before-term") == 0 &&
            strcmp(failure, "deadline_before_term") == 0 &&
            owner.group_signals == 0) {
            fputs("C2_EXPECTED_BLOCK phase=deadline_before_term "
                  "group_signals=0 owner_reaped=1 descendant_exit=1\n", stdout);
            return 0;
        }
        if (strcmp(mode, "term-false-eof") == 0 &&
            strcmp(failure, "descendant_exit_witness") == 0 &&
            owner.group_signals == 1) {
            fputs("C2_EXPECTED_BLOCK phase=descendant_exit_witness "
                  "group_signals=1 owner_reaped=1 descendant_exit=1\n", stdout);
            return 0;
        }
        const char *faults[] = {"fault-register", "fault-before-arm",
                                "fault-after-arm"};
        const char *labels[] = {"fault_register", "fault_before_arm",
                                "fault_after_arm"};
        for (size_t i = 0; i < sizeof faults / sizeof faults[0]; ++i) {
            if (strcmp(mode, faults[i]) == 0 &&
                strcmp(failure, labels[i]) == 0 &&
                owner.group_signals == 0) {
                printf("C2_EXPECTED_BLOCK phase=%s group_signals=0 "
                       "owner_reaped=1 descendant_exit=1\n", labels[i]);
                return 0;
            }
        }
    }
    if (cleanup_incomplete) return block("cleanup_incomplete");
    return block(failure);
}
#endif
