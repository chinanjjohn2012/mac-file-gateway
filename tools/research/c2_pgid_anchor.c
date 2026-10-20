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
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
typedef struct { pid_t pid; int reaped; int status; } Owner;

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

/* The only owner of waitpid may reap this direct child. Never cache a PID as proof. */
static int owner_live(Owner *owner) {
    if (owner->reaped || owner->pid <= 0) return 0;
    int result = waitpid(owner->pid, &owner->status, WNOHANG);
    if (result == owner->pid) { owner->reaped = 1; return 0; }
    if (result < 0) return 0;
    return getpgid(owner->pid) == owner->pid;
}

/* Group signal ONLY with a live, exclusively-owned leader; no numeric fallback. */
static int signal_owned_group(Owner *owner, pid_t expected, int signum) {
    if (expected != owner->pid || !owner_live(owner)) return 0;
    if (kill(-owner->pid, signum) != 0) return -1;
    return 1;
}
static int bounded_reap(Owner *owner, long deadline_ms) {
    long long until = monotonic_ms() + deadline_ms;
    while (!owner->reaped && monotonic_ms() < until) {
        int result = waitpid(owner->pid, &owner->status, WNOHANG);
        if (result == owner->pid) { owner->reaped = 1; break; }
        if (result < 0) return -1;
        pause_ms(20);
    }
    if (owner->reaped) return 0;
    /* Only the still-unreaped direct child PID is eligible for fallback signal. */
    int result = waitpid(owner->pid, &owner->status, WNOHANG);
    if (result == owner->pid) { owner->reaped = 1; return 0; }
    if (result != 0) return -1;
    if (kill(owner->pid, SIGKILL) != 0 && errno != ESRCH) return -1;
    do { result = waitpid(owner->pid, &owner->status, 0); }
    while (result < 0 && errno == EINTR);
    if (result == owner->pid) owner->reaped = 1;
    return -1; /* Requiring fallback always BLOCKS experiment. */
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
        strcmp(mode, "stale")) return block("unknown_mode");
    if (python[0] != '/') return block("python_path");

    int dirfd = -1;
    char script[PATH_MAX];
    if (!synthetic_root(root, &dirfd, script, sizeof(script))) return block("non_synthetic_root");
    int gate[2] = {-1, -1}, output[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    int actions_ready = 0, attr_ready = 0, error = 0;
    Owner owner = {.pid = -1, .reaped = 0, .status = 0};
    const char *failure = "setup";
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
    close(gate[1]); gate[1] = -1;

    pid_t descendant = -1;
    failure = "descendant_identity";
    if (!read_ready(output[0], owner.pid, &descendant)) goto done;
    int descendant_verified = 1, term_sent = 0, kill_sent = 0, refused = 0, held = 0;

    if (strcmp(mode, "leader-exit") == 0) {
        failure = "leader_exit_reap";
        if (bounded_reap(&owner, 2500) != 0 || !owner.reaped) goto done;
        failure = "leader_exit_descendant_still_alive";
        if (getpgid(descendant) != owner.pid) goto done;
        held = 0;
        failure = "leader_exit_refusal";
        refused = signal_owned_group(&owner, owner.pid, SIGTERM) == 0;
        if (!refused) goto done;
    } else if (strcmp(mode, "stale") == 0) {
        failure = "stale_anchor";
        if (!owner_live(&owner)) goto done;
        held = 1;
        refused = signal_owned_group(&owner, 0, SIGTERM) == 0;
        if (!refused) goto done;
    } else {
        failure = "live_anchor";
        if (!owner_live(&owner)) goto done;
        held = 1;
        failure = "term_signal";
        if (signal_owned_group(&owner, owner.pid, SIGTERM) != 1) goto done;
        term_sent = 1;
        if (strcmp(mode, "kill") == 0) {
            pause_ms(350);
            failure = "kill_anchor_or_descendant";
            if (!owner_live(&owner) || getpgid(descendant) != owner.pid) goto done;
            if (signal_owned_group(&owner, owner.pid, SIGKILL) != 1) goto done;
            kill_sent = 1;
        }
    }

    failure = "pipe_eof";
    long drain_budget_ms = refused ? 4000 : 2000;
    if (!drain_to_eof(output[0], drain_budget_ms)) goto done;
    failure = "owned_reap";
    if (bounded_reap(&owner, 2000) != 0 || !owner.reaped) goto done;
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
    return 0;

done:
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    if (attr_ready) posix_spawnattr_destroy(&attr);
    if (gate[0] >= 0) close(gate[0]);
    if (gate[1] >= 0) close(gate[1]);
    if (output[0] >= 0) close(output[0]);
    if (output[1] >= 0) close(output[1]);
    if (dirfd >= 0) close(dirfd);
    if (owner.pid > 0 && !owner.reaped) (void)bounded_reap(&owner, 2500);
    return block(failure);
}
#endif
