/* Isolated C1 cwd/pgid primitive experiment. NEVER link into Gateway. */
#if !defined(__APPLE__)
#include <stdio.h>
int main(void) {
    fputs("C1_NOT_RUN_NON_DARWIN\n", stderr);
    return 77;
}
#else
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int block(const char *phase, int error) {
    fprintf(stderr, "C1_BLOCK phase=%s errno=%d\n", phase, error);
    return 70;
}

/* The unreaped child PID remains owned; never address an external group. */
static int reap_owned(pid_t pid, int *status) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 50000000L};
    for (int i = 0; i < 240; i++) {
        pid_t waited = waitpid(pid, status, WNOHANG);
        if (waited == pid) return 0;
        if (waited < 0) {
            if (errno == EINTR) continue;
            return block("waitpid", errno);
        }
        (void)nanosleep(&pause, NULL);
    }
    /* No PID reuse is possible until this single parent actually reaps pid. */
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH)
        return block("owned_child_kill", errno);
    pid_t waited;
    do { waited = waitpid(pid, status, 0); } while (waited < 0 && errno == EINTR);
    return block("child_deadline", ETIMEDOUT);
}

int main(int argc, char **argv) {
    if (argc < 4 || (strcmp(argv[1], "--normal") != 0 && strcmp(argv[1], "--race") != 0)
            || argv[2][0] != '/' || argv[3][0] != '/') {
        return block("usage", EINVAL);
    }
    int dirfd = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) return block("open_cwd", errno);
    struct stat before;
    if (fstat(dirfd, &before) != 0 || !S_ISDIR(before.st_mode)) {
        int error = errno;
        close(dirfd);
        return block("fstat_cwd", error ? error : ENOTDIR);
    }
    /* Hard-stop before any rename/spawn unless this is our fake test tree. */
    int marker_fd = openat(dirfd, "C1_TEST_MARKER", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (marker_fd < 0) {
        int error = errno;
        close(dirfd);
        return block("missing_synthetic_marker", error);
    }
    struct stat marker_stat;
    char marker_data[16] = {0};
    ssize_t marker_size = read(marker_fd, marker_data, sizeof marker_data);
    int marker_valid = fstat(marker_fd, &marker_stat) == 0
        && S_ISREG(marker_stat.st_mode) && marker_stat.st_uid == geteuid()
        && marker_stat.st_nlink == 1 && marker_size == 9
        && memcmp(marker_data, "synthetic", 9) == 0;
    close(marker_fd);
    if (!marker_valid || before.st_uid != geteuid()) {
        close(dirfd);
        return block("bad_synthetic_marker", EPERM);
    }
    if (strcmp(argv[1], "--race") == 0) {
        char held[PATH_MAX];
        int length = snprintf(held, sizeof held, "%s.held", argv[2]);
        if (length < 0 || (size_t)length >= sizeof held) {
            close(dirfd);
            return block("rename_length", ENAMETOOLONG);
        }
        if (rename(argv[2], held) != 0) {
            int error = errno;
            close(dirfd);
            return block("rename_cwd", error);
        }
        if (mkdir(argv[2], 0700) != 0) {
            int error = errno;
            close(dirfd);
            return block("replace_cwd", error);
        }
    }

    /* A failed pipe write must not SIGPIPE-kill the owner before reap. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        close(dirfd);
        return block("ignore_sigpipe", errno);
    }
    int gate[2] = {-1, -1};
    if (pipe(gate) != 0) {
        int error = errno;
        close(dirfd);
        return block("pipe", error);
    }
    /* The child reads exactly one byte on stdin as a spawn/PGID barrier. */
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    int actions_ready = 0, attr_ready = 0, code = 0;
    pid_t pid = -1;
    if ((code = posix_spawn_file_actions_init(&actions)) != 0) goto setup_fail;
    actions_ready = 1;
    /* This Darwin API avoids pathname cwd re-resolution after rename. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    code = posix_spawn_file_actions_addfchdir_np(&actions, dirfd);
#pragma clang diagnostic pop
    if (code != 0) goto setup_fail;
    if ((code = posix_spawn_file_actions_adddup2(&actions, gate[0], STDIN_FILENO)) != 0) goto setup_fail;
    if ((code = posix_spawn_file_actions_addclose(&actions, gate[0])) != 0) goto setup_fail;
    if ((code = posix_spawn_file_actions_addclose(&actions, gate[1])) != 0) goto setup_fail;
    if ((code = posix_spawnattr_init(&attr)) != 0) goto setup_fail;
    attr_ready = 1;
    if ((code = posix_spawnattr_setpgroup(&attr, 0)) != 0) goto setup_fail;
    if ((code = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP)) != 0) goto setup_fail;
    /* One kernel spawn per case. No fallback, no global chdir, no preexec. */
    code = posix_spawn(&pid, argv[3], &actions, &attr, &argv[3], environ);
    if (code != 0) goto setup_fail;

    close(gate[0]);
    gate[0] = -1;
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    if (attr_ready) posix_spawnattr_destroy(&attr);
    close(dirfd);
    dirfd = -1;

    /* No group signal is sent: this is not a safe-reap/PGID-reuse proof. */
    pid_t pgid = getpgid(pid);
    if (pgid != pid) {
        close(gate[1]);
        gate[1] = -1;
        int ignored = 0;
        int group_error = pgid < 0 ? errno : EINVAL;
        (void)reap_owned(pid, &ignored);
        return block("pgid_identity", group_error);
    }
    fprintf(stderr, "C1_ANCHOR pid=%ld pgid=%ld dir_dev=%llu dir_ino=%llu\n",
            (long)pid, (long)pgid,
            (unsigned long long)before.st_dev,
            (unsigned long long)before.st_ino);
    if (write(gate[1], "R", 1) != 1) {
        int error = errno;
        close(gate[1]);
        int ignored = 0;
        (void)reap_owned(pid, &ignored);
        return block("handshake", error);
    }
    close(gate[1]);
    int status = 0;
    int reap_result = reap_owned(pid, &status);
    if (reap_result != 0) return reap_result;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return block("child_exit", ECHILD);
    fputs("C1_REAP_OK\n", stderr);
    return 0;

setup_fail:
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    if (attr_ready) posix_spawnattr_destroy(&attr);
    if (gate[0] >= 0) close(gate[0]);
    if (gate[1] >= 0) close(gate[1]);
    if (dirfd >= 0) close(dirfd);
    return block("spawn_setup", code);
}
#endif
