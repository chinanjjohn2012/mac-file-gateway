/*
 * Seatbelt canary-only pre-sandbox FD scrub: no network, process or policy.
 * The very same source is included by the future macOS Seatbelt C canary.
 *
 * NEVER bound enumeration by RLIMIT_NOFILE, getdtablesize, or _SC_OPEN_MAX:
 * a high inherited descriptor can survive lowering the soft/hard cap.
 * Darwin /dev/fd and Linux /proc/self/fd enumerate actually open FDs.
 * Failure to enumerate, close, re-enumerate or verify = deny before sandbox.
 *
 * The _with variant supplies fault injection for safe T0 only. Production
 * calls the fixed filesystem path and libc close with no untrusted input.
 * Native Darwin behavior is NOT verified by Linux T0.
 */
#ifndef LBE_M2_FD_SCRUB_T0_H
#define LBE_M2_FD_SCRUB_T0_H

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#define LBE_FD_DIRECTORY "/dev/fd"
#elif defined(__linux__)
#define LBE_FD_DIRECTORY "/proc/self/fd"
#else
#error "unsupported FD enumeration platform"
#endif

/* Cap metadata scan work, NOT the numeric FD range. Overflow denies. */
#define LBE_FD_MAX_ENTRIES 131072U

static bool lbe_parse_fd_number(const char *name, int *fd) {
    if (name == NULL || fd == NULL || name[0] == '\0') {
        return false;
    }
    unsigned int value = 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
        const unsigned int digit = (unsigned int)(*p - '0');
        if (value > ((unsigned int)INT_MAX - digit) / 10U) {
            return false;
        }
        value = value * 10U + digit;
    }
    *fd = (int)value;
    return true;
}

static bool lbe_verify_no_remaining_fds(const char *directory) {
    DIR *listing = opendir(directory);
    if (listing == NULL) {
        return false;
    }
    const int self = dirfd(listing);
    bool okay = self >= 3;
    unsigned int scanned = 0;
    while (okay) {
        errno = 0;
        struct dirent *entry = readdir(listing);
        if (entry == NULL) {
            if (errno != 0) {
                okay = false;
            }
            break;
        }
        if (++scanned > LBE_FD_MAX_ENTRIES) {
            okay = false;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        int fd = -1;
        if (!lbe_parse_fd_number(entry->d_name, &fd)) {
            okay = false;
            break;
        }
        if (fd >= 3 && fd != self) {
            okay = false;
            break;
        }
    }
    if (closedir(listing) != 0) {
        okay = false;
    }
    return okay;
}

static bool lbe_scrub_inherited_fds_with(
    const char *directory, int (*closer)(int)
) {
    if (directory == NULL || closer == NULL) {
        return false;
    }
    /* Socket stdio can act as a preopened unsandboxed network relay. */
    for (int fd = 0; fd <= 2; fd++) {
        struct stat st;
        if (fstat(fd, &st) != 0 || S_ISSOCK(st.st_mode)) {
            return false;
        }
    }
    DIR *listing = opendir(directory);
    if (listing == NULL) {
        return false;
    }
    const int self = dirfd(listing);
    bool okay = self >= 3;
    unsigned int scanned = 0;
    while (okay) {
        errno = 0;
        struct dirent *entry = readdir(listing);
        if (entry == NULL) {
            if (errno != 0) {
                okay = false;
            }
            break;
        }
        if (++scanned > LBE_FD_MAX_ENTRIES) {
            okay = false;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        int fd = -1;
        if (!lbe_parse_fd_number(entry->d_name, &fd)) {
            okay = false;
            break;
        }
        if (fd >= 3 && fd != self) {
            if (closer(fd) != 0 && errno != EBADF) {
                okay = false;
                break;
            }
        }
    }
    if (closedir(listing) != 0) {
        okay = false;
    }
    if (!okay) {
        return false;
    }
    /* Independent second enumeration proves no high FD survived. */
    return lbe_verify_no_remaining_fds(directory);
}

static bool lbe_scrub_inherited_fds(void) {
    return lbe_scrub_inherited_fds_with(LBE_FD_DIRECTORY, close);
}

#endif /* LBE_M2_FD_SCRUB_T0_H */
