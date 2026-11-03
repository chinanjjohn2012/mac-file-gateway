/*
 * macOS 15 ARM64 Seatbelt OFFLINE_ONLY canary-only backend candidate.
 *
 * T0 SOURCE ONLY: this file is never compiled or executed by the existing
 * Linux CI. There is intentionally NO execve/posix_spawn/Popen of Go or
 * Pipenv here, and no callback/argv capability to start any foreign tool.
 * Before a future non-destructive macOS canary run, an exact Head and B/C
 * review must qualify the current hosted runner, compiler and binary.
 *
 * Uses deprecated sandbox_init; success on one macOS version is not proof
 * of another. No host-wide firewall, pf, VM or root operations.
 */
#define _POSIX_C_SOURCE 200809L
#if !defined(__APPLE__)
#error "macOS Seatbelt canary may only be compiled on a reviewed macOS host"
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <sandbox.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lbe_m2_fd_scrub_t0.h"
#include "lbe_m2_canary_bounded_wait_t0.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Only exact, compile-time policy text. Default deny: no network-outbound,
 * network-inbound, network-bind, Mach network/proxy extension or per-target
 * allow. Read-only resource access + process fork are for the limited
 * same-profile canary, NOT a usable Go/Pipenv execution sandbox.
 *
 * A future Go/Pipenv profile must be separately designed, fixed and tested:
 * this current one has NO process-exec grant and cannot run toolchains.
 */
static const char kSeatbeltPolicy[] =
    "(version 1)\n"
    "(deny default)\n"
    "(allow file-read*)\n"
    "(allow process-fork)\n"
    "(allow sysctl-read)\n";

static bool permission_denied(int error_value) {
    return error_value == EPERM || error_value == EACCES;
}

static bool socket_denied(sa_family_t family, int type,
                          const struct sockaddr *address, socklen_t length) {
    int fd = socket((int)family, type, 0);
    if (fd == -1) {
        return permission_denied(errno);
    }
    /*
     * MUST avoid any packet reaching a remote site even on a broken
     * policy: all selected canary targets are loopback only. Never
     * use DNS/resolver, fetch, arbitrary host, proxy or user address.
     */
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        (void)close(fd);
        return false;
    }
    int result;
    int saved_errno;
    if (type == SOCK_DGRAM) {
        const char byte = 0;
        result = (int)sendto(fd, &byte, sizeof(byte), 0, address, length);
        saved_errno = errno;
    } else {
        result = connect(fd, address, length);
        saved_errno = errno;
    }
    (void)close(fd);
    return result == -1 && permission_denied(saved_errno);
}

static bool deny_loopback_canaries(void) {
    struct sockaddr_in v4;
    memset(&v4, 0, sizeof(v4));
    v4.sin_len = (uint8_t)sizeof(v4);
    v4.sin_family = AF_INET;
    v4.sin_port = htons(9);
    v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct sockaddr_in6 v6;
    memset(&v6, 0, sizeof(v6));
    v6.sin6_len = (uint8_t)sizeof(v6);
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons(9);
    v6.sin6_addr = in6addr_loopback;
    return socket_denied(AF_INET, SOCK_STREAM,
                         (const struct sockaddr *)&v4, sizeof(v4))
        && socket_denied(AF_INET, SOCK_DGRAM,
                         (const struct sockaddr *)&v4, sizeof(v4))
        && socket_denied(AF_INET6, SOCK_STREAM,
                         (const struct sockaddr *)&v6, sizeof(v6))
        && socket_denied(AF_INET6, SOCK_DGRAM,
                         (const struct sockaddr *)&v6, sizeof(v6));
}

static bool reject_inherited_socket_descriptors(void) {
    /*
     * r002 P2-110-01 / C110-R001-SPEC-01: enumerate ACTUAL open FDs
     * through /dev/fd, never assume fd < current RLIMIT_NOFILE soft/hard
     * limit. The isolated, single-thread canary must reject incomplete
     * enumeration or any FD remaining >=3 before Seatbelt attachment.
     */
    return lbe_scrub_inherited_fds();
}

int main(int argc, char **argv) {
    /* No user-defined command, exec path, profile or network target. */
    (void)argv;
    if (argc != 1) {
        return 64;
    }
    if (!reject_inherited_socket_descriptors()) {
        return 65;
    }
    char *errorbuf = NULL;
    int applied = sandbox_init(kSeatbeltPolicy, 0, &errorbuf);
    if (errorbuf != NULL) {
        sandbox_free_error(errorbuf);
        errorbuf = NULL;
    }
    if (applied != 0) {
        return 66;
    }
    /* The original canary runs in its own now-sandboxed process context. */
    if (!deny_loopback_canaries()) {
        return 67;
    }
    /*
     * A forked canary is required to confirm inherited kernel restrictions
     * in a natural-exit descendant. This is a first-party safe probe only:
     * it CANNOT attest an eventual foreign Go/Pipenv child or exec lineage.
     */
    pid_t child = fork();
    if (child < 0) {
        return 68;
    }
    if (child == 0) {
        _exit(deny_loopback_canaries() ? 0 : 1);
    }
    /*
     * FINITE wait using WNOHANG + CLOCK_MONOTONIC (2s proposed maximum).
     * A timeout/unknown CHILD IS NOT RETIRED: no kill, no retry, no
     * admission. A future native-run supervisor must prove safe ownership
     * of a possibly live child before this canary is ever run on macOS.
     * This is a source-only T0 proposal, not a cleanup guarantee.
     */
    if (lbe_canary_wait_bounded(child) != LBE_CANARY_CHILD_EXIT_0) {
        return 69;
    }
    /*
     * Even a successful probe is only a LIMITED OS canary observation.
     * It cannot open the separate T1 native executor and does not prove
     * resolver/AF_UNIX proxy coverage, real Go/Pipenv or resource budgets.
     */
    static const char receipt[] =
        "SEATBELT_CANARY_ONLY_NATIVE_GO_PIPENV_NOT_RUN\n";
    if (write(STDOUT_FILENO, receipt, sizeof(receipt) - 1) !=
        (ssize_t)(sizeof(receipt) - 1)) {
        return 70;
    }
    return 0;
}
