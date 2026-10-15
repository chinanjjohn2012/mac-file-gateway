//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -lsandbox
#include <sandbox.h>
static int gateway_initialize_named_sandbox(void) {
    char *description = NULL;
    int result = sandbox_init(kSBXProfilePureComputation, SANDBOX_NAMED, &description);
    if (description != NULL) {
        sandbox_free_error(description);
    }
    return result;
}
*/
import "C"

import "errors"

func initializeSandbox() error {
    if C.gateway_initialize_named_sandbox() != 0 {
        return errors.New("sandbox_unavailable")
    }
    return nil
}
