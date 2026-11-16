# R006 fixed macOS selected-source allowlist candidate

Source values are fixed from prior original GitHub-hosted macOS T0
Run 42449482213 / Job 128635422796:

- macos-15 ARM64, ImageVersion `20261104.0514.1`
- locally observed macOS `15.8.2`, ProductBuildVersion `24H232`
- SystemVersion.plist SHA256 `7789975d8ee10cd0a331a22c8fded5232cdc3c4462fad0561a604cad5bb0d07e`
- /usr/bin/env SHA256 `ebda86b855682a1910382f8d03578f8df114c83277893d86082240b7e7345ed0`
- /usr/lib/dyld SHA256 `02a4b237c9a87ea11ff4eeaac7bee360bd8cc94b07ea2e697cf88d5bd85610f9`

A new run must re-read these fixed bytes with the nofollow, ancestor-pinned
probe. It may not learn a digest and accept it in the same execution.

This remains a finite source subset and A-development candidate, not full
boot-image attestation, complete actual loaded graph, B/C code PASS, owner
exact-run authorization, or native PRODUCT_T1 permission.
