# SDCP replay provenance

The original recording in upstream commit
`2d7c5277de08c6b29b3fac7447f17a516fbc4d1c` is for USB `1c7a:0582`.
Its SHA-256 is:

```text
2d10da4c3cd57d6220b8c4bc2f8e1e011f55779b9cf3bb14ec44d01bf3fbf48d
```

The current `custom.pcapng` is a **synthetic transformation** of that recording,
not a new physical-device capture. In each of its two identification exchanges,
the request's zero nonce is replaced with the public, deterministic emulation
nonce. The corresponding response MAC and packet checksums are recomputed.
Enrollment duplicate checks retain their original zero fields. Packet sizes,
the attestation, enrollment data, and other exchanges are unchanged.

The transformed recording has SHA-256:

```text
5de511b570ef3b3ab425d713e2e688e7a14e753bd8b9a71f2f897a61dca65ab8
```

Run `python3 tests/sdcp-refresh-fixture.py` from the source root to reproduce
this transformation. Python `cryptography` is required only for regeneration.
The script accepts either the original or transformed recording, validates
both captured attestation signatures and the original connect MAC, and
produces identical output on reruns. It reads the public emulation host keys
and nonces from `fpi-sdcp-device.c`; it contains no device/model private keys.
The TOD virtual driver retains its independently generated upstream fixtures.

`egismoc-sdcp-malformed.py` creates temporary mutations for invalid certificate
lengths, truncated connect/identify responses, a rejected enrollment commit,
and a response MAC belonging to the original zero nonce. Truncation updates
pcapng and USB lengths. Rejection tests also check that the device can close.
The retry cases duplicate the vendor init or Connect exchange so that a second
open can succeed after the first one fails. `delete-legacy` deletes an invalid
record and then a print in the pre-SDCP RAW format; it reuses the recorded
delete exchange, so the replay also checks that the right template ID is sent.
Tests run inside umockdev and never touch real enrollment storage.

The cancellation/suspend tests share this recording via symlinks. Their
operations stop while waiting for a finger, before a nonce-bearing identify
command is sent.

Hardware evidence is separate from this fixture. On 2026-09-20 the TOD-based
build passed attestation and two identification matches against existing
templates on `1c7a:05a1`, including close/reopen between matches. The template
list remained unchanged. The previous experimental-branch build also matched
twice on that device on 2026-09-19, with distinct nonce digests logged. Neither
result establishes nonzero-nonce compatibility for `1c7a:0582` or every other
Egis model.
