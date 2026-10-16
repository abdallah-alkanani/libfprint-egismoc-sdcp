# Egis SDCP implementation

This driver adapts Joshua Grisham's Egis SDCP conversion from libfprint
[MR !547](https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/547)
to the shared SDCP API in libfprint-TOD `v1.95.2+tod1`, commit
`461d57c64cabea5320438388a16aa4b41a9a90cc`. The conversion source was
`feature/sdcp-v2`, commit `2d7c5277de08c6b29b3fac7447f17a516fbc4d1c`.
Existing LGPL notices and author attribution are retained.

The shared implementation supplies ECDH, key derivation, certificate-chain
validation, model/device signature verification, and authenticated identity
checking. Egis-specific code transports and parses the messages. See the
[Microsoft specification](https://github.com/microsoft/SecureDeviceConnectionProtocol/wiki/Secure-Device-Connection-Protocol)
for the cryptographic protocol. No proprietary driver module is required;
the native build uses `-Dtod=false`.

## Device message mapping

Offsets below include the Egis frame header; integers describing certificate
length are big-endian. Responses must be bounds-checked before extracting fields.

| Response | Layout |
| --- | --- |
| Connect | 15-byte prefix, 32-byte device random, 2-byte certificate length, certificate, 65-byte device public key, 65-byte firmware public key, 32-byte firmware hash, 64-byte model signature, 64-byte device signature, 32-byte MAC, 2-byte status |
| Identify match | 14-byte prefix, 32-byte MAC, 32-byte enrollment ID, 2-byte status |
| Enrollment nonce | 14-byte prefix, 32-byte device nonce, 2-byte status |

The Connect certificate length must account for the entire response after
subtracting its 373 bytes of fixed fields. Egis returns MAC before enrollment
ID, reversing SDCP's conceptual `(id, MAC)` order.

For identify and verify, the shared base class generates a new cryptographic
nonce. The driver writes it at bytes 21 through 52 of the check command, and
the shared base class validates the returned identity MAC against that nonce.
There is no fallback to a zero nonce or acceptance after a MAC failure.
Enrollment duplicate checks retain the vendor protocol's zero field; they are
not reported to callers as authenticated identification results.

## Trust and lifetime rules

- Certificate-chain and both attestation signatures are checked. The leaf must
  explicitly contain biometric EKU `1.3.6.1.4.1.311.76.43.1`, observed in both
  available real Microsoft-issued model certificates. CA certificates cannot
  serve as leaves, and EKU restrictions in the verified chain are enforced.
  Missing, unrelated, or generic any-purpose leaf EKUs are rejected. This
  conservative policy needs confirmation on additional Egis models. Derived keys
  are never written to production debug logs.
- Egis explicitly selects `CERTIFICATE_NO_CHECK_TIME` because existing devices
  retain expired factory certificates. This skips validity dates, including
  those in the chain; it does not skip chain signatures or attestation checks.
- Certificate/model/device revocation and a trusted firmware denylist are not
  implemented. A signed firmware hash alone is not proof that the firmware is
  free of known vulnerabilities.
- The Linux host holds the session secret. This driver does not implement the
  hardware-isolated Windows Hello/ESS trust model or protect against a
  compromised privileged host.
- The task state machine owns per-operation allocations. Error ownership is
  transferred once; a failed command must drain the task before completing the
  libfprint action. Enrollment aborts reset the sensor before completion.
- Suspend returns `FP_DEVICE_ERROR_NOT_SUPPORTED`, allowing libfprint to cancel
  and drain the operation. It does not pretend that a capture survives suspend.

## Validation and compatibility

The replay includes enrollment, list/delete, identify, verify, and no-match
behavior. Additional tests cover cancellation, suspend, malformed responses,
replayed identity MACs, rejected enrollment commits, and failed-open/enrollment
recovery in the shared virtual driver. See `tests/egismoc/README.md` for the
recording's provenance and regeneration instructions.

On 2026-09-20 this TOD-based port passed attestation and two identification
matches against existing templates on `1c7a:05a1`, with a successful close and
reopen between matches. The device's two-template list remained unchanged.
This does not validate other Egis models. Old non-SDCP recordings are disabled
explicitly.

The released core preserves the experimental driver's FP3 SDCP on-disk format:
a nested variant containing a single 32-byte enrollment ID. Both libraries
read and reserialized the two existing fprintd records byte-for-byte on
2026-09-20, so those records require no migration. Regression tests preserve
valid records and reject malformed structures, invalid metadata, and missing
or wrong-length SDCP IDs. Fresh enrollment, PAM integration, and system
suspend/resume still require separate validation before installation.
