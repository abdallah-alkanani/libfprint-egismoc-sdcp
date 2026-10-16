# libfprint SDCP support for Egis Match-on-Chip readers

This is an unofficial libfprint build for Egis Technology (LighTuning)
Match-on-Chip fingerprint readers, such as the ETU905A80-E (`1c7a:05a1`) in
Samsung Galaxy Book laptops. These Windows Hello readers expect the host to use
Microsoft's [Secure Device Connection Protocol][sdcp] (SDCP). Released
libfprint has no SDCP support; with its `egismoc` driver, `1c7a:05a1` users
report that enrolled prints are not kept ([#850], [#889]).

The branch `egismoc-sdcp` is [libfprint-TOD v1.95.2+tod1][tod] plus a short
series of commits. They port Joshua Grisham's Egis SDCP driver from libfprint
[MR !547][mr547] onto the released shared SDCP core, and fix the problems
found while reviewing both. Each commit message explains its change and
evidence; [`SDCP.md`](../libfprint/drivers/egismoc/SDCP.md) describes the
driver's protocol mapping and trust rules.

## Status

| | |
| --- | --- |
| Tested with this branch | `1c7a:05a1`; `1c7a:0584` by fusuma |
| Daily use | 597 fingerprint logins through `pam_fprintd` (GDM, polkit, sudo) from 2026-09-21 to 2026-10-16 with the build of the first five commits, including suspend during identify |
| This branch on hardware | Enroll, duplicate rejection, verify, wrong-finger no-match, delete, verify after a cancelled verify, and repeated reopen, all through fprintd on 2026-10-16 |
| Automated tests | 73 native and 114 TOD-enabled test jobs; unit suites and 21 USB replays also under ASan and UBSan |
| Not yet tested on hardware | Hibernation and the other readers below; failed opens and deleting pre-SDCP records are covered by replays only |

## Readers

| USB ID | Found in | Status |
| --- | --- | --- |
| `1c7a:05a1` | Samsung Galaxy Book (ETU905A80-E) | Tested with this branch |
| `1c7a:0584` | Acer Swift SF16-51 (ETU905A88-E) | Enroll, verify, delete and PAM tested with this branch by [fusuma][fusuma] |
| `1c7a:05aa` | HONOR MagicBook Pro 14 2025 (ET171) | Enroll, verify, PAM and suspend tested by [Philip Walsh][honor] with his MR !547 build; his patch is included |
| `1c7a:05b1` | Fujitsu (ETU906Axx-E) | Open, enroll and verify reported in [MR !671][mr671] with the MR !547 driver |
| `1c7a:05a5` | Samsung Galaxy Book4/Book5 | Reported working with MR !547 builds by [Roman2K][roman2k]; his longer finger wait is included |
| `1c7a:0582`, `0583`, `0586`, `0587`, `0588` | Various | Listed by MR !547; not tested with this branch |

Find your reader's ID with `lsusb | grep 1c7a`. Reports from any of these
models are welcome, working or not.

## Build

Install the build dependencies of your distribution's libfprint:

```sh
sudo dnf install meson ninja-build gcc && sudo dnf builddep libfprint  # Fedora
sudo apt install meson ninja-build build-essential && sudo apt build-dep libfprint  # Debian, Ubuntu (deb-src enabled)
```

Then build only this driver:

```sh
git clone https://github.com/abdallah-alkanani/libfprint-egismoc-sdcp.git
cd libfprint-egismoc-sdcp
meson setup build -Ddrivers=egismoc -Dtod=false -Ddoc=false \
  -Dgtk-examples=false -Dintrospection=false -Dinstalled-tests=false
meson compile -C build
```

To run the tests, which need umockdev and PyGObject, configure a second build
with introspection and the virtual SDCP test driver:

```sh
meson setup build-test -Ddrivers=egismoc,virtual_sdcp -Dtod=false \
  -Ddoc=false -Dgtk-examples=false -Dinstalled-tests=false
meson test -C build-test --suite unit-tests --suite drivers --suite virtual-sdcp
```

## Install for fprintd only

Only fprintd talks to the reader; the PAM module and desktop settings use
fprintd over D-Bus. Point fprintd at the new library and leave the
distribution's libfprint in place:

```sh
sudo install -Dm755 build/libfprint/libfprint-2.so.2.0.0 \
  /usr/local/lib/libfprint-egismoc-sdcp/libfprint-2.so.2
sudo mkdir -p /etc/systemd/system/fprintd.service.d
printf '[Service]\nEnvironment=LD_LIBRARY_PATH=/usr/local/lib/libfprint-egismoc-sdcp\n' |
  sudo tee /etc/systemd/system/fprintd.service.d/egismoc-sdcp.conf
sudo systemctl daemon-reload
sudo systemctl restart fprintd
```

The directory gets the standard `lib_t` SELinux label on Fedora. fprintd
starts on demand and exits after about 30 idle seconds, so check that it
loaded the library right after using it:

```sh
fprintd-list "$USER"
sudo grep libfprint /proc/$(pidof fprintd)/maps
```

### Existing enrollments

Fingers enrolled with your distribution's driver are stored in a format SDCP
identification cannot match. Remove them and enroll again, in your desktop's
fingerprint settings or with:

```sh
fprintd-delete "$USER"
fprintd-enroll
```

The reader has one template store. On a dual-boot machine, fprintd can delete
Windows Hello templates it does not know about: when enrollment starts and
the finger matches one, or when the reader is full.

### If a wrong finger matches

The reader, not the host, decides whether a finger matches. An enrollment
with sloppy or interrupted touches can give a weak template that accepts
other fingers. Delete that finger and enroll it again in one go, touching
with the same finger each time. The reader stops waiting after 30 to 60
seconds without a touch, which ends the enrollment.

### Roll back

```sh
sudo rm /etc/systemd/system/fprintd.service.d/egismoc-sdcp.conf
sudo systemctl daemon-reload
sudo systemctl restart fprintd
```

Fingers enrolled with this build must then be enrolled again.

## Security notes

- The reader's model certificate must chain to the Microsoft certificates in
  `libfprint/sdcp/ca-store/` and carry the Windows Hello biometric key usage. Both
  attestation signatures and every identity MAC are checked, with a fresh
  random nonce for each identification.
- Certificate expiry dates are ignored, because these readers ship with
  expired factory certificates. There is no certificate revocation or
  firmware denylist.
- The Linux host holds the session secret. This protects against a spoofed
  or replayed USB device, but it is not the virtualization-isolated Windows
  Hello Enhanced Sign-in Security model and does not protect against a
  compromised root account.

## Reporting problems

Include the USB ID from `lsusb`, your distribution, and the output of:

```sh
sudo systemctl stop fprintd
sudo env G_MESSAGES_DEBUG=all LD_LIBRARY_PATH=/usr/local/lib/libfprint-egismoc-sdcp /usr/libexec/fprintd -t
```

while you reproduce the problem in another terminal. The log contains device
template IDs and MACs but no session keys. On Debian and Ubuntu fprintd is
`/usr/libexec/fprintd` or `/usr/lib/fprintd/fprintd`.

## Credits and license

libfprint is LGPL-2.1-or-later; see [COPYING](../COPYING). The Egis protocol
work and SDCP driver are by Joshua Grisham; the shared SDCP core by Benjamin
Berg, Joshua Grisham and Marco Trevisan. Philip Walsh contributed the
`05aa` support and the identified-print fix, konoe-akitoshi the `05b1` entry
and offline metadata check, Roman2K the longer finger wait, and alexeyru the
temperature-model fix.

[sdcp]: https://github.com/microsoft/SecureDeviceConnectionProtocol/wiki/Secure-Device-Connection-Protocol
[tod]: https://gitlab.freedesktop.org/3v1n0/libfprint/-/tree/v1.95.2+tod1
[mr547]: https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/547
[#850]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/850
[#889]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/889
[honor]: https://github.com/drphilth/honor-fmbp-libfprint-sdcp
[mr671]: https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/671
[roman2k]: https://github.com/Roman2K/samsung-galaxybook-libfprint
[fusuma]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/889
