#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Replay malformed Egis SDCP messages and enrollment failures.

Responses in the public capture are mutated, rebuilding USB and pcapng lengths
when necessary. The normal umockdev runner isolates all USB access; no physical
device or enrollment storage is accessed.
"""

import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile


def mutate_response(capture, case):
    """Rebuild EPBs when truncating a response, including USB actual lengths."""
    output = bytearray()
    position = 0
    pending_commit = False
    pending_list = False
    pending_check = False
    changed = False
    while position < len(capture):
        kind, length = struct.unpack_from('<II', capture, position)
        block = bytearray(capture[position:position + length])
        if kind == 6:
            size = struct.unpack_from('<I', block, 20)[0]
            packet = bytearray(block[28:28 + size])
            data = packet[64:]
            if data.startswith(b'EGIS') and data[14:17] == bytes.fromhex('501603'):
                pending_commit = True
            if data.startswith(b'EGIS') and data[14:17] == bytes.fromhex('501904'):
                pending_list = True
            if data.startswith(b'EGIS') and data[14:17] == bytes.fromhex('501703'):
                pending_check = True
            if not changed and data.startswith(b'SIGE'):
                selected = False
                if case == 'commit-rejected' and pending_commit:
                    assert data[-2:] == bytes.fromhex('9000')
                    data[-2:] = bytes.fromhex('9004')
                    selected = True
                elif case == 'enroll-check-status' and pending_check:
                    assert data[-2:] == bytes.fromhex('9004')
                    data[-2:] = bytes.fromhex('9005')
                    selected = True
                elif case == 'identify-short' and len(data) == 80:
                    data = data[:14] + data[-2:]
                    selected = True
                elif case == 'connect-short' and len(data) == 1180:
                    data = data[:15] + data[-2:]
                    selected = True
                elif case.startswith('list-') and pending_list:
                    if case == 'list-short':
                        data = data[:14]
                    elif case == 'list-partial':
                        assert len(data) >= 48
                        del data[-3]
                    elif case == 'list-status':
                        data[-2:] = bytes.fromhex('9004')
                    elif case == 'list-header':
                        data[:4] = b'BAD!'
                    elif case == 'list-empty-status':
                        assert len(data) >= 48
                        data[-2:] = bytes.fromhex('65fe')
                    elif case == 'list-length':
                        pass  # Corrupt the length after rebuilding the frame below.
                    else:
                        raise AssertionError(case)
                    selected = True
                if selected:
                    # Recompute vendor framing and checksum for the changed message.
                    data[10:14] = (len(data) - 14).to_bytes(4, 'big')
                    if case == 'list-length':
                        data[10:14] = (len(data) - 13).to_bytes(4, 'big')
                    data[8:10] = bytes(2)
                    padded = data + bytes(len(data) % 2)
                    checksum = 65535 - sum(x[0] for x in struct.iter_unpack('>H', padded)) % 65535
                    data[8:10] = checksum.to_bytes(2, 'big')
                    usb = packet[:64]
                    struct.pack_into('<II', usb, 32, len(data), len(data))
                    packet = usb + data
                    options = block[28 + size + (-size % 4):-4]
                    block = block[:28] + packet + bytes(-len(packet) % 4) + options + bytes(4)
                    struct.pack_into('<I', block, 4, len(block))
                    struct.pack_into('<II', block, 20, len(packet), len(packet))
                    struct.pack_into('<I', block, len(block) - 4, len(block))
                    changed = True
        output.extend(block)
        position += length
    assert changed, case
    return output


def duplicate_connect_exchange(capture):
    """Insert a second valid Connect request/response for an open retry."""
    position = 0
    exchange_start = None
    while position < len(capture):
        kind, length = struct.unpack_from('<II', capture, position)
        block = capture[position:position + length]
        if kind == 6:
            size = struct.unpack_from('<I', block, 20)[0]
            data = block[28 + 64:28 + size]
            if data.startswith(b'EGIS') and data[14:17] == bytes.fromhex('505701'):
                exchange_start = position
            elif exchange_start is not None and data.startswith(b'SIGE') and len(data) == 1180:
                exchange_end = position + length
                return (capture[:exchange_end] +
                        capture[exchange_start:exchange_end] +
                        capture[exchange_end:])
        position += length
    raise AssertionError('Connect exchange not found')


def main():
    source = Path(__file__).resolve().parent
    capture = bytearray((source / "egismoc/custom.pcapng").read_bytes())
    assert hashlib.sha256(capture).hexdigest() == (
        "5de511b570ef3b3ab425d713e2e688e7a14e753bd8b9a71f2f897a61dca65ab8"
    )
    marker = bytes.fromhex("032730820323308202ca")
    offset = capture.index(marker)
    assert capture.count(marker) == 1
    case = sys.argv[1]
    if case == "connect-retry":
        capture = duplicate_connect_exchange(capture)
        capture[offset:offset + 2] = bytes(2)
    elif case.startswith('list-') or case in ("commit-rejected", "identify-short", "connect-short", "enroll-check-status"):
        capture = mutate_response(capture, case)
    elif case == "clear-empty":
        pass
    elif case == "stale-identify":
        # Restore the first Identify response's valid *zero-nonce* MAC from
        # upstream's original recording, while retaining the fresh request.
        old_mac = bytes.fromhex(
            "513e5373b268ff5662a75f8540e2dbc0d43d7d10f3e0f7c705004e1bc3ca08cd"
        )
        position = 0
        while position < len(capture):
            kind, length = struct.unpack_from('<II', capture, position)
            if kind == 6:
                size = struct.unpack_from('<I', capture, position + 20)[0]
                start, end = position + 28 + 64, position + 28 + size
                packet = capture[start:end]
                if len(packet) == 80 and packet.startswith(b'SIGE'):
                    packet[14:46] = old_mac
                    packet[8:10] = bytes(2)
                    checksum = 65535 - sum(x[0] for x in struct.iter_unpack('>H', packet)) % 65535
                    packet[8:10] = checksum.to_bytes(2, 'big')
                    capture[start:end] = packet
                    break
            position += length
        else:
            raise AssertionError('No Identify response found')
    else:
        replacement = {"empty": 0, "oversized": 65535, "overlap": 808}[case]
        capture[offset:offset + 2] = replacement.to_bytes(2, "big")

    with tempfile.TemporaryDirectory(prefix="egismoc-sdcp-malformed-") as temp:
        directory = Path(temp)
        shutil.copyfile(source / "egismoc/device", directory / "device")
        (directory / "custom.pcapng").write_bytes(capture)
        if case == "connect-retry":
            script = '''\
import gi
gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib
context = FPrint.Context()
devices = context.get_devices()
assert len(devices) == 1
device = devices[0]
try:
    device.open_sync()
except GLib.Error as error:
    assert error.matches(FPrint.DeviceError.quark(), FPrint.DeviceError.DATA_INVALID), error
    assert 'certificate length' in error.message, error
else:
    raise AssertionError('Malformed ConnectResponse was accepted')
assert not device.is_open()
device.open_sync()
assert device.is_open()
device.close_sync()
assert not device.is_open()
print('Failed SDCP open released USB resources and retry succeeded')
'''
        elif case == "clear-empty":
            script = (source / "egismoc/custom.py").read_text()
            needle = '''\
print("clear done")

print("listing - device should be empty")
stored = d.list_prints_sync()
assert len(stored) == 0
del stored
'''
            replacement = '''\
print("clear done")

print("clearing an already-empty device")
try:
    d.clear_storage_sync()
except GLib.Error as error:
    assert error.matches(FPrint.DeviceError.quark(), FPrint.DeviceError.DATA_NOT_FOUND), error
else:
    raise AssertionError('Clearing an empty device unexpectedly succeeded')
assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
d.close_sync()
assert not d.is_open()
print('Empty clear failed cleanly and device closed')
sys.exit(0)
'''
            assert script.count(needle) == 2
            script = script.replace(needle, replacement, 1)
        elif case.startswith('list-'):
            script = '''\
import gi
gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib
context = FPrint.Context()
devices = context.get_devices()
assert len(devices) == 1
device = devices[0]
device.open_sync()
try:
    device.list_prints_sync()
except GLib.Error as error:
    assert error.matches(FPrint.DeviceError.quark(), FPrint.DeviceError.PROTO), error
    assert 'template list' in error.message, error
else:
    raise AssertionError('Malformed template list was accepted')
device.close_sync()
assert not device.is_open()
print('Malformed template list rejected and device closed cleanly')
'''
        elif case in ("stale-identify", "identify-short", "commit-rejected", "enroll-check-status"):
            script = (source / "egismoc/custom.py").read_text()
            if case in ("commit-rejected", "enroll-check-status"):
                needle = 'p1 = d.enroll_sync(template, None, enroll_progress, None)'
                call = 'd.enroll_sync(template, None, enroll_progress, None)'
                expected, message = ('UNTRUSTED', 'Enrollment was rejected') if case == 'commit-rejected' else ('PROTO', 'duplicate-check response')
            else:
                needle = 'verify_res, verify_print = d.verify_sync(p1)'
                call = 'd.verify_sync(p1)'
                expected = 'PROTO' if case == 'identify-short' else 'UNTRUSTED'
                message = 'Identify response too short' if case == 'identify-short' else 'AuthorizedIdentity'
            assert script.count(needle) == 1
            script = script.replace(needle, f"""\
try:
    {call}
except GLib.Error as error:
    assert error.matches(FPrint.DeviceError.quark(), FPrint.DeviceError.{expected}), error
    assert {message!r} in error.message, error
else:
    raise AssertionError('Malformed response was accepted')
assert d.get_finger_status() == FPrint.FingerStatusFlags.NONE
d.close_sync()
assert not d.is_open()
print('Failure rejected and device closed cleanly')
sys.exit(0)
""")
        else:
            script = '''\
import gi
gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib

context = FPrint.Context()
context.enumerate()
devices = context.get_devices()
assert len(devices) == 1
device = devices[0]
assert device.get_driver() == 'egismoc'
try:
    device.open_sync()
except GLib.Error as error:
    assert error.matches(FPrint.DeviceError.quark(), FPrint.DeviceError.DATA_INVALID), error
    assert ('certificate length' in error.message or 'not long enough' in error.message), error
else:
    raise AssertionError('Malformed ConnectResponse was accepted')
assert not device.is_open()
'''
        (directory / "custom.py").write_text(script)
        return subprocess.call([sys.executable, str(source / "umockdev-test.py"), temp])


if __name__ == "__main__":
    sys.exit(main())
