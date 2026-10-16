#!/usr/bin/python3

import sys
import traceback

import gi

gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib


sys.excepthook = lambda *args: (traceback.print_exception(*args), sys.exit(1))
ctx = GLib.main_context_default()

context = FPrint.Context()
context.enumerate()
device = context.get_devices()[0]
device.open_sync()

assert device.get_driver() == 'egismoc'


def enroll_progress(*args):
    pass


# Replay the recorded setup through the first enrollment. The next operation
# is verification, which is suspended while its interrupt transfer is pending.
stored = device.list_prints_sync()
assert len(stored) > 0
device.clear_storage_sync()
assert len(device.list_prints_sync()) == 0

template = FPrint.Print.new(device)
template.set_finger(FPrint.Finger.LEFT_INDEX)
enrolled = device.enroll_sync(template, None, enroll_progress, None)
stored = device.list_prints_sync()
assert len(stored) == 1
assert stored[0].equal(enrolled)

suspend_scheduled = False
suspend_finished = False
verify_finished = False
suspend_failure = None


def suspend_resume():
    global suspend_failure, suspend_finished

    try:
        try:
            device.suspend_sync()
        except GLib.Error as error:
            assert error.matches(FPrint.DeviceError.quark(),
                                 FPrint.DeviceError.NOT_SUPPORTED)
        else:
            raise AssertionError('unsupported suspend unexpectedly succeeded')

        device.resume_sync()
    except BaseException as error:
        suspend_failure = error
    finally:
        suspend_finished = True

    return GLib.SOURCE_REMOVE


def finger_status_changed(dev, _param):
    global suspend_scheduled

    if (dev.get_finger_status() & FPrint.FingerStatusFlags.NEEDED and
            not suspend_scheduled):
        suspend_scheduled = True
        GLib.idle_add(suspend_resume, priority=GLib.PRIORITY_HIGH)


def verify_done(dev, result):
    global verify_finished

    try:
        dev.verify_finish(result)
    except GLib.Error as error:
        assert error.matches(FPrint.DeviceError.quark(), FPrint.DeviceError.BUSY)
    else:
        raise AssertionError('verification unexpectedly survived suspend')

    verify_finished = True


device.connect('notify::finger-status', finger_status_changed)
device.verify(enrolled, callback=verify_done)

while not suspend_finished or not verify_finished:
    ctx.iteration(True)

if suspend_failure:
    raise suspend_failure

assert suspend_scheduled
assert device.get_finger_status() == FPrint.FingerStatusFlags.NONE
device.close_sync()
