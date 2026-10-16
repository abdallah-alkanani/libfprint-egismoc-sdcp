#!/usr/bin/python3

import sys
import traceback

import gi

gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, Gio, GLib


sys.excepthook = lambda *args: (traceback.print_exception(*args), sys.exit(1))
ctx = GLib.main_context_default()

context = FPrint.Context()
context.enumerate()
device = context.get_devices()[0]
device.open_sync()

assert device.get_driver() == 'egismoc'


def enroll_progress(*args):
    pass


# Replay the recorded setup through the first enrollment. The next recorded
# operation is verification, which is cancelled while its interrupt transfer
# is pending.
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

cancellable = Gio.Cancellable()
finished = False


def finger_status_changed(dev, _param):
    if (dev.get_finger_status() & FPrint.FingerStatusFlags.NEEDED and
            not cancellable.is_cancelled()):
        cancellable.cancel()


def verify_done(dev, result):
    global finished

    try:
        dev.verify_finish(result)
    except GLib.Error as error:
        assert error.matches(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED)
    else:
        raise AssertionError('cancelled verification unexpectedly succeeded')

    finished = True


device.connect('notify::finger-status', finger_status_changed)
device.verify(enrolled, cancellable=cancellable, callback=verify_done)

while not finished:
    ctx.iteration(True)

assert cancellable.is_cancelled()
assert device.get_finger_status() == FPrint.FingerStatusFlags.NONE
device.close_sync()
