#!/usr/bin/env python3

import sys
try:
    import gi
    import os

    from gi.repository import GLib

    import unittest
except Exception as e:
    print("Missing dependencies: %s" % str(e))
    sys.exit(77)

FPrint = None

# Only permit loading virtual_sdcp driver for tests in this file
os.environ['FP_DRIVERS_WHITELIST'] = 'virtual_sdcp'

if hasattr(os.environ, 'MESON_SOURCE_ROOT'):
    root = os.environ['MESON_SOURCE_ROOT']
else:
    root = os.path.join(os.path.dirname(__file__), '..')

ctx = GLib.main_context_default()

class VirtualSDCPBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ['FP_VIRTUAL_SDCP'] = '1'

        cls.ctx = FPrint.Context()

        cls.dev = None
        for dev in cls.ctx.get_devices():
            cls.dev = dev
            break

        assert cls.dev is not None, "You need to compile with virtual_sdcp for testing"

    @classmethod
    def tearDownClass(cls):
        # We still close the device here if it is open, so that we can
        # catch other issues, given that it must be closed in each test as per
        # the tearDown definition.
        if cls.dev is not None and cls.dev.is_open():
            cls.dev.close_sync()

        del cls.dev
        del cls.ctx

    def setUp(self):
        self.assertIsNotNone(self.dev)
        self.assertFalse(self.dev.is_open())

    def tearDown(self):
        self.assertFalse(self.dev.is_open())

    def set_env(self, key, value='1'):
        os.environ[key] = value
        self.addCleanup(os.environ.pop, key, None)

    def remove_env(self, key):
        old = os.environ.pop(key, None)
        self.assertIsNotNone(old)
        self.addCleanup(os.environ.__setitem__, key, old)

    def use_untrusted_certificate(self):
        self.set_env('FP_VIRTUAL_SDCP_UNTRUSTED_CERTIFICATE')

    def disable_device_emulation(self):
        self.remove_env('FP_DEVICE_EMULATION')

class VirtualSDCPOpenFailures(VirtualSDCPBase):

    def test_fails_to_open_if_not_using_device_emulation(self):
        if not 'FP_TESTS_INDEPENDENT' in os.environ:
            self.skipTest("This can only run when tests are independent")

        self.disable_device_emulation()
        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_if_device_certificate_is_untrusted(self):
        self.use_untrusted_certificate()

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))


class VirtualSDCPOpenedBase(VirtualSDCPBase):

    def setUp(self):
        super().setUp()
        self.dev.open_sync()
        self.assertTrue(self.dev.is_open())

    def tearDown(self):
        self.dev.clear_storage_sync()
        self.dev.close_sync()
        super().tearDown()


class VirtualSDCP(VirtualSDCPOpenedBase):

    def test_connect(self):
        # Nothing to do here since setUp and tearDown will open and close the device
        pass

    def test_reconnect(self):
        # FIXME:
        # Ensure device was opened once before, this may be a reconnect if
        # it is the same process as another test.
        self.dev.close_sync()

        # Check that a reconnect happens on next open. To know about this, we
        # need to parse check log messages for that.
        reconnected = False

        def log_func(domain, level, msg):
            nonlocal reconnected

            print(f"log: '{domain}', '{level}', '{msg}'")
            # FIXME: We should not rely on log messages, but rather setup a socket
            # for communication between the test and the driver.
            if msg == 'SDCP Reconnect succeeded':
                reconnected = True

            # Call default handler
            GLib.log_default_handler(domain, level, msg)

        handler_id = GLib.log_set_handler('libfprint-sdcp_device', GLib.LogLevelFlags.LEVEL_DEBUG, log_func)
        self.dev.open_sync()
        GLib.log_remove_handler('libfprint-sdcp_device', handler_id)
        self.assertTrue(reconnected)

    def test_list(self):
        prints = self.dev.list_prints_sync()
        self.assertEqual(prints, [])

    def test_enroll_list_verify(self):
        # Set up a new print
        template = FPrint.Print.new(self.dev)
        template.set_finger(FPrint.Finger.LEFT_THUMB)

        # Enroll the new print
        new_print = self.dev.enroll_sync(template, None, None, None)
        self.assertIsInstance(new_print, FPrint.Print)

        # Get the print list again and ensure there is exactly 1 print
        prints = self.dev.list_prints_sync()
        self.assertEqual(len(prints), 1)

        # Ensure the one print from list is the same as new_print
        self.assertTrue(prints[0].equal(new_print))

        # Verify new_print
        verify_res, verify_print = self.dev.verify_sync(prints[0])
        self.assertTrue(verify_res)
        self.assertTrue(verify_print.equal(prints[0]))

        # Set up a second new print
        template = FPrint.Print.new(self.dev)
        template.set_finger(FPrint.Finger.LEFT_INDEX)

        # Enroll the second print
        new_print2 = self.dev.enroll_sync(template, None, None, None)
        self.assertIsInstance(new_print2, FPrint.Print)

        # Get the print list again and ensure there is exactly 2 prints
        prints = self.dev.list_prints_sync()
        self.assertEqual(len(prints), 2)

        # Ensure the second print from list is the same as new_print2
        self.assertTrue(prints[1].equal(new_print2))

class VirtualSDCPNoReconnect(VirtualSDCPOpenedBase):

    @classmethod
    def setUpClass(cls):
        os.environ['FP_VIRTUAL_SDCP_NO_RECONNECT'] = '1'
        super().setUpClass()

    def test_connect(self):
        # Nothing to do here since setUp and tearDown will open and close the device
        pass

    def test_reconnect(self):
        # Ensure device was opened once before, this may be a reconnect if
        # it is the same process as another test.
        self.dev.close_sync()

        # Check that a reconnect happens on next open. To know about this, we
        # need to parse check log messages for that.
        reconnected = False
        def log_func(domain, level, msg):
            nonlocal reconnected

            print(f"log: '{domain}', '{level}', '{msg}'")
            # FIXME: We should not rely on log messages, but rather setup a socket
            # for communication between the test and the driver.
            if msg == 'SDCP Reconnect succeeded':
                reconnected = True

            # Call default handler
            GLib.log_default_handler(domain, level, msg)

        handler_id = GLib.log_set_handler('libfprint-sdcp_device',
                                          GLib.LogLevelFlags.LEVEL_DEBUG, log_func)
        self.dev.open_sync()
        GLib.log_remove_handler('libfprint-sdcp_device', handler_id)

        # Ensure that we did NOT see "SDCP Reconnect succeeded" in the log
        self.assertFalse(reconnected)


if __name__ == '__main__':
    try:
        gi.require_version('FPrint', '2.0')
        from gi.repository import FPrint

    except Exception as e:
        print("Missing dependencies: %s" % str(e))
        sys.exit(77)

    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))
