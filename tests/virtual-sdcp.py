#!/usr/bin/env python3

import sys
try:
    import gi
    import enum
    import os
    import select
    import socket
    import tempfile
    import time

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


class Connection:
    """Context manager for a Unix-domain socket connection to the driver."""

    def __init__(self, addr):
        self.addr = addr

    def __enter__(self):
        self.con = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.con.connect(self.addr)
        return self.con

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.con.close()
        del self.con


class SDCPEvent(enum.Enum):
    """Events emitted by the virtual SDCP driver over the events socket."""
    CONNECT = 'connect'
    RECONNECT = 'reconnect'


class VirtualSDCPBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._events_tmpdir = tempfile.TemporaryDirectory(prefix='sdcp-events-')
        cls.events_socket_path = os.path.join(cls._events_tmpdir.name, 'events.sock')
        os.environ['FP_VIRTUAL_SDCP_EVENTS_SOCKET'] = cls.events_socket_path
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

        os.environ.pop('FP_VIRTUAL_SDCP_EVENTS_SOCKET', None)
        cls._events_tmpdir.cleanup()

    def setUp(self):
        self.assertIsNotNone(self.dev)
        self.assertFalse(self.dev.is_open())

    def tearDown(self):
        self.assertFalse(self.dev.is_open())

    def skipIfNotIndependentTest(self):
        # Some tests rely on environment variables to configure the virtual SDCP
        # device behavior.
        # If tests are not run independently, then the environment variables may
        # leak between tests and cause unexpected interactions.
        if os.environ.get('FP_TESTS_INDEPENDENT') != '1':
            self.skipTest("This test must be run in independent mode")

    def set_env(self, key, value='1'):
        os.environ[key] = value
        self.addCleanup(os.environ.pop, key, None)

    def remove_env(self, key):
        old = os.environ.pop(key, None)
        self.assertIsNotNone(old)
        self.addCleanup(os.environ.__setitem__, key, old)

    def use_expired_certificate(self):
        self.set_env('FP_VIRTUAL_SDCP_EXPIRED_CERTIFICATE')

    def allow_expired_certificate(self):
        self.set_env('FP_VIRTUAL_SDCP_ALLOW_EXPIRED_CERTIFICATE')

    def use_untrusted_certificate(self):
        self.set_env('FP_VIRTUAL_SDCP_UNTRUSTED_CERTIFICATE')

    def use_non_x509_strict_certificate(self):
        self.set_env('FP_VIRTUAL_SDCP_NON_X509_STRICT_CERTIFICATE')

    def allow_non_x509_strict_certificate(self):
        self.set_env('FP_VIRTUAL_SDCP_NON_X509_STRICT_VERIFICATION')

    def use_partial_chain_certificate(self):
        self.set_env('FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CERTIFICATE')

    def use_partial_chain_ca_store(self):
        self.set_env('FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CA_ONLY')

    def use_full_chain_ca_store(self):
        self.set_env('FP_VIRTUAL_SDCP_FULL_CHAIN_CA_STORE')

    def allow_partial_chain(self):
        self.set_env('FP_VIRTUAL_SDCP_ALLOW_PARTIAL_CHAIN')

    def use_deterministic_random(self):
        self.set_env('FP_VIRTUAL_SDCP_DETERMINISTIC')
        self.set_env('FP_SDCP_FIXED_RANDOM')

    def set_enroll_label(self, label):
        self.set_env('FP_VIRTUAL_SDCP_ENROLL_LABEL', label)

    def set_identify_label(self, label):
        self.set_env('FP_VIRTUAL_SDCP_IDENTIFY_LABEL', label)

    def set_connect_label(self, label):
        self.set_env('FP_VIRTUAL_SDCP_CONNECT_LABEL', label)

    def set_master_secret_label(self, label):
        self.set_env('FP_VIRTUAL_SDCP_MASTER_SECRET_LABEL', label)

    def set_application_keys_label(self, label):
        self.set_env('FP_VIRTUAL_SDCP_APPLICATION_KEYS_LABEL', label)

    def set_reconnect_label(self, label):
        self.set_env('FP_VIRTUAL_SDCP_RECONNECT_LABEL', label)

    @property
    def sleep_multiplier(self):
        return 5 if 'UNDER_VALGRIND' in os.environ else 1

    def read_events(self, con, timeout=0.5):
        """Pump the GLib main loop then read and parse all pending events.

        Returns a list of SDCPEvent values in the order they were emitted.
        """
        # Let the driver flush its pending_events queue to the socket.
        while ctx.iteration(False):
            pass

        raw = b''
        con.setblocking(False)
        deadline = time.time() + timeout * self.sleep_multiplier
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            r, _, _ = select.select([con], [], [], min(remaining, 0.1))
            if r:
                data = con.recv(256)
                if not data:
                    break
                raw += data
            else:
                break
        con.setblocking(True)

        return [SDCPEvent(token)
                for token in raw.decode().split('\n')
                if token]


class VirtualSDCPOpen(VirtualSDCPBase):
    def tearDown(self):
        if self.dev.is_open():
            self.dev.close_sync()
        super().tearDown()

    def test_connect_succeeds_with_allowed_expired_certificate(self):
        self.use_expired_certificate()
        self.allow_expired_certificate()

        self.dev.open_sync()

    def test_connect_succeeds_with_compliant_certificate_and_strict_validation_by_default(self):
        self.dev.open_sync()

    def test_connect_succeeds_with_non_x509_strict_certificate_with_non_x509_strict_verification(self):
        self.use_non_x509_strict_certificate()
        self.allow_non_x509_strict_certificate()

        self.dev.open_sync()

    def test_connect_succeeds_with_partial_chain_certificate_and_allow_partial_chain(self):
        self.use_partial_chain_certificate()
        self.use_partial_chain_ca_store()
        self.allow_partial_chain()

        self.dev.open_sync()

    def test_connect_succeeds_with_partial_chain_certificate_and_full_chain_ca_store(self):
        self.use_partial_chain_certificate()
        self.use_full_chain_ca_store()

        self.dev.open_sync()

    def test_connect_succeeds_with_partial_chain_certificate_and_full_chain_ca_store_and_allow_partial_chain(self):
        self.use_partial_chain_certificate()
        self.use_full_chain_ca_store()
        self.allow_partial_chain()

        self.dev.open_sync()

    def test_enroll_fails_with_other_label(self):
        self.skipIfNotIndependentTest()

        self.set_enroll_label('other-enroll-label')
        self.dev.open_sync()

        template = FPrint.Print.new(self.dev)
        template.set_finger(FPrint.Finger.LEFT_THUMB)

        with self.assertRaises(GLib.Error) as error:
            self.dev.enroll_sync(template, None, None, None)
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_identify_fails_with_other_label(self):
        self.skipIfNotIndependentTest()

        self.set_identify_label('other-identify-label')
        self.dev.open_sync()

        template = FPrint.Print.new(self.dev)
        template.set_finger(FPrint.Finger.LEFT_THUMB)

        enrolled = self.dev.enroll_sync(template, None, None, None)
        self.assertIsInstance(enrolled, FPrint.Print)

        with self.assertRaises(GLib.Error) as error:
            self.dev.identify_sync([enrolled], None, None, None)
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

        self.dev.clear_storage_sync()

    def test_reconnect_fails_with_other_label(self):
        self.skipIfNotIndependentTest()

        self.set_reconnect_label('other-reconnect-label')

        with Connection(self.events_socket_path) as con:
            self.dev.open_sync()
            self.dev.close_sync()

            # On the second open, the reconnect MAC won't match because the
            # stored label diverges from the device's actual label.  The base
            # class falls back to a fresh connect silently, so open still
            # succeeds.  Drain the first-open events before continuing.
            self.read_events(con)

            self.dev.open_sync()
            events = self.read_events(con)

        # Expect: reconnect attempted, MAC mismatch, fallback full connect.
        self.assertIn(SDCPEvent.RECONNECT, events)
        self.assertEqual(events[-2:], [SDCPEvent.RECONNECT, SDCPEvent.CONNECT])


class VirtualSDCPOpenDeterministic(VirtualSDCPOpen):
    """Run the same VirtualSDCPOpen tests with FP_VIRTUAL_SDCP_DETERMINISTIC=1."""

    def setUp(self):
        self.use_deterministic_random()
        super().setUp()


class VirtualSDCPOpenFailures(VirtualSDCPBase):

    def test_fails_to_open_if_device_certificate_is_untrusted(self):
        self.use_untrusted_certificate()

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_if_device_certificate_is_expired(self):
        self.use_expired_certificate()

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_if_non_x509_strict_certificate_rejected_by_default(self):
        self.use_non_x509_strict_certificate()

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_if_partial_chain_certificate_without_allow_partial_chain(self):
        self.use_partial_chain_certificate()
        self.use_partial_chain_ca_store()

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_if_partial_chain_certificate_with_root_only_ca_store(self):
        self.use_partial_chain_certificate()

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_if_partial_chain_certificate_with_root_only_ca_store_and_allow_partial_chain(self):
        self.use_partial_chain_certificate()
        self.allow_partial_chain()

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_with_other_connect_label(self):
        self.set_connect_label('other-connect-label')

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_with_other_master_secret_label(self):
        self.set_master_secret_label('other-master-secret-label')

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))

    def test_fails_to_open_with_other_application_keys_label(self):
        self.set_application_keys_label('other-application-keys-label')

        with self.assertRaises(GLib.Error) as error:
            self.dev.open_sync()
        self.assertTrue(error.exception.matches(FPrint.DeviceError.quark(),
                                                FPrint.DeviceError.UNTRUSTED))


class VirtualSDCPOpenFailuresDeterministic(VirtualSDCPOpenFailures):
    """Run the same VirtualSDCPOpenFailures tests with FP_VIRTUAL_SDCP_DETERMINISTIC=1."""

    def setUp(self):
        self.use_deterministic_random()
        super().setUp()


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
        # Ensure device was opened once before; setUp already did that, so
        # close it now to trigger a reconnect on the next open.
        self.dev.close_sync()

        with Connection(self.events_socket_path) as con:
            self.dev.open_sync()
            events = self.read_events(con)

        # The reconnect path: last event is RECONNECT (no fallback connect).
        self.assertIn(SDCPEvent.RECONNECT, events)
        self.assertEqual(events[-1], SDCPEvent.RECONNECT)

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

class VirtualSDCPDeterministic(VirtualSDCP):
    """Run the same VirtualSDCP tests with FP_VIRTUAL_SDCP_DETERMINISTIC=1."""

    def setUp(self):
        self.use_deterministic_random()
        super().setUp()


class VirtualSDCPNoReconnect(VirtualSDCPOpenedBase):

    @classmethod
    def setUpClass(cls):
        os.environ['FP_VIRTUAL_SDCP_NO_RECONNECT'] = '1'
        super().setUpClass()

    def test_connect(self):
        # Nothing to do here since setUp and tearDown will open and close the device
        pass

    def test_reconnect(self):
        # Ensure device was opened once before; setUp already did that, so
        # close it now and verify no reconnect is attempted on next open.
        self.dev.close_sync()

        with Connection(self.events_socket_path) as con:
            self.dev.open_sync()
            events = self.read_events(con)

        # No reconnect vfunc: last event must be CONNECT, no RECONNECT seen.
        self.assertEqual(events[-1], SDCPEvent.CONNECT)
        self.assertNotIn(SDCPEvent.RECONNECT, events)


if __name__ == '__main__':
    try:
        gi.require_version('FPrint', '2.0')
        from gi.repository import FPrint

    except Exception as e:
        print("Missing dependencies: %s" % str(e))
        sys.exit(77)

    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))
