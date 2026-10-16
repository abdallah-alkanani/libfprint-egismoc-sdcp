/*
 * Unit tests for the FpSdcpDevice base class
 * Copyright (C) 2026 Marco Trevisan (Treviño) <marco.trevisan@canonical.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>

#include <libfprint/fprint.h>

#include "glib/gstdio.h"
#include "test-utils.h"

#ifdef TEST_TOD_DRIVER
#include "test-utils-tod.h"
#endif

/* Connect to the SDCP events Unix socket at @path. */
static GSocket *
connect_events_socket (const char *path)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GSocketAddress) addr = g_unix_socket_address_new (path);
  GSocket *sock;

  sock = g_socket_new (G_SOCKET_FAMILY_UNIX, G_SOCKET_TYPE_STREAM, 0, &error);
  g_assert_no_error (error);

  g_socket_connect (sock, addr, NULL, &error);
  g_assert_no_error (error);

  return sock;
}

static char *
read_events (GSocket *sock)
{
  GString *result = g_string_new (NULL);

  /* Let the driver flush its pending_events queue to the socket. */
  while (g_main_context_iteration (NULL, FALSE))
    ;

  /* Read all available data; 200 ms timeout per chunk so we stop cleanly. */
  while (g_socket_condition_timed_wait (sock, G_IO_IN,
                                        200 * G_TIME_SPAN_MILLISECOND,
                                        NULL, NULL))
    {
      char buf[256];
      gssize n = g_socket_receive (sock, buf, sizeof (buf), NULL, NULL);
      if (n <= 0)
        break;
      g_string_append_len (result, buf, n);
    }

  return g_string_free (result, FALSE);
}

static FptContext *
sdcp_context_new (void)
{
#ifdef TEST_TOD_DRIVER
  return fpt_context_new_with_fake_dev ();
#else
  return fpt_context_new_with_virtual_device (FPT_VIRTUAL_DEVICE_SDCP);
#endif
}

#ifndef TEST_TOD_DRIVER
/* These fault hooks are provided by the current virtual driver only. */
static void
test_sdcp_device_enroll_failure_retry (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) template = g_object_ref_sink (fp_print_new (tctx->device));
  g_autoptr(FpPrint) enrolled = NULL;
  g_autoptr(GPtrArray) prints = NULL;

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_setenv ("FP_VIRTUAL_SDCP_ENROLL_FAILURE", "1", TRUE);
  enrolled = fp_device_enroll_sync (tctx->device, template, NULL, NULL, NULL, &error);
  g_assert_null (enrolled);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
  g_clear_error (&error);
  g_unsetenv ("FP_VIRTUAL_SDCP_ENROLL_FAILURE");
  prints = fp_device_list_prints_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (prints->len, ==, 0);
  enrolled = fp_device_enroll_sync (tctx->device, template, NULL, NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (enrolled);
}

static void
test_sdcp_device_connect_failure_retry (gconstpointer data)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) secret = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_CONNECT_FAILURE", data, TRUE);
  g_assert_false (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL);
  g_assert_false (fp_device_is_open (tctx->device));
  g_object_get (tctx->device, "sdcp-data", &secret, NULL);
  g_assert_null (secret);
  g_unsetenv ("FP_VIRTUAL_SDCP_CONNECT_FAILURE");
  g_clear_error (&error);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
}
#endif

static FpPrint *
make_enroll_template (FpDevice *device)
{
  FpPrint *tmpl = fp_print_new (device);

  fp_print_set_finger (tmpl, FP_FINGER_LEFT_THUMB);
  return tmpl;
}

static void
test_sdcp_device_open_connect (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));
}

static void
test_sdcp_device_open_connect_deterministic (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_DETERMINISTIC", "1", TRUE);
  g_setenv ("FP_SDCP_FIXED_RANDOM", "1", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));

  g_unsetenv ("FP_VIRTUAL_SDCP_DETERMINISTIC");
  g_unsetenv ("FP_SDCP_FIXED_RANDOM");
}

static void
test_sdcp_device_open_fails_expired_certificate (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_EXPIRED_CERTIFICATE", "1", TRUE);

  g_assert_false (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);

  g_unsetenv ("FP_VIRTUAL_SDCP_EXPIRED_CERTIFICATE");
}

static void
test_sdcp_device_open_succeeds_expired_certificate_allowed (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_EXPIRED_CERTIFICATE", "1", TRUE);
  g_setenv ("FP_VIRTUAL_SDCP_ALLOW_EXPIRED_CERTIFICATE", "1", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));

  g_unsetenv ("FP_VIRTUAL_SDCP_EXPIRED_CERTIFICATE");
  g_unsetenv ("FP_VIRTUAL_SDCP_ALLOW_EXPIRED_CERTIFICATE");
}

static void
test_sdcp_device_open_fails_untrusted_certificate (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_UNTRUSTED_CERTIFICATE", "1", TRUE);

  g_assert_false (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);

  g_unsetenv ("FP_VIRTUAL_SDCP_UNTRUSTED_CERTIFICATE");
}

static void
test_sdcp_device_open_fails_non_x509_strict_certificate (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_NON_X509_STRICT_CERTIFICATE", "1", TRUE);

  g_assert_false (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);

  g_unsetenv ("FP_VIRTUAL_SDCP_NON_X509_STRICT_CERTIFICATE");
}

static void
test_sdcp_device_open_succeeds_non_x509_strict_certificate_allowed (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_NON_X509_STRICT_CERTIFICATE", "1", TRUE);
  g_setenv ("FP_VIRTUAL_SDCP_NON_X509_STRICT_VERIFICATION", "1", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));

  g_unsetenv ("FP_VIRTUAL_SDCP_NON_X509_STRICT_CERTIFICATE");
  g_unsetenv ("FP_VIRTUAL_SDCP_NON_X509_STRICT_VERIFICATION");
}

static void
test_sdcp_device_open_fails_partial_chain_certificate (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CERTIFICATE", "1", TRUE);
  g_setenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CA_ONLY", "1", TRUE);

  g_assert_false (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);

  g_unsetenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CERTIFICATE");
  g_unsetenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CA_ONLY");
}

static void
test_sdcp_device_open_succeeds_partial_chain_certificate_with_allow (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CERTIFICATE", "1", TRUE);
  g_setenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CA_ONLY", "1", TRUE);
  g_setenv ("FP_VIRTUAL_SDCP_ALLOW_PARTIAL_CHAIN", "1", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));

  g_unsetenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CERTIFICATE");
  g_unsetenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CA_ONLY");
  g_unsetenv ("FP_VIRTUAL_SDCP_ALLOW_PARTIAL_CHAIN");
}

static void
test_sdcp_device_open_succeeds_partial_chain_certificate_with_full_chain_ca (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CERTIFICATE", "1", TRUE);
  g_setenv ("FP_VIRTUAL_SDCP_FULL_CHAIN_CA_STORE", "1", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));

  g_unsetenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CERTIFICATE");
  g_unsetenv ("FP_VIRTUAL_SDCP_FULL_CHAIN_CA_STORE");
}

static void
test_sdcp_device_reconnect (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  /* First open triggers a full connect. */
  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);

  fp_device_close_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  /* Second open of the same device instance triggers a reconnect. */
  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));
}

static void
test_sdcp_device_reconnect_deterministic (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_DETERMINISTIC", "1", TRUE);
  g_setenv ("FP_SDCP_FIXED_RANDOM", "1", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);

  fp_device_close_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));

  g_unsetenv ("FP_VIRTUAL_SDCP_DETERMINISTIC");
  g_unsetenv ("FP_SDCP_FIXED_RANDOM");
}

static void
test_sdcp_device_reconnect_not_supported (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_NO_RECONNECT", "1", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);

  fp_device_close_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  /* Second open falls back to a full connect since the driver has no reconnect. */
  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));

  g_unsetenv ("FP_VIRTUAL_SDCP_NO_RECONNECT");
}

static void
test_sdcp_device_reconnect_wrong_label (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree char *tmpdir = g_dir_make_tmp ("sdcp-events-XXXXXX", &error);
  g_autofree char *socket_path = NULL;
  g_autoptr(GSocket) sock = NULL;
  g_autofree char *events = NULL;
  g_autoptr(FptContext) tctx = NULL;

  g_assert_no_error (error);
  socket_path = g_build_filename (tmpdir, "events.sock", NULL);

  g_setenv ("FP_VIRTUAL_SDCP_RECONNECT_LABEL", "other reconnect label", TRUE);
  g_setenv ("FP_VIRTUAL_SDCP_EVENTS_SOCKET", socket_path, TRUE);

  /* Device is created after the env vars are set so the listener starts. */
  tctx = sdcp_context_new ();
  sock = connect_events_socket (socket_path);

  /* First open triggers a full connect, storing the wrong reconnect label. */
  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);

  /* Drain the first-open event and verify it is a plain connect. */
  g_clear_pointer (&events, g_free);
  events = read_events (sock);
  {
    g_auto(GStrv) ev = g_strsplit (events, "\n", -1);
    g_assert_cmpstr (ev[0], ==, "connect");
  }

  fp_device_close_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  /* Second open: reconnect is attempted but its MAC doesn't match because the
   * stored label diverges from the device's actual label.  The base class
   * falls back to a fresh connect silently, so open still succeeds. */
  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));

  g_clear_pointer (&events, g_free);
  events = read_events (sock);
  {
    g_auto(GStrv) ev = g_strsplit (events, "\n", -1);
    /* Expect: reconnect attempted, MAC mismatch, fallback full connect. */
    g_assert_cmpstr (ev[0], ==, "reconnect");
    g_assert_cmpstr (ev[1], ==, "connect");
  }

  g_unsetenv ("FP_VIRTUAL_SDCP_RECONNECT_LABEL");
  g_unsetenv ("FP_VIRTUAL_SDCP_EVENTS_SOCKET");

  g_unlink (socket_path);
  g_rmdir (tmpdir);
}

static void
test_sdcp_device_list_empty (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(GPtrArray) prints = NULL;

  fp_device_open_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  prints = fp_device_list_prints_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (prints);
  g_assert_cmpuint (prints->len, ==, 0);
}

static void
test_sdcp_device_enroll (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) enrolled = NULL;

  fp_device_open_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  /* fp_device_enroll_sync() takes (transfer floating), so pass a raw pointer. */
  enrolled = fp_device_enroll_sync (tctx->device,
                                    make_enroll_template (tctx->device),
                                    NULL, NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (enrolled);
}

static void
test_sdcp_device_enroll_list (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) enrolled = NULL;
  g_autoptr(GPtrArray) prints = NULL;

  fp_device_open_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  enrolled = fp_device_enroll_sync (tctx->device,
                                    make_enroll_template (tctx->device),
                                    NULL, NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (enrolled);

  prints = fp_device_list_prints_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (prints);
  g_assert_cmpuint (prints->len, ==, 1);
  g_assert_true (fp_print_equal (g_ptr_array_index (prints, 0), enrolled));
}

static void
test_sdcp_device_identify (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) enrolled = NULL;
  g_autoptr(GPtrArray) gallery = NULL;
  g_autoptr(FpPrint) match = NULL;

  fp_device_open_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  enrolled = fp_device_enroll_sync (tctx->device,
                                    make_enroll_template (tctx->device),
                                    NULL, NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (enrolled);

  gallery = g_ptr_array_new_with_free_func (g_object_unref);
  g_ptr_array_add (gallery, g_object_ref (enrolled));

  g_assert_true (fp_device_identify_sync (tctx->device, gallery, NULL,
                                          NULL, NULL, &match, NULL, &error));
  g_assert_no_error (error);
  g_assert_nonnull (match);
  g_assert_true (fp_print_equal (match, enrolled));
}

static void
test_sdcp_device_identify_no_prints (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  g_autoptr(FpPrint) match = NULL;

  fp_device_open_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  /* No prints enrolled on device; the driver returns DATA_NOT_FOUND. */
  g_assert_false (fp_device_identify_sync (tctx->device, gallery, NULL,
                                           NULL, NULL, &match, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_NOT_FOUND);
  g_assert_null (match);
}

static void
test_sdcp_device_open_fails_wrong_connect_label (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_CONNECT_LABEL", "other connect label", TRUE);

  g_assert_false (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);

  g_unsetenv ("FP_VIRTUAL_SDCP_CONNECT_LABEL");
}

static void
test_sdcp_device_open_fails_wrong_master_secret_label (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_MASTER_SECRET_LABEL", "other master secret label", TRUE);

  g_assert_false (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);

  g_unsetenv ("FP_VIRTUAL_SDCP_MASTER_SECRET_LABEL");
}

static void
test_sdcp_device_open_fails_wrong_application_keys_label (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_APPLICATION_KEYS_LABEL", "other application keys label", TRUE);

  g_assert_false (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);

  g_unsetenv ("FP_VIRTUAL_SDCP_APPLICATION_KEYS_LABEL");
}

static void
test_sdcp_device_enroll_fails_wrong_label (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) enrolled = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_ENROLL_LABEL", "other enroll label", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);

  g_unsetenv ("FP_VIRTUAL_SDCP_ENROLL_LABEL");

  /* Enroll fails because the host uses the wrong claim label to generate
   * the enrollment ID, which the device rejects as not matching. */
  enrolled = fp_device_enroll_sync (tctx->device,
                                    make_enroll_template (tctx->device),
                                    NULL, NULL, NULL, &error);
  g_assert_null (enrolled);
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
}

static void
test_sdcp_device_identify_fails_wrong_label (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) enrolled = NULL;
  g_autoptr(GPtrArray) gallery = NULL;
  g_autoptr(FpPrint) match = NULL;

  g_setenv ("FP_VIRTUAL_SDCP_IDENTIFY_LABEL", "other identify label", TRUE);

  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);

  g_unsetenv ("FP_VIRTUAL_SDCP_IDENTIFY_LABEL");

  /* Enroll succeeds: the enroll label is still the default. */
  enrolled = fp_device_enroll_sync (tctx->device,
                                    make_enroll_template (tctx->device),
                                    NULL, NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (enrolled);

  gallery = g_ptr_array_new_with_free_func (g_object_unref);
  g_ptr_array_add (gallery, g_object_ref (enrolled));

  /* Identify fails because the host uses the wrong claim label to verify
   * the identify MAC, which doesn't match the MAC computed by the device. */
  g_assert_false (fp_device_identify_sync (tctx->device, gallery, NULL,
                                           NULL, NULL, &match, NULL, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
  g_assert_null (match);
}

static void
test_sdcp_device_clear_storage (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) enrolled = NULL;
  g_autoptr(GPtrArray) prints_before = NULL;
  g_autoptr(GPtrArray) prints_after = NULL;

  fp_device_open_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  enrolled = fp_device_enroll_sync (tctx->device,
                                    make_enroll_template (tctx->device),
                                    NULL, NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (enrolled);

  prints_before = fp_device_list_prints_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (prints_before->len, ==, 1);

  g_assert_true (fp_device_clear_storage_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);

  prints_after = fp_device_list_prints_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (prints_after->len, ==, 0);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/sdcp-device/open/connect",
                   test_sdcp_device_open_connect);
  g_test_add_func ("/sdcp-device/open/connect/deterministic",
                   test_sdcp_device_open_connect_deterministic);
  g_test_add_func ("/sdcp-device/open/fails/expired_certificate",
                   test_sdcp_device_open_fails_expired_certificate);
  g_test_add_func ("/sdcp-device/open/succeeds/expired_certificate_allowed",
                   test_sdcp_device_open_succeeds_expired_certificate_allowed);
  g_test_add_func ("/sdcp-device/open/fails/untrusted_certificate",
                   test_sdcp_device_open_fails_untrusted_certificate);
  g_test_add_func ("/sdcp-device/open/fails/non_x509_strict_certificate",
                   test_sdcp_device_open_fails_non_x509_strict_certificate);
  g_test_add_func ("/sdcp-device/open/succeeds/non_x509_strict_certificate_allowed",
                   test_sdcp_device_open_succeeds_non_x509_strict_certificate_allowed);
  g_test_add_func ("/sdcp-device/open/fails/partial_chain_certificate",
                   test_sdcp_device_open_fails_partial_chain_certificate);
  g_test_add_func ("/sdcp-device/open/succeeds/partial_chain_certificate_with_allow",
                   test_sdcp_device_open_succeeds_partial_chain_certificate_with_allow);
  g_test_add_func ("/sdcp-device/open/succeeds/partial_chain_certificate_with_full_chain_ca",
                   test_sdcp_device_open_succeeds_partial_chain_certificate_with_full_chain_ca);
  g_test_add_func ("/sdcp-device/open/fails/wrong_connect_label",
                   test_sdcp_device_open_fails_wrong_connect_label);
  g_test_add_func ("/sdcp-device/open/fails/wrong_master_secret_label",
                   test_sdcp_device_open_fails_wrong_master_secret_label);
  g_test_add_func ("/sdcp-device/open/fails/wrong_application_keys_label",
                   test_sdcp_device_open_fails_wrong_application_keys_label);

  g_test_add_func ("/sdcp-device/reconnect",
                   test_sdcp_device_reconnect);
  g_test_add_func ("/sdcp-device/reconnect/deterministic",
                   test_sdcp_device_reconnect_deterministic);
  g_test_add_func ("/sdcp-device/reconnect/not_supported",
                   test_sdcp_device_reconnect_not_supported);
  g_test_add_func ("/sdcp-device/reconnect/wrong_label",
                   test_sdcp_device_reconnect_wrong_label);

  g_test_add_func ("/sdcp-device/list/empty",
                   test_sdcp_device_list_empty);
  g_test_add_func ("/sdcp-device/enroll",
                   test_sdcp_device_enroll);
  g_test_add_func ("/sdcp-device/enroll/list",
                   test_sdcp_device_enroll_list);
  g_test_add_func ("/sdcp-device/enroll/fails/wrong_label",
                   test_sdcp_device_enroll_fails_wrong_label);
  g_test_add_func ("/sdcp-device/identify",
                   test_sdcp_device_identify);
  g_test_add_func ("/sdcp-device/identify/no_prints",
                   test_sdcp_device_identify_no_prints);
  g_test_add_func ("/sdcp-device/identify/fails/wrong_label",
                   test_sdcp_device_identify_fails_wrong_label);
  g_test_add_func ("/sdcp-device/clear_storage",
                   test_sdcp_device_clear_storage);

#ifndef TEST_TOD_DRIVER
  g_test_add_func ("/sdcp-device/enroll/fails/abort_retry", test_sdcp_device_enroll_failure_retry);
  g_test_add_data_func ("/sdcp-device/open/fails/before_keys_retry", "before-keys",
                        test_sdcp_device_connect_failure_retry);
  g_test_add_data_func ("/sdcp-device/open/fails/incomplete_claim_retry", "incomplete-claim",
                        test_sdcp_device_connect_failure_retry);
#endif

  return g_test_run ();
}
