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

#include <libfprint/fprint.h>

#include "test-utils.h"

#ifdef TEST_TOD_DRIVER
#include "test-utils-tod.h"
#endif

static FptContext *
sdcp_context_new (void)
{
#ifdef TEST_TOD_DRIVER
  return fpt_context_new_with_fake_dev ();
#else
  return fpt_context_new_with_virtual_device (FPT_VIRTUAL_DEVICE_SDCP);
#endif
}

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
reconnect_log_handler (const gchar   *log_domain,
                       GLogLevelFlags log_level,
                       const gchar   *message,
                       gpointer       user_data)
{
  gboolean *reconnect_failure = user_data;

  if (g_str_has_prefix (message, "SDCP Reconnect failed:"))
    *reconnect_failure = TRUE;

  g_log_default_handler (log_domain, log_level, message, NULL);
}

static void
test_sdcp_device_reconnect_wrong_label (void)
{
  g_autoptr(FptContext) tctx = sdcp_context_new ();
  g_autoptr(GError) error = NULL;
  gboolean reconnect_failure = FALSE;
  guint handler_id;

  g_setenv ("FP_VIRTUAL_SDCP_RECONNECT_LABEL", "other reconnect label", TRUE);

  /* First open triggers a full connect, storing the wrong reconnect label
   * in the session. */
  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_assert_no_error (error);

  fp_device_close_sync (tctx->device, NULL, &error);
  g_assert_no_error (error);

  /* Second open: reconnect is attempted but its MAC doesn't match because
   * the stored label diverges from the device's actual label.  The base
   * class silently falls back to a fresh connect, so open still succeeds
   * but "SDCP Reconnect failed; doing a full connect" is logged. */
  handler_id = g_log_set_handler ("libfprint-sdcp_device",
                                  G_LOG_LEVEL_DEBUG,
                                  reconnect_log_handler,
                                  &reconnect_failure);
  g_assert_true (fp_device_open_sync (tctx->device, NULL, &error));
  g_log_remove_handler ("libfprint-sdcp_device", handler_id);

  g_assert_no_error (error);
  g_assert_true (fp_device_is_open (tctx->device));
  g_assert_true (reconnect_failure);

  g_unsetenv ("FP_VIRTUAL_SDCP_RECONNECT_LABEL");
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
  FpPrint *match = NULL;

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

  return g_test_run ();
}
