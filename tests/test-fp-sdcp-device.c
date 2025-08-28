/*
 * FpSdcpDevice Unit tests
 * Copyright (C) 2025 Joshua Grisham <josh@joshuagrisham.com>
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

#include "test-sdcp-device-fake.h"
#include "test-sdcp-utils.h"

static void
test_set_get_print_id (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_SDCP_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) print = fp_print_new (device);
  g_autoptr(GBytes) id1 = NULL;
  g_autoptr(GBytes) id2 = NULL;
  g_autoptr(GError) error = NULL;

  id1 = fpi_sdcp_generate_random (&error);

  g_assert_nonnull (id1);
  g_assert_no_error (error);

  fpi_sdcp_device_set_print_id (print, id1);
  fpi_sdcp_device_get_print_id (print, &id2);

  g_assert_nonnull (id2);
  g_assert_true (g_bytes_equal (id1, id2));
}

static void
test_identify (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_SDCP_DEVICE_FAKE, NULL);
  g_autoptr(GPtrArray) match_prints = g_ptr_array_new_with_free_func (g_object_unref);
  g_autoptr(FpPrint) template_print = fp_print_new (device);
  g_autoptr(FpPrint) print = NULL;
  g_autoptr(FpPrint) matched_print = NULL;
  g_autoptr(GError) error = NULL;

  g_assert_true (fp_device_open_sync (device, NULL, &error));

  print = fp_device_enroll_sync (device, template_print, NULL, NULL, NULL, &error);
  g_ptr_array_add (match_prints, g_object_ref_sink (print));

  g_assert_true (fp_device_identify_sync (device, match_prints, NULL, NULL, NULL,
                                          &matched_print, &print, &error));

  g_assert_true (fp_device_close_sync (device, NULL, &error));
}

static void
test_enroll (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_SDCP_DEVICE_FAKE, NULL);
  g_autoptr(FpPrint) template_print = fp_print_new (device);
  g_autoptr(GError) error = NULL;

  g_assert_true (fp_device_open_sync (device, NULL, &error));

  g_assert_nonnull (fp_device_enroll_sync (device, template_print, NULL, NULL, NULL, &error));
  g_assert_no_error (error);

  g_assert_true (fp_device_close_sync (device, NULL, &error));
}

static void
test_list (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_SDCP_DEVICE_FAKE, NULL);
  g_autoptr(GPtrArray) prints = NULL;
  g_autoptr(GError) error = NULL;

  g_assert_true (fp_device_open_sync (device, NULL, &error));

  prints = fp_device_list_prints_sync (device, NULL, &error);

  g_assert_nonnull (prints);
  g_assert_true (prints->len == 1);

  /* TODO: Should we also check the print's "fpi-data" for the expected ID? */

  g_assert_no_error (error);

  g_assert_true (fp_device_close_sync (device, NULL, &error));
}

static void
test_reconnect (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_SDCP_DEVICE_FAKE, NULL);
  FpiSdcpDeviceFake *fake_device = FPI_SDCP_DEVICE_FAKE (device);

  g_assert_true (fp_device_open_sync (device, NULL, NULL));
  g_assert (fake_device->reconnect_called == FALSE);

  g_assert_true (fp_device_close_sync (device, NULL, NULL));

  /* open a second time to reconnect */
  g_assert_true (fp_device_open_sync (device, NULL, NULL));
  g_assert (fake_device->reconnect_called == TRUE);

  g_assert_true (fp_device_close_sync (device, NULL, NULL));
}

static void
test_open (void)
{
  g_autoptr(FpDevice) device = g_object_new (FPI_TYPE_SDCP_DEVICE_FAKE, NULL);

  g_assert_true (fp_device_open_sync (device, NULL, NULL));
  g_assert_true (fp_device_close_sync (device, NULL, NULL));
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/sdcp_device/open", test_open);
  g_test_add_func ("/sdcp_device/reconnect", test_reconnect);
  g_test_add_func ("/sdcp_device/list", test_list);
  g_test_add_func ("/sdcp_device/enroll", test_enroll);
  g_test_add_func ("/sdcp_device/identify", test_identify);
  g_test_add_func ("/sdcp_device/set_get_print_id", test_set_get_print_id);

  return g_test_run ();
}
