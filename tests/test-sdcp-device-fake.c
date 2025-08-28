/*
 * Virtual driver for SDCP unit testing
 * Completes actions using example values from Microsoft's SDCP documentation
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

#define FP_COMPONENT "fake_test_sdcp_dev"
#include "fpi-log.h"

#include "test-sdcp-device-fake.h"

G_DEFINE_TYPE (FpiSdcpDeviceFake, fpi_sdcp_device_fake, FP_TYPE_SDCP_DEVICE)

static const FpIdEntry driver_ids[] = {
  { .virtual_envvar = "FP_VIRTUAL_FAKE_SDCP_DEVICE" },
  { .virtual_envvar = NULL }
};

static void
fpi_sdcp_device_fake_identify (FpSdcpDevice *sdcp_device)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) nonce = NULL;
  g_autoptr(GBytes) identify_enrollment_id = g_bytes_from_hex (identify_enrollment_id_hex);
  g_autoptr(GBytes) identify_mac = g_bytes_from_hex (identify_mac_hex);

  /*
   * Normally, a driver would fetch the identify data and then send it to the
   * device's Identify command. In this fake device, we will just fetch and
   * verify the nonce was generated but do nothing with it
   */

  fpi_sdcp_device_get_identify_data (sdcp_device, &nonce);

  g_assert (nonce);
  g_assert (g_bytes_get_size (nonce) == SDCP_NONCE_SIZE);

  /*
   * In emulation mode (FP_DEVICE_EMULATION=1), a different hard-coded nonce is
   * set in fpi-sdcp-device, which was the same nonce used to generate both the
   * identify_enrollment_id and identify_mac values provided here
   */

  fpi_sdcp_device_identify_complete (sdcp_device, identify_enrollment_id, identify_mac, error);
}

static void
fpi_sdcp_device_fake_enroll_commit (FpSdcpDevice *sdcp_device, GBytes *id)
{
  fpi_sdcp_device_enroll_commit_complete (sdcp_device, NULL);
}

static void
fpi_sdcp_device_fake_enroll (FpSdcpDevice *sdcp_device)
{
  g_autoptr(GError) error = NULL;
  GBytes *enrollment_nonce = g_bytes_from_hex (enrollment_nonce_hex);

  fpi_sdcp_device_enroll_commit (sdcp_device, enrollment_nonce, error);

  g_bytes_unref (enrollment_nonce);
}

static void
fpi_sdcp_device_fake_list (FpSdcpDevice *sdcp_device)
{
  g_autoptr(GBytes) identify_enrollment_id = g_bytes_from_hex (identify_enrollment_id_hex);
  GPtrArray *enrollment_ids = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);

  g_ptr_array_add (enrollment_ids, g_steal_pointer (&identify_enrollment_id));

  for (gint i = 0; i < enrollment_ids->len; i++)
    {
      fp_dbg ("print %d:", i);
      fp_dbg_hex_dump_gbytes (g_ptr_array_index (enrollment_ids, i));
    }

  fpi_sdcp_device_list_complete (sdcp_device, g_steal_pointer (&enrollment_ids), NULL);
}

static void
fpi_sdcp_device_fake_reconnect (FpSdcpDevice *sdcp_device)
{
  FpiSdcpDeviceFake *fake_device = FPI_SDCP_DEVICE_FAKE (sdcp_device);

  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) random = NULL;
  g_autoptr(GBytes) reconnect_mac = g_bytes_from_hex (reconnect_mac_hex);

  /*
   * Normally, a driver would fetch the reconnect data and then send it to the
   * device's Reconnect command. In this fake device, we will just fetch and
   * verify the random was generated but do nothing with it
   */

  fpi_sdcp_device_get_reconnect_data (sdcp_device, &random);

  g_assert (random);
  g_assert (g_bytes_get_size (random) == SDCP_RANDOM_SIZE);

  /*
   * In emulation mode (FP_DEVICE_EMULATION=1), a different hard-coded random is
   * set in fpi-sdcp-device, which was the same random used to generate the
   * reconnect_mac value provided here
   */

  fpi_sdcp_device_reconnect_complete (sdcp_device, reconnect_mac, error);

  fake_device->reconnect_called = TRUE;
}

static void
fpi_sdcp_device_fake_connect (FpSdcpDevice *sdcp_device)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) host_random = NULL;
  g_autoptr(GBytes) host_public_key = NULL;
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = g_bytes_from_hex (connect_mac_hex);
  FpiSdcpClaim *claim = sdcp_test_claim ();

  fp_device_open_sync (FP_DEVICE (sdcp_device), NULL, NULL);

  fpi_sdcp_device_get_connect_data (sdcp_device, &host_random, &host_public_key);

  g_assert (host_random);
  g_assert (g_bytes_get_size (host_random) == SDCP_RANDOM_SIZE);

  g_assert (host_public_key);
  g_assert (g_bytes_get_size (host_public_key) == SDCP_PUBLIC_KEY_SIZE);

  fpi_sdcp_device_connect_complete (sdcp_device, device_random, claim, connect_mac, error);

  fpi_sdcp_claim_free (claim);
}

static void
fpi_sdcp_device_fake_close (FpDevice *device)
{
  fpi_device_close_complete (device, NULL);
}

static void
fpi_sdcp_device_fake_open (FpSdcpDevice *sdcp_device)
{
  fpi_sdcp_device_open_complete (sdcp_device, NULL);
}

static void
fpi_sdcp_device_fake_init (FpiSdcpDeviceFake *self)
{
  G_DEBUG_HERE ();
}

static void
fpi_sdcp_device_fake_class_init (FpiSdcpDeviceFakeClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpSdcpDeviceClass *sdcp_dev_class = FP_SDCP_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Virtual SDCP test device";
  dev_class->type = FP_DEVICE_TYPE_VIRTUAL;
  dev_class->id_table = driver_ids;
  dev_class->nr_enroll_stages = 5;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  sdcp_dev_class->ignore_device_certificate = FALSE;
  sdcp_dev_class->ignore_device_signatures = FALSE;

  sdcp_dev_class->open = fpi_sdcp_device_fake_open;
  sdcp_dev_class->connect = fpi_sdcp_device_fake_connect;
  sdcp_dev_class->reconnect = fpi_sdcp_device_fake_reconnect;
  sdcp_dev_class->list = fpi_sdcp_device_fake_list;
  sdcp_dev_class->enroll = fpi_sdcp_device_fake_enroll;
  sdcp_dev_class->enroll_commit = fpi_sdcp_device_fake_enroll_commit;
  sdcp_dev_class->identify = fpi_sdcp_device_fake_identify;

  dev_class->close = fpi_sdcp_device_fake_close;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_STORAGE;
}
