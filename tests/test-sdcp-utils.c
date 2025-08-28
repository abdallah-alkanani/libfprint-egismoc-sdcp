/*
 * Secure Device Connection Protocol (SDCP) support test utils
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

#include "test-sdcp-utils.h"

static const guint8 from_hex_map[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,   // 01234567
  0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 89:;<=>?
  0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,         // @abcdef
};

GBytes *
g_bytes_from_hex (const gchar *hex)
{
  g_autoptr(GBytes) res = NULL;
  guint8 b0, b1;
  gsize bytes_len = strlen (hex) / 2;
  guint8 *bytes = g_malloc0 (bytes_len);

  for (int i = 0; i < strlen (hex) - 1; i += 2)
    {
      b0 = ((guint8) hex[i + 0] & 0x1F) ^ 0x10;
      b1 = ((guint8) hex[i + 1] & 0x1F) ^ 0x10;
      bytes[i / 2] = (guint8) (from_hex_map[b0] << 4) | from_hex_map[b1];
    }

  res = g_bytes_new_take (bytes, bytes_len);

  return g_steal_pointer (&res);
}

FpiSdcpClaim *
sdcp_test_claim (void)
{
  FpiSdcpClaim *claim = g_new0 (FpiSdcpClaim, 1);

  claim->model_certificate = g_bytes_from_hex (model_certificate_hex);
  claim->device_public_key = g_bytes_from_hex (device_public_key_hex);
  claim->firmware_public_key = g_bytes_from_hex (firmware_public_key_hex);
  claim->firmware_hash = g_bytes_from_hex (firmware_hash_hex);
  claim->model_signature = g_bytes_from_hex (model_signature_hex);
  claim->device_signature = g_bytes_from_hex (device_signature_hex);
  return g_steal_pointer (&claim);
}
