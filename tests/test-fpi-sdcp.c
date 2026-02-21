/*
 * Secure Device Connection Protocol (SDCP) support unit tests
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

#define FP_COMPONENT "test_fpi_sdcp"
#include "fpi-log.h"

#include "fpi-sdcp.h"
#include "fpi-sdcp-device.h"

/* We can re-use the device test payloads from virtual-sdcp */
#include "drivers/virtual-sdcp.h"

/* host keys used for the deterministic key exchange test */
static const gchar host_private_key_hex[] = "8400ed14579cdf11586477e836e8cb52708441c1c2a447c218c5bbc2d118fbc7";
static const gchar host_random_hex[]      = "d877403abe82f4d97e1448c5052d83a532a45e56ef049cbbf981137520e713bf";

/******************************************************************************/

static const guint8 from_hex_map[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,   // 01234567
  0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 89:;<=>?
  0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,         // @abcdef
};

static GBytes *
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

static FpiSdcpClaim *
get_fake_sdcp_claim (void)
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

/* Compute the connect MAC from the application secret and the fake device claim */
static GBytes *
compute_connect_mac (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(FpiSdcpClaim) claim = get_fake_sdcp_claim ();
  g_autoptr(GBytes) app_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) claim_hash = fpi_sdcp_hash_claim (claim, &error);

  g_assert_no_error (error);

  GBytes *mac = fpi_sdcp_mac (app_secret, FPI_SDCP_DEFAULT_LABEL_CONNECT, claim_hash, NULL, &error);

  g_assert_no_error (error);
  return mac;
}

/* Compute the enrollment ID from the application secret and fixed test nonce */
static GBytes *
compute_enrollment_id (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) app_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) nonce = g_bytes_from_hex (enrollment_nonce_hex);

  GBytes *id = fpi_sdcp_generate_enrollment_id (app_secret, NULL, nonce, &error);

  g_assert_no_error (error);
  return id;
}

/* Compute the identify MAC from the application secret, identify nonce, and enrollment ID */
static GBytes *
compute_identify_mac (GBytes *enrollment_id)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) app_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) nonce = g_bytes_from_hex (identify_nonce_hex);

  GBytes *mac = fpi_sdcp_mac (app_secret, FPI_SDCP_DEFAULT_LABEL_IDENTIFY, nonce, enrollment_id, &error);

  g_assert_no_error (error);
  return mac;
}

/* Compute the reconnect MAC from the application secret and a given random */
static GBytes *
compute_reconnect_mac (GBytes *random)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) app_secret = g_bytes_from_hex (application_secret_hex);

  GBytes *mac = fpi_sdcp_mac (app_secret, FPI_SDCP_DEFAULT_LABEL_RECONNECT, random, NULL, &error);

  g_assert_no_error (error);
  return mac;
}

/******************************************************************************/

static void
test_generate_enrollment_id (void)
{
  g_autoptr(GBytes) id = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) application_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) nonce = g_bytes_from_hex (enrollment_nonce_hex);
  g_autoptr(GBytes) expected_id = compute_enrollment_id ();

  id = fpi_sdcp_generate_enrollment_id (application_secret, NULL, nonce, &error);

  fp_dbg ("id:");
  fp_dbg_hex_dump_gbytes (id);

  fp_dbg ("expected:");
  fp_dbg_hex_dump_gbytes (expected_id);

  g_assert_cmpmem (g_bytes_get_data (expected_id, NULL), g_bytes_get_size (expected_id),
                   g_bytes_get_data (id, NULL), g_bytes_get_size (id));
  g_assert_no_error (error);
}

static void
test_verify_identify (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) application_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) nonce = g_bytes_from_hex (identify_nonce_hex);
  g_autoptr(GBytes) id = compute_enrollment_id ();
  g_autoptr(GBytes) mac = compute_identify_mac (id);

  g_assert_true (fpi_sdcp_verify_identify (application_secret, NULL, nonce, id, mac, &error));
  g_assert_no_error (error);
}

static void
test_verify_reconnect (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) application_secret = g_bytes_from_hex (application_secret_hex);
  g_autoptr(GBytes) random = fpi_sdcp_generate_random (&error);
  g_autoptr(GBytes) mac = compute_reconnect_mac (random);

  g_assert_no_error (error);
  g_assert_true (fpi_sdcp_verify_reconnect (application_secret, NULL, random, mac, &error));
  g_assert_no_error (error);
}

static void
test_verify_connect (void)
{
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GError) error = NULL;

  g_autoptr(GBytes) host_private_key = g_bytes_from_hex (host_private_key_hex);
  g_autoptr(GBytes) host_random = g_bytes_from_hex (host_random_hex);
  g_autoptr(GBytes) device_random = g_bytes_from_hex (device_random_hex);
  g_autoptr(GBytes) connect_mac = compute_connect_mac ();
  FpiSdcpClaim *claim = get_fake_sdcp_claim ();

  g_autoptr(GBytes) expected_application_secret = g_bytes_from_hex (application_secret_hex);

  g_assert_true (fpi_sdcp_verify_connect (host_private_key,
                                          host_random,
                                          device_random,
                                          claim,
                                          connect_mac,
                                          FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NO_CHECK_TIME,
                                          &application_secret,
                                          &error));

  g_assert_no_error (error);
  g_assert_cmpuint (g_bytes_get_size (application_secret), ==, FPI_SDCP_APPLICATION_SECRET_SIZE);

  fp_dbg ("application_secret:");
  fp_dbg_hex_dump_gbytes (application_secret);

  fp_dbg ("expected:");
  fp_dbg_hex_dump_gbytes (expected_application_secret);

  g_assert_cmpmem (g_bytes_get_data (expected_application_secret, NULL), g_bytes_get_size (expected_application_secret),
                   g_bytes_get_data (application_secret, NULL), g_bytes_get_size (application_secret));

  fpi_sdcp_claim_free (claim);
}

static void
test_generate_random (void)
{
  g_autoptr(GBytes) random = NULL;
  g_autoptr(GError) error = NULL;

  random = fpi_sdcp_generate_random (&error);

  g_assert_no_error (error);
  g_assert_nonnull (random);
  g_assert_cmpuint (g_bytes_get_size (random), ==, FPI_SDCP_RANDOM_SIZE);

  fp_dbg ("random:");
  fp_dbg_hex_dump_gbytes (random);
}

static void
test_generate_host_key (void)
{
  g_autoptr(GBytes) private_key = NULL;
  g_autoptr(GBytes) public_key = NULL;
  g_autoptr(GError) error = NULL;

  fpi_sdcp_generate_host_key (&private_key, &public_key, &error);

  g_assert_no_error (error);
  g_assert_nonnull (private_key);
  g_assert_cmpuint (g_bytes_get_size (private_key), ==, FPI_SDCP_PRIVATE_KEY_SIZE);

  fp_dbg ("private_key:");
  fp_dbg_hex_dump_gbytes (private_key);

  g_assert_nonnull (public_key);
  g_assert_cmpuint (g_bytes_get_size (public_key), ==, FPI_SDCP_PUBLIC_KEY_SIZE);

  fp_dbg ("public_key:");
  fp_dbg_hex_dump_gbytes (public_key);
}

static void
test_sdcp_mac (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) app_secret = NULL;
  g_autoptr(GBytes) enrollment_nonce = NULL;
  g_autoptr(GBytes) identify_nonce = NULL;
  g_autoptr(GBytes) reconnect_random = NULL;

  /*
   * Expected well-known output values derived from the test vectors above.
   * All are HMAC-SHA256 with key=application_secret_hex.
   *
   * Reproduce with (requires xxd + openssl):
   *
   *   APP_SECRET=13330ba3135ecf5dc71cede01a886540771efab35c8ba053902b2c1ee7de6efe
   *
   *   enrollment_id:
   *     { printf 'enroll\0'; echo -n $ENROLLMENT_NONCE | xxd -r -p; } | \
   *     openssl dgst -sha256 -mac HMAC -macopt hexkey:$APP_SECRET
   *
   *   connect_mac:
   *     { printf 'connect\0'; echo -n <SHA256_of_claim> | xxd -r -p; } | \
   *     openssl dgst -sha256 -mac HMAC -macopt hexkey:$APP_SECRET
   *
   *   reconnect_mac (using host_random_hex as the reconnect random):
   *     { printf 'reconnect\0'; echo -n $HOST_RANDOM | xxd -r -p; } | \
   *     openssl dgst -sha256 -mac HMAC -macopt hexkey:$APP_SECRET
   *
   *   identify_mac:
   *     { printf 'identify\0'; echo -n $IDENTIFY_NONCE<enrollment_id> | xxd -r -p; } | \
   *     openssl dgst -sha256 -mac HMAC -macopt hexkey:$APP_SECRET
   */
  static const gchar expected_connect_mac_hex[] =
    "587099769025b54ddbae2a7a2d9166b930929e6f0515433cf2e126f71e024cd4";
  static const gchar expected_enrollment_id_hex[] =
    "67109dc70a216331f1580ddac601915929c1ff6c9bcba6544ba572c660c3d91e";
  static const gchar expected_reconnect_mac_hex[] =
    "c0d080a246fc38cf113f64a615e576118828829624c22c054160d26ab2a89d7f";
  static const gchar expected_identify_mac_hex[] =
    "53a723eef40713094a90c5ef9996cbd6ba268e30676cd7107705a6c3e3e1eff9";

  app_secret = g_bytes_from_hex (application_secret_hex);
  enrollment_nonce = g_bytes_from_hex (enrollment_nonce_hex);
  identify_nonce = g_bytes_from_hex (identify_nonce_hex);

  /* Use host_random_hex as a fixed deterministic random for the reconnect test. */
  reconnect_random = g_bytes_from_hex (host_random_hex);

  /* enrollment ID: HMAC-SHA256(app_secret, "enroll\0" || enrollment_nonce) */
  g_autoptr(GBytes) enrollment_id = NULL;
  g_autoptr(GBytes) expected_enrollment_id = NULL;

  enrollment_id = fpi_sdcp_generate_enrollment_id (app_secret, NULL,
                                                   enrollment_nonce, &error);
  g_assert_no_error (error);
  expected_enrollment_id = g_bytes_from_hex (expected_enrollment_id_hex);
  g_assert_cmpmem (g_bytes_get_data (expected_enrollment_id, NULL),
                   g_bytes_get_size (expected_enrollment_id),
                   g_bytes_get_data (enrollment_id, NULL),
                   g_bytes_get_size (enrollment_id));

  /* connect MAC: HMAC-SHA256(app_secret, "connect\0" || SHA256(claim fields)) */
  g_autoptr(GBytes) connect_mac = NULL;
  g_autoptr(GBytes) expected_connect_mac = NULL;

  connect_mac  = compute_connect_mac ();
  expected_connect_mac = g_bytes_from_hex (expected_connect_mac_hex);
  g_assert_cmpmem (g_bytes_get_data (expected_connect_mac, NULL),
                   g_bytes_get_size (expected_connect_mac),
                   g_bytes_get_data (connect_mac, NULL),
                   g_bytes_get_size (connect_mac));

  /* reconnect MAC: HMAC-SHA256(app_secret, "reconnect\0" || reconnect_random) */
  g_autoptr(GBytes) reconnect_mac = NULL;
  g_autoptr(GBytes) expected_reconnect_mac = NULL;

  reconnect_mac = fpi_sdcp_mac (app_secret, FPI_SDCP_DEFAULT_LABEL_RECONNECT,
                                reconnect_random, NULL, &error);
  g_assert_no_error (error);
  expected_reconnect_mac = g_bytes_from_hex (expected_reconnect_mac_hex);
  g_assert_cmpmem (g_bytes_get_data (expected_reconnect_mac, NULL),
                   g_bytes_get_size (expected_reconnect_mac),
                   g_bytes_get_data (reconnect_mac, NULL),
                   g_bytes_get_size (reconnect_mac));

  /* identify MAC: HMAC-SHA256(app_secret, "identify\0" || identify_nonce || enrollment_id) */
  g_autoptr(GBytes) identify_mac = NULL;
  g_autoptr(GBytes) expected_identify_mac = NULL;

  identify_mac = fpi_sdcp_mac (app_secret, FPI_SDCP_DEFAULT_LABEL_IDENTIFY,
                               identify_nonce, enrollment_id, &error);
  g_assert_no_error (error);
  expected_identify_mac = g_bytes_from_hex (expected_identify_mac_hex);
  g_assert_cmpmem (g_bytes_get_data (expected_identify_mac, NULL),
                   g_bytes_get_size (expected_identify_mac),
                   g_bytes_get_data (identify_mac, NULL),
                   g_bytes_get_size (identify_mac));
}

static void
test_sdcp_mac_wrong_mac (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GBytes) reconnect_random = NULL;
  g_autoptr(GBytes) reconnect_mac = NULL;
  g_autoptr(GBytes) wrong_mac = NULL;
  g_autoptr(GBytes) nonce = NULL;
  g_autoptr(GBytes) id = NULL;
  g_autoptr(GBytes) identify_mac = NULL;

  application_secret = g_bytes_from_hex (application_secret_hex);

  /* reconnect: correct random but flipped first byte in the MAC */
  reconnect_random = g_bytes_from_hex (host_random_hex);
  reconnect_mac = compute_reconnect_mac (reconnect_random);

  const guint8 *mac_data = g_bytes_get_data (reconnect_mac, NULL);
  guint8 flipped[FPI_SDCP_MAC_SIZE];
  memcpy (flipped, mac_data, FPI_SDCP_MAC_SIZE);
  flipped[0] ^= 0xff;
  wrong_mac = g_bytes_new (flipped, FPI_SDCP_MAC_SIZE);

  g_assert_false (fpi_sdcp_verify_reconnect (application_secret, NULL,
                                             reconnect_random, wrong_mac, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
  g_clear_error (&error);

  /* identify: correct nonce + id but flipped first byte in the MAC */
  nonce = g_bytes_from_hex (identify_nonce_hex);
  id = compute_enrollment_id ();
  identify_mac = compute_identify_mac (id);

  const guint8 *id_mac_data = g_bytes_get_data (identify_mac, NULL);
  guint8 flipped_id[FPI_SDCP_MAC_SIZE];
  memcpy (flipped_id, id_mac_data, FPI_SDCP_MAC_SIZE);
  flipped_id[0] ^= 0xff;
  g_autoptr(GBytes) wrong_identify_mac = g_bytes_new (flipped_id, FPI_SDCP_MAC_SIZE);

  g_assert_false (fpi_sdcp_verify_identify (application_secret, NULL,
                                            nonce, id, wrong_identify_mac, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
}

static void
test_sdcp_mac_wrong_data (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) application_secret = NULL;
  g_autoptr(GBytes) reconnect_random = NULL;
  g_autoptr(GBytes) reconnect_mac = NULL;
  g_autoptr(GBytes) other_random = NULL;
  g_autoptr(GBytes) nonce = NULL;
  g_autoptr(GBytes) id = NULL;
  g_autoptr(GBytes) identify_mac = NULL;
  g_autoptr(GBytes) other_nonce = NULL;

  application_secret = g_bytes_from_hex (application_secret_hex);

  /* reconnect: MAC is correct for host_random but verified against a different random */
  reconnect_random = g_bytes_from_hex (host_random_hex);
  reconnect_mac = compute_reconnect_mac (reconnect_random);
  other_random = g_bytes_from_hex (enrollment_nonce_hex);

  g_assert_false (fpi_sdcp_verify_reconnect (application_secret, NULL,
                                             other_random, reconnect_mac, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
  g_clear_error (&error);

  /* identify: MAC is correct for identify_nonce but verified against enrollment_nonce */
  nonce = g_bytes_from_hex (identify_nonce_hex);
  id = compute_enrollment_id ();
  identify_mac = compute_identify_mac (id);
  other_nonce = g_bytes_from_hex (enrollment_nonce_hex);

  g_assert_false (fpi_sdcp_verify_identify (application_secret, NULL,
                                            other_nonce, id, identify_mac, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/sdcp/generate_host_key", test_generate_host_key);
  g_test_add_func ("/sdcp/generate_random", test_generate_random);
  g_test_add_func ("/sdcp/verify_connect", test_verify_connect);
  g_test_add_func ("/sdcp/verify_reconnect", test_verify_reconnect);
  g_test_add_func ("/sdcp/verify_identify", test_verify_identify);
  g_test_add_func ("/sdcp/generate_enrollment_id", test_generate_enrollment_id);
  g_test_add_func ("/sdcp/mac", test_sdcp_mac);
  g_test_add_func ("/sdcp/mac/wrong_mac", test_sdcp_mac_wrong_mac);
  g_test_add_func ("/sdcp/mac/wrong_data", test_sdcp_mac_wrong_data);

  return g_test_run ();
}
