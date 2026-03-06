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
#include "fpi-sdcp-claim.h"
#include "fpi-sdcp-device.h"

/* We can re-use the device test payloads from virtual-sdcp */
#include "drivers/virtual-sdcp/virtual-sdcp.h"

/*
 * Fixed host key material used for the deterministic key exchange test.
 *
 * host_private_key_hex is a P-256 private key scalar.
 * To generate a new one:
 *   openssl ecparam -name prime256v1 -genkey -noout -out key.pem
 *   openssl ec -in key.pem -noout -text
 *
 * host_random_hex is 32 random bytes. They can be generated with:
 *   openssl rand -hex 32
 *
 * After changing either value, recompute application_secret_hex and all
 * expected MAC / key-derivation values - see test_sdcp_key_derivation() for
 * the openssl KBKDF commands, and the MAC comment block in test_sdcp_mac()
 * for the openssl HMAC commands.
 */
static const gchar host_private_key_hex[] = "8400ed14579cdf11586477e836e8cb52708441c1c2a447c218c5bbc2d118fbc7";
static const gchar host_random_hex[]      = "d877403abe82f4d97e1448c5052d83a532a45e56ef049cbbf981137520e713bf";

/*
 * Application secret derived from: ECDH(sk_h=8400ed14, pk_f) then KBKDF.
 * The device side computes the same value via ECDH(sk_f=1bdd42b6, pk_h) + KBKDF,
 * using device_random_hex from virtual-sdcp.h as the device-side random.
 *
 * See test_sdcp_key_derivation() for the openssl commands to reproduce this value.
 */
static const gchar application_secret_hex[] = "81cbe5d02ad5185b2296a10a6f951b12cdb580e4cf7db4ed7207a17d62a364f6";

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
  g_autoptr(GBytes) claim_hash = fpi_sdcp_claim_hash (claim, &error);

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
   *   APP_SECRET=81cbe5d02ad5185b2296a10a6f951b12cdb580e4cf7db4ed7207a17d62a364f6
   *   ENROLLMENT_NONCE=c2101c44c9a667bba397e81f48b143398603e2c9335a68b409e1dbe71e005ca2
   *   IDENTIFY_NONCE=3a1b506f5bec089059acefb9b44dfbdea7a599ee9aa267e5252664d60b798053
   *   HOST_RANDOM=d877403abe82f4d97e1448c5052d83a532a45e56ef049cbbf981137520e713bf
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
    "947bd3aff9c3522dd6510f06d529c2a6e3acc6d9bd89443dd9e3a315d66d32cb";
  static const gchar expected_enrollment_id_hex[] =
    "0b93a18533dc49c514a15a886bdb1d92970291800733ebcfc2db689a9344e6eb";
  static const gchar expected_reconnect_mac_hex[] =
    "2c368ca59c62863d9c8538c6ee1405a618f4c5dc6d32c08d8ca47e3a814786b7";
  static const gchar expected_identify_mac_hex[] =
    "f61d12e1b4d8b0fcafe73839028c51ee3c73c91ebf37130b2e8176faa79ee835";

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

/*
 * Tests the full SDCP key derivation chain:
 *   ECDH(sk_h, pk_f) -> key_agreement
 *   KBKDF(key_agreement, "master secret", r_h||r_d, 32) -> master_secret
 *   KBKDF(master_secret, "application keys", NULL, 64) -> s (first 32) + k (last 32)
 *
 * All expected values were derived using the test key material (sk_h, pk_f, r_h, r_d)
 * from virtual-sdcp.h and verified with openssl command line.
 *
 * Reproduce with openssl (label hex: "master secret"=6d617374657220736563726574,
 * "application keys"=6170706c69636174696f6e206b657973):
 *
 *   SK_H=8400ed14579cdf11586477e836e8cb52708441c1c2a447c218c5bbc2d118fbc7
 *   R_H=d877403abe82f4d97e1448c5052d83a532a45e56ef049cbbf981137520e713bf
 *   R_D=353eb43ffb422fc96c857140d5c399d588feef46f62bd363b97c823975bb27e7
 *   KEY_AGREEMENT=10babb6a23f0c8041ece41c18af1f6aaf9d1e311aedb2afc18bc72c8b05995d7
 *
 *   master_secret:
 *     openssl kdf -keylen 32 -kdfopt mode:counter -kdfopt mac:HMAC \
 *       -kdfopt digest:SHA2-256 -kdfopt hexkey:$KEY_AGREEMENT \
 *       -kdfopt hexsalt:6d617374657220736563726574 \
 *       -kdfopt hexinfo:${R_H}${R_D} KBKDF
 *
 *   application_keys (s = first 32 bytes, k = last 32 bytes):
 *     openssl kdf -keylen 64 -kdfopt mode:counter -kdfopt mac:HMAC \
 *       -kdfopt digest:SHA2-256 -kdfopt hexkey:<master_secret> \
 *       -kdfopt hexsalt:6170706c69636174696f6e206b657973 KBKDF
 *
 * Note: the Microsoft SDCP README ships example ms/s/k values seems to be
 * inconsistent (maybe printed from different test runs?).
 */
static void
test_sdcp_key_derivation (void)
{
  g_autoptr(GBytes) sk_h = NULL;
  g_autoptr(GBytes) pk_f = NULL;
  g_autoptr(GBytes) key_agreement = NULL;
  g_autoptr(GBytes) expected_key_agreement = NULL;
  g_autoptr(GBytes) r_h = NULL;
  g_autoptr(GBytes) r_d = NULL;
  g_autoptr(GBytes) master_secret = NULL;
  g_autoptr(GBytes) expected_master_secret = NULL;
  g_autoptr(GBytes) app_keys = NULL;
  g_autoptr(GBytes) expected_s = NULL;
  g_autoptr(GBytes) expected_k = NULL;
  g_autoptr(GError) error = NULL;

  /* Step 1: ECDH(sk_h, pk_f) */
  sk_h = g_bytes_from_hex (host_private_key_hex);
  pk_f = g_bytes_from_hex (firmware_public_key_hex);

  static const gchar expected_key_agreement_hex[] =
    "10babb6a23f0c8041ece41c18af1f6aaf9d1e311aedb2afc18bc72c8b05995d7";

  key_agreement = fpi_sdcp_key_agreement (sk_h, pk_f, &error);
  g_assert_no_error (error);
  g_assert_nonnull (key_agreement);
  g_assert_cmpuint (g_bytes_get_size (key_agreement), ==, 32);

  expected_key_agreement = g_bytes_from_hex (expected_key_agreement_hex);
  g_assert_cmpmem (g_bytes_get_data (expected_key_agreement, NULL),
                   g_bytes_get_size (expected_key_agreement),
                   g_bytes_get_data (key_agreement, NULL),
                   g_bytes_get_size (key_agreement));

  /* Step 2: KBKDF(key_agreement, "master secret", r_h || r_d, 32) */
  r_h = g_bytes_from_hex (host_random_hex);
  r_d = g_bytes_from_hex (device_random_hex);

  static const gchar expected_master_secret_hex[] =
    "a03cfaac987eba1184a60286560d4840f93841283e38c7f5ed51e1feaac6d791";

  master_secret = fpi_sdcp_kdf (key_agreement,
                                FPI_SDCP_DEFAULT_LABEL_MASTER_SECRET,
                                r_h, r_d,
                                FPI_SDCP_APPLICATION_SECRET_SIZE,
                                &error);
  g_assert_no_error (error);
  g_assert_nonnull (master_secret);

  expected_master_secret = g_bytes_from_hex (expected_master_secret_hex);
  g_assert_cmpmem (g_bytes_get_data (expected_master_secret, NULL),
                   g_bytes_get_size (expected_master_secret),
                   g_bytes_get_data (master_secret, NULL),
                   g_bytes_get_size (master_secret));

  /* Step 3: KBKDF(master_secret, "application keys", NULL, 64) -> s + k */
  static const gchar expected_application_key_k_hex[] =
    "af72d32f17ca8d1a7ae6755881fd5e742f1c0ad1ce8f0e9d60cc61949c3fc1e3";

  app_keys = fpi_sdcp_kdf (master_secret,
                           FPI_SDCP_DEFAULT_LABEL_APPLICATION_KEYS,
                           NULL, NULL,
                           2 * FPI_SDCP_APPLICATION_SECRET_SIZE,
                           &error);
  g_assert_no_error (error);
  g_assert_nonnull (app_keys);
  g_assert_cmpuint (g_bytes_get_size (app_keys), ==, 2 * FPI_SDCP_APPLICATION_SECRET_SIZE);

  const guint8 *app_keys_data = g_bytes_get_data (app_keys, NULL);

  /* First 32 bytes == s (application secret) */
  expected_s = g_bytes_from_hex (application_secret_hex);
  g_assert_cmpmem (g_bytes_get_data (expected_s, NULL), FPI_SDCP_APPLICATION_SECRET_SIZE,
                   app_keys_data, FPI_SDCP_APPLICATION_SECRET_SIZE);

  /* Last 32 bytes == k (encryption key) */
  expected_k = g_bytes_from_hex (expected_application_key_k_hex);
  g_assert_cmpmem (g_bytes_get_data (expected_k, NULL), FPI_SDCP_APPLICATION_SECRET_SIZE,
                   app_keys_data + FPI_SDCP_APPLICATION_SECRET_SIZE,
                   FPI_SDCP_APPLICATION_SECRET_SIZE);
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

  g_assert_true (fpi_sdcp_verify_identify (application_secret, NULL,
                                           nonce, id, identify_mac, &error));
  g_assert_no_error (error);

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
  g_test_add_func ("/sdcp/key_derivation", test_sdcp_key_derivation);
  g_test_add_func ("/sdcp/verify_connect", test_verify_connect);
  g_test_add_func ("/sdcp/verify_reconnect", test_verify_reconnect);
  g_test_add_func ("/sdcp/verify_identify", test_verify_identify);
  g_test_add_func ("/sdcp/generate_enrollment_id", test_generate_enrollment_id);
  g_test_add_func ("/sdcp/mac", test_sdcp_mac);
  g_test_add_func ("/sdcp/mac/wrong_mac", test_sdcp_mac_wrong_mac);
  g_test_add_func ("/sdcp/mac/wrong_data", test_sdcp_mac_wrong_data);

  return g_test_run ();
}
