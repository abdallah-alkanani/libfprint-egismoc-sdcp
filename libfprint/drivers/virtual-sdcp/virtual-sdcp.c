/*
 * Virtual driver for SDCP device debugging
 *
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

/*
 * This is a virtual driver to debug the SDCP-based drivers.
 * This virtual driver does not use a socket listener but instead
 * embeds the simulated logic of the fake "device" directly within
 * the logic of each function. This driver also allows prints to be
 * registered programmatically, making it possible to test libfprint
 * and fprintd.
 *
 * This virtual driver will override FpSdcpDevice's dynamically
 * generated cryptography values and instead replace them with
 * pre-generated values taken from from Microsoft's sample client
 * implementation. See:
 *   https://github.com/Microsoft/SecureDeviceConnectionProtocol
 */

#ifdef TEST_TOD_DRIVER
/* Use a distinct GType name to avoid colliding with the virtual_sdcp
 * type already registered inside libfprint.  The type_func prefix and
 * all generated helper names stay identical so no changes are required
 * in the function bodies below.  The _##TypeName token produced by
 * G_DECLARE_FINAL_TYPE undergoes rescan, so this alias is enough to
 * re-use the same underlying struct. */
#  define FP_COMPONENT "virtual_sdcp_tod_current"
#  define _FpDeviceVirtualSdcpTod _FpDeviceVirtualSdcp
#else
#  define FP_COMPONENT "virtual_sdcp"
#endif

#include "fpi-log.h"

#include "fpi-sdcp.h"
#include "fpi-sdcp-claim.h"

#include "virtual-sdcp.h"
#include "virtual-sdcp-ca-store-resource.h"
#include "virtual-sdcp-partial-chain-ca-store-resource.h"
#include "virtual-sdcp-full-chain-ca-store-resource.h"

struct _FpDeviceVirtualSdcp
{
  FpSdcpDevice parent;

  GPtrArray   *print_ids;
};

#ifdef TEST_TOD_DRIVER
G_DECLARE_FINAL_TYPE (FpDeviceVirtualSdcpTod, fpi_device_virtual_sdcp, FPI, DEVICE_VIRTUAL_SDCP, FpSdcpDevice)
G_DEFINE_TYPE (FpDeviceVirtualSdcpTod, fpi_device_virtual_sdcp, FP_TYPE_SDCP_DEVICE)
/* Alias old names so every function body below compiles unchanged. */
#  define FpDeviceVirtualSdcp FpDeviceVirtualSdcpTod
#  define FpDeviceVirtualSdcpClass FpDeviceVirtualSdcpTodClass
#else
G_DECLARE_FINAL_TYPE (FpDeviceVirtualSdcp, fpi_device_virtual_sdcp, FPI, DEVICE_VIRTUAL_SDCP, FpSdcpDevice)
G_DEFINE_TYPE (FpDeviceVirtualSdcp, fpi_device_virtual_sdcp, FP_TYPE_SDCP_DEVICE)
#endif

/******************************************************************************/

static const guint8 from_hex_map[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,   // 01234567
  0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 89:;<=>?
  0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,         // @abcdef
};

static GBytes *
bytes_from_hex (const gchar *hex)
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
get_fake_sdcp_claim (const gchar *certificate_hex)
{
  FpiSdcpClaim *claim = g_new0 (FpiSdcpClaim, 1);

  claim->model_certificate = bytes_from_hex (certificate_hex);
  claim->device_public_key = bytes_from_hex (device_public_key_hex);
  claim->firmware_public_key = bytes_from_hex (firmware_public_key_hex);
  claim->firmware_hash = bytes_from_hex (firmware_hash_hex);
  claim->model_signature = bytes_from_hex (model_signature_hex);
  claim->device_signature = bytes_from_hex (device_signature_hex);

  /* Allow tests to override any HMAC label in the claim.
   *
   * Open-phase labels (master_secret, application_keys, connect): the device
   * always computes using the default labels, so putting a different label in
   * the claim causes fpi_sdcp_verify_connect() to derive different keys /
   * verify the wrong MAC, leading to FP_DEVICE_ERROR_UNTRUSTED during open.
   *
   * Per-session labels (reconnect, enroll, identify): these are stored from
   * the claim during connect and used for subsequent operations.  A wrong
   * label causes the host-side recomputation to diverge from the device's
   * value, leading to FP_DEVICE_ERROR_UNTRUSTED in the affected operation.
   */
  claim->master_secret_label    = g_getenv ("FP_VIRTUAL_SDCP_MASTER_SECRET_LABEL");
  claim->application_keys_label = g_getenv ("FP_VIRTUAL_SDCP_APPLICATION_KEYS_LABEL");
  claim->connect_label          = g_getenv ("FP_VIRTUAL_SDCP_CONNECT_LABEL");
  claim->reconnect_label        = g_getenv ("FP_VIRTUAL_SDCP_RECONNECT_LABEL");
  claim->enroll_label           = g_getenv ("FP_VIRTUAL_SDCP_ENROLL_LABEL");
  claim->identify_label         = g_getenv ("FP_VIRTUAL_SDCP_IDENTIFY_LABEL");

  return g_steal_pointer (&claim);
}

/******************************************************************************/

static GBytes *
compute_connect_mac (FpiSdcpClaim *claim, GBytes *app_secret, GError **error)
{
  g_autoptr(GBytes) claim_hash = fpi_sdcp_claim_hash (claim, error);

  if (!claim_hash)
    return NULL;

  return fpi_sdcp_mac (app_secret, FPI_SDCP_DEFAULT_LABEL_CONNECT,
                       claim_hash, NULL, error);
}

static void
dev_identify (FpSdcpDevice *sdcp_device)
{
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (sdcp_device);

  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) app_secret = NULL;
  g_autoptr(GBytes) enroll_nonce = NULL;
  g_autoptr(GBytes) identify_nonce = NULL;
  g_autoptr(GBytes) enrollment_id = NULL;
  g_autoptr(GBytes) identify_mac = NULL;

  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);

  if (self->print_ids->len == 0)
    {
      fpi_sdcp_device_identify_complete (sdcp_device, NULL, NULL,
                                         fpi_device_error_new (FP_DEVICE_ERROR_DATA_NOT_FOUND));
      return;
    }

  /*
   * Pretend that the virtual device identified the first print.
   * Compute the enrollment ID and identify MAC at runtime from the
   * application secret and the fixed test nonces.
   */
  app_secret = fpi_sdcp_device_get_application_secret (sdcp_device);
  g_assert (app_secret);

  enroll_nonce = bytes_from_hex (enrollment_nonce_hex);
  identify_nonce = bytes_from_hex (identify_nonce_hex);

  enrollment_id = fpi_sdcp_generate_enrollment_id (app_secret, NULL, enroll_nonce, &error);
  if (!enrollment_id)
    {
      fpi_sdcp_device_identify_complete (sdcp_device, NULL, NULL, error);
      return;
    }

  identify_mac = fpi_sdcp_mac (app_secret, FPI_SDCP_DEFAULT_LABEL_IDENTIFY,
                               identify_nonce, enrollment_id, &error);
  if (!identify_mac)
    {
      fpi_sdcp_device_identify_complete (sdcp_device, NULL, NULL, error);
      return;
    }

  fpi_sdcp_device_set_identify_data (sdcp_device, g_steal_pointer (&identify_nonce));
  fpi_sdcp_device_identify_complete (sdcp_device, enrollment_id, identify_mac, NULL);
}

static void
dev_enroll_commit (FpSdcpDevice *sdcp_device, GBytes *id)
{
  g_autoptr(GBytes) print_id = NULL;
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (sdcp_device);

  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);

  print_id = g_bytes_new (g_bytes_get_data (id, NULL), g_bytes_get_size (id));

  /*
   * If this is the first print, verify the internal API assigned it the
   * expected ID derived from the enrollment nonce.
   */
  if (self->print_ids->len == 0)
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(GBytes) app_secret = NULL;
      g_autoptr(GBytes) nonce = NULL;
      g_autoptr(GBytes) expected_id = NULL;

      app_secret = fpi_sdcp_device_get_application_secret (sdcp_device);
      g_assert (app_secret);

      nonce = bytes_from_hex (enrollment_nonce_hex);
      expected_id = fpi_sdcp_generate_enrollment_id (app_secret, NULL,
                                                     nonce, &error);

      if (!expected_id)
        {
          fpi_sdcp_device_enroll_commit_complete (sdcp_device, error);
          return;
        }

      if (!g_bytes_equal (print_id, expected_id))
        {
          fpi_sdcp_device_enroll_commit_complete (sdcp_device,
                                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                                            "First enrolled print ID does not match expected value"));
          return;
        }
    }

  g_ptr_array_add (self->print_ids, g_steal_pointer (&print_id));

  fpi_sdcp_device_enroll_commit_complete (sdcp_device, NULL);
}

static void
dev_enroll (FpSdcpDevice *sdcp_device)
{
  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (sdcp_device);
  FpDevice *device = FP_DEVICE (sdcp_device);
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) nonce = NULL;
  FpPrint *print;

  fpi_device_get_enroll_data (device, &print);

  if (self->print_ids->len == 0)
    {
      /* Use the hard-coded nonce for the first enrollment */
      nonce = bytes_from_hex (enrollment_nonce_hex);
    }
  else
    {
      /* Generate a new nonce for all other enrollments */
      nonce = fpi_sdcp_generate_random (&error);
      if (error)
        fpi_device_enroll_progress (device, 0, print, error);
    }

  fpi_device_enroll_progress (device, 1, print, NULL);
  fpi_sdcp_device_enroll_commit (sdcp_device, nonce, error);
}

static void
dev_list (FpSdcpDevice *sdcp_device)
{
  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (sdcp_device);
  GPtrArray *print_ids = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);

  for (gint i = 0; i < self->print_ids->len; i++)
    {
      GBytes *print_id = g_ptr_array_index (self->print_ids, i);
      fp_dbg ("print %d:", i);
      fp_dbg_hex_dump_gbytes (print_id);
      g_ptr_array_add (print_ids, g_bytes_new (g_bytes_get_data (print_id, NULL),
                                               g_bytes_get_size (print_id)));
    }

  fpi_sdcp_device_list_complete (sdcp_device, g_steal_pointer (&print_ids), NULL);
}

static void
dev_clear_storage (FpDevice *device)
{
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (device);

  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);

  g_ptr_array_set_size (self->print_ids, 0);

  fpi_device_clear_storage_complete (device, NULL);
}

static void
dev_reconnect (FpSdcpDevice *sdcp_device)
{
  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) random = NULL;
  g_autoptr(GBytes) app_secret = NULL;
  g_autoptr(GBytes) reconnect_mac = NULL;

  /*
   * Normally, a driver would fetch the reconnect data and then send it to the
   * device's Reconnect command. In this fake device, we will just fetch and
   * verify the random was generated but do nothing with it
   */

  fpi_sdcp_device_get_reconnect_data (sdcp_device, &random);

  g_assert (random);
  g_assert (g_bytes_get_size (random) == FPI_SDCP_RANDOM_SIZE);

  app_secret = fpi_sdcp_device_get_application_secret (sdcp_device);
  g_assert (app_secret);

  reconnect_mac = fpi_sdcp_mac (app_secret, FPI_SDCP_DEFAULT_LABEL_RECONNECT,
                                random, NULL, &error);

  fpi_sdcp_device_reconnect_complete (sdcp_device, reconnect_mac, error);
}

static inline gboolean
use_expired_certificate (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_EXPIRED_CERTIFICATE"), "1") == 0;
}

static inline gboolean
allow_expired_certificate (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_ALLOW_EXPIRED_CERTIFICATE"), "1") == 0;
}

static inline gboolean
use_untrusted_certificate (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_UNTRUSTED_CERTIFICATE"), "1") == 0;
}

static inline gboolean
use_non_x509_strict_certificate (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_NON_X509_STRICT_CERTIFICATE"), "1") == 0;
}

static inline gboolean
use_non_x509_strict_verification (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_NON_X509_STRICT_VERIFICATION"), "1") == 0;
}

static inline gboolean
use_partial_chain_certificate (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CERTIFICATE"), "1") == 0;
}

static inline gboolean
use_partial_chain_ca_store (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_PARTIAL_CHAIN_CA_ONLY"), "1") == 0;
}

static inline gboolean
use_full_chain_ca_store (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_FULL_CHAIN_CA_STORE"), "1") == 0;
}

static inline gboolean
allow_partial_chain (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_ALLOW_PARTIAL_CHAIN"), "1") == 0;
}

static inline gboolean
use_deterministic_random (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_DETERMINISTIC"), "1") == 0;
}

/*
 * Perform device-side key exchange and derive the application secret.
 * Equivalent to ECDH(sk_f, pk_h) + KBKDF with host_random and device_random,
 * mirroring what the host computes via ECDH(sk_h, pk_f) + KBKDF.
 */
static GBytes *
derive_application_secret (GBytes  *host_public_key,
                           GBytes  *host_random,
                           GBytes  *device_random,
                           GError **error)
{
  g_autoptr(GBytes) firmware_private_key = bytes_from_hex (firmware_private_key_hex);
  g_autoptr(GBytes) key_agreement = NULL;
  g_autoptr(GBytes) master_secret = NULL;
  g_autoptr(GBytes) application_keys = NULL;

  key_agreement = fpi_sdcp_key_agreement (firmware_private_key, host_public_key, error);
  if (!key_agreement)
    return NULL;

  master_secret = fpi_sdcp_kdf (key_agreement,
                                FPI_SDCP_DEFAULT_LABEL_MASTER_SECRET,
                                host_random, device_random,
                                FPI_SDCP_MASTER_SECRET_SIZE, error);
  if (!master_secret)
    return NULL;

  application_keys = fpi_sdcp_kdf (master_secret,
                                   FPI_SDCP_DEFAULT_LABEL_APPLICATION_KEYS,
                                   NULL, NULL,
                                   FPI_SDCP_APPLICATION_KEYS_SIZE, error);
  if (!application_keys)
    return NULL;

  return g_bytes_new_from_bytes (application_keys, 0, FPI_SDCP_APPLICATION_SECRET_SIZE);
}

static void
dev_connect (FpSdcpDevice *sdcp_device)
{
  FpSdcpDeviceClass *sdcp_cls = FP_SDCP_DEVICE_GET_CLASS (sdcp_device);
  FpiDeviceSdcpVerificationFlags old_flags;

  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) host_random = NULL;
  g_autoptr(GBytes) host_public_key = NULL;
  g_autoptr(GBytes) device_random = NULL;
  g_autoptr(GBytes) app_secret = NULL;
  g_autoptr(GBytes) connect_mac = NULL;
  g_autoptr(FpiSdcpClaim) claim = NULL;
  const gchar *model_certificate;

  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);

  fpi_sdcp_device_get_connect_data (sdcp_device, &host_random, &host_public_key);

  g_assert (host_random);
  g_assert (g_bytes_get_size (host_random) == FPI_SDCP_RANDOM_SIZE);

  g_assert (host_public_key);
  g_assert (g_bytes_get_size (host_public_key) == FPI_SDCP_PUBLIC_KEY_SIZE);

  /* Use the fixed device_random_hex in deterministic mode, otherwise generate a fresh one */
  if (use_deterministic_random ())
    {
      device_random = bytes_from_hex (device_random_hex);
    }
  else if (!(device_random = fpi_sdcp_generate_random (&error)))
    {
      fpi_sdcp_device_connect_complete (sdcp_device, NULL, NULL, NULL, error);
      return;
    }

  /*
   * Device-side key exchange: ECDH(sk_f, pk_h) + KDF -> application_secret.
   * The host will compute the identical value via ECDH(sk_h, pk_f) + KDF, so
   * the two sides will arrive at the same application_secret independently.
   */
  app_secret = derive_application_secret (host_public_key, host_random, device_random, &error);
  if (!app_secret)
    {
      fpi_sdcp_device_connect_complete (sdcp_device, NULL, NULL, NULL, error);
      return;
    }

  if (use_expired_certificate ())
    model_certificate = expired_model_certificate_hex;
  else if (use_non_x509_strict_certificate ())
    model_certificate = non_x509_strict_model_certificate_hex;
  else if (use_partial_chain_certificate ())
    model_certificate = partial_chain_model_certificate_hex;
  else
    model_certificate = model_certificate_hex;

  claim = get_fake_sdcp_claim (model_certificate);
  connect_mac = compute_connect_mac (claim, app_secret, &error);

  old_flags = sdcp_cls->verification_flags;
  if (connect_mac && use_expired_certificate () && allow_expired_certificate ())
    sdcp_cls->verification_flags |=
      FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NO_CHECK_TIME;
  if (connect_mac && use_non_x509_strict_verification ())
    sdcp_cls->verification_flags |=
      FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NON_X509_STRICT;
  if (connect_mac && allow_partial_chain ())
    sdcp_cls->verification_flags |=
      FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_ALLOW_PARTIAL_CHAIN;

  fpi_sdcp_device_connect_complete (sdcp_device, device_random, claim, connect_mac, error);
  sdcp_cls->verification_flags = old_flags;
}

static GResource *
dev_get_ca_store (FpSdcpDevice *sdcp_device)
{
  if (use_untrusted_certificate ())
    {
      fp_dbg ("FP_VIRTUAL_SDCP_UNTRUSTED_CERTIFICATE is set; not providing CA store.");
      return NULL;
    }

  if (use_partial_chain_ca_store ())
    return fpi_virtual_sdcp_partial_chain_ca_store_get_resource ();

  if (use_full_chain_ca_store ())
    return fpi_virtual_sdcp_full_chain_ca_store_get_resource ();

  return fpi_virtual_sdcp_ca_store_get_resource ();
}

static void
dev_close (FpDevice *device)
{
  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);
  fpi_device_close_complete (device, NULL);
}

static inline gboolean
is_reconnect_supported (void)
{
  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_NO_RECONNECT"), "1") != 0;
}

static void
dev_open (FpSdcpDevice *sdcp_device)
{
  void (*old_reconnect)(FpSdcpDevice *sdcp_device) = dev_reconnect;

  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);

  if (!is_reconnect_supported ())
    {
      fp_dbg ("FP_VIRTUAL_SDCP_NO_RECONNECT is set.");

      /* FIXME: Ideally we should use another sub-device for this  */
      old_reconnect = g_steal_pointer (
        &FP_SDCP_DEVICE_GET_CLASS (sdcp_device)->reconnect);
    }

  fpi_sdcp_device_open_complete (sdcp_device, NULL);

  if (!is_reconnect_supported ())
    FP_SDCP_DEVICE_GET_CLASS (sdcp_device)->reconnect = old_reconnect;
}

static void
fpi_device_virtual_sdcp_finalize (GObject *object)
{
  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (object);

  g_clear_pointer (&self->print_ids, g_ptr_array_unref);

  G_OBJECT_CLASS (fpi_device_virtual_sdcp_parent_class)->finalize (object);
}

static void
fpi_device_virtual_sdcp_init (FpDeviceVirtualSdcp *self)
{
  static gsize initialized = FALSE;

  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);

  if (g_once_init_enter (&initialized))
    {
      fpi_virtual_sdcp_ca_store_register_resource ();
      fpi_virtual_sdcp_partial_chain_ca_store_register_resource ();
      fpi_virtual_sdcp_full_chain_ca_store_register_resource ();

      g_once_init_leave (&initialized, TRUE);
    }

  self->print_ids = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
}

static const FpIdEntry driver_ids[] = {
#ifdef TEST_TOD_DRIVER
  /* Use a dedicated env var so that the TOD module does not conflict with
   * the built-in virtual_sdcp driver (both are present in the test process). */
  { .virtual_envvar = "FP_VIRTUAL_SDCP_TOD" },
#else
  { .virtual_envvar = "FP_VIRTUAL_SDCP" },
#endif
  { .virtual_envvar = NULL }
};

static void
fpi_device_virtual_sdcp_class_init (FpDeviceVirtualSdcpClass *klass)
{
  fp_dbg ("Virtual SDCP device: %s()", G_STRFUNC);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpSdcpDeviceClass *sdcp_dev_class = FP_SDCP_DEVICE_CLASS (klass);
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = fpi_device_virtual_sdcp_finalize;

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Virtual SDCP device for debugging";
  dev_class->type = FP_DEVICE_TYPE_VIRTUAL;
  dev_class->id_table = driver_ids;
  dev_class->nr_enroll_stages = 1;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->clear_storage = dev_clear_storage;

  sdcp_dev_class->verification_flags = FPI_DEVICE_SDCP_VERIFICATION_DEFAULT;

  sdcp_dev_class->open = dev_open;
  sdcp_dev_class->connect = dev_connect;
  sdcp_dev_class->reconnect = dev_reconnect;
  sdcp_dev_class->list = dev_list;
  sdcp_dev_class->enroll = dev_enroll;
  sdcp_dev_class->enroll_commit = dev_enroll_commit;
  sdcp_dev_class->identify = dev_identify;
  sdcp_dev_class->get_ca_store = dev_get_ca_store;

  if (!is_reconnect_supported ())
    sdcp_dev_class->reconnect = NULL;

  dev_class->close = dev_close;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_STORAGE;
}
