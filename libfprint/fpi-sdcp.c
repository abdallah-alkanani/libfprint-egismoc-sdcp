/*
 * Secure Device Connection Protocol (SDCP) support implementation
 * Copyright (C) 2025 Joshua Grisham <josh@joshuagrisham.com>
 * Copyright (C) 2026 Marco Trevisan <marco.trevisan@canonical.com>
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

#define FP_COMPONENT "sdcp"
#include "fpi-log.h"

#include "fpi-sdcp.h"
#include "fpi-sdcp-claim.h"
#include "sdcp/fpi-sdcp-ca-store-resource.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdarg.h>

#define SDCP_KEY_AGREEMENT_SIZE 32

#define SDCP_DEVICE_SIGNATURE_HEADER "\xC0\x01"

G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_PKEY, EVP_PKEY_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_PKEY_CTX, EVP_PKEY_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_MD_CTX, EVP_MD_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_MAC, EVP_MAC_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_MAC_CTX, EVP_MAC_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_KDF, EVP_KDF_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_KDF_CTX, EVP_KDF_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (X509, X509_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (X509_STORE, X509_STORE_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (X509_STORE_CTX, X509_STORE_CTX_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (BIGNUM, BN_clear_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (OSSL_PARAM_BLD, OSSL_PARAM_BLD_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (OSSL_PARAM, OSSL_PARAM_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (BIO, BIO_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ECDSA_SIG, ECDSA_SIG_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EC_GROUP, EC_GROUP_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EC_POINT, EC_POINT_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ASN1_OBJECT, ASN1_OBJECT_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free)

/******************************************************************************/

GError * G_GNUC_PRINTF (2, 3)
fpi_sdcp_error_new_msg (FpDeviceError error_code,
                        const gchar   * format,
                        ...)
{
  va_list args;
  g_autofree gchar *msg = NULL;
  gulong openssl_err;

  va_start (args, format);
  msg = g_strdup_vprintf (format, args);
  va_end (args);

  openssl_err = ERR_get_error ();
  if (openssl_err != 0)
    {
      char openssl_buf[256];

      ERR_error_string_n (openssl_err, openssl_buf, sizeof (openssl_buf));
      ERR_clear_error ();

      return g_error_new (FP_DEVICE_ERROR, error_code, "%s: %s", msg, openssl_buf);
    }

  return g_error_new_literal (FP_DEVICE_ERROR, error_code, msg);
}

static void
print_certificate (X509 *certificate)
{
  if (g_log_writer_default_would_drop (G_LOG_LEVEL_DEBUG, G_LOG_DOMAIN))
    return;

  g_autoptr(BIO) bio = BIO_new (BIO_s_mem ());
  BUF_MEM *bio_mem = NULL;

  X509_print (bio, certificate);
  BIO_get_mem_ptr (bio, &bio_mem);
  fp_dbg ("SDCP Device reported the following model certificate:\n%.*s\n",
          (int) bio_mem->length, bio_mem->data);
}

typedef struct
{
  void *ptr;
  gsize size;
} FpiSdcpDestroyData;

static void
fpi_sdcp_secure_destroy_notify (gpointer destroy_data)
{
  g_autofree FpiSdcpDestroyData *d = destroy_data;

  OPENSSL_cleanse (d->ptr, d->size);
  g_free (d->ptr);
}

static GBytes *
fpi_sdcp_bytes_new_secure_take (void *buf, gsize size)
{
  FpiSdcpDestroyData *d;

  d = g_new0 (FpiSdcpDestroyData, 1);
  d->ptr = buf;
  d->size = size;

  return g_bytes_new_with_free_func (buf, size, fpi_sdcp_secure_destroy_notify, d);
}

/******************************************************************************/

static inline void
fpi_openssl_free_wrapper (void *ptr)
{
  /* This is a macro, so we cannot use it as callback. */
  OPENSSL_free (ptr);
}

/* Convert a raw 64-byte IEEE P1363 ECDSA signature (r||s) to DER, which is
 * what OpenSSL's EVP_DigestVerifyFinal() requires for EC keys. */
static GBytes *
raw_ecdsa_sig_to_der (GBytes  *raw_sig,
                      GError **error)
{
  g_autoptr(ECDSA_SIG) sig = NULL;
  g_autoptr(BIGNUM) r = NULL;
  g_autoptr(BIGNUM) s = NULL;
  const guint8 *data;
  gsize len;
  guint8 *der;
  int der_len;

  data = g_bytes_get_data (raw_sig, &len);

  if (len != FPI_SDCP_SIGNATURE_SIZE)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                 "Invalid ECDSA signature size: "
                                                 "expected %d bytes, got %zu",
                                                 FPI_SDCP_SIGNATURE_SIZE, len));
      return NULL;
    }

  sig = ECDSA_SIG_new ();
  if (!sig)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "OpenSSL error allocating ECDSA signature"));
      return NULL;
    }

  r = BN_bin2bn (data, FPI_SDCP_SIGNATURE_SIZE / 2, NULL);
  s = BN_bin2bn (data + FPI_SDCP_SIGNATURE_SIZE / 2,
                 FPI_SDCP_SIGNATURE_SIZE / 2, NULL);

  if (!r || !s)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "OpenSSL error parsing ECDSA signature "
                                                 "components (r, s)"));
      return NULL;
    }

  /* ECDSA_SIG_set0 takes ownership of r and s on success */
  if (!ECDSA_SIG_set0 (sig, r, s))
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "OpenSSL error setting ECDSA signature "
                                                 "components (r, s)"));
      return NULL;
    }

  /* ECDSA_SIG now owns r and s; steal to prevent autoptr double-free */
  g_steal_pointer (&r);
  g_steal_pointer (&s);

  der = NULL;
  der_len = i2d_ECDSA_SIG (sig, &der);

  if (der_len <= 0)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "OpenSSL error encoding ECDSA signature "
                                                 "to DER"));
      return NULL;
    }

  return g_bytes_new_with_free_func (der, der_len, fpi_openssl_free_wrapper, der);
}

static gboolean
fpi_sdcp_verify_signature (EVP_PKEY    *pkey,
                           const gchar *label,
                           GBytes      *data_a,
                           GBytes      *data_b,
                           GBytes      *signature,
                           GError     **error)
{
  g_autoptr(GBytes) der_sig = NULL;
  g_autoptr(EVP_MD_CTX) mdctx = NULL;
  int verify_result;

  /* SDCP signatures are raw 64-byte (r||s); convert to DER for OpenSSL */
  der_sig = raw_ecdsa_sig_to_der (signature, error);
  if (!der_sig)
    {
      g_prefix_error (error, "Failed to convert signature for label '%s': ", label);
      return FALSE;
    }

  mdctx = EVP_MD_CTX_new ();

  /* Let EVP_DigestVerifyInit create and own the pctx internally */
  if (!EVP_DigestVerifyInit (mdctx, NULL, EVP_sha256 (), NULL, pkey))
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "Failed to initialize digest verification "
                                                 "for label '%s'",
                                                 label));
      return FALSE;
    }

  if (label)
    {
      if (!EVP_DigestVerifyUpdate (mdctx, label, strlen (label)))
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "Failed to update digest with label '%s'",
                                                     label));
          return FALSE;
        }
    }

  if (data_a)
    {
      if (!EVP_DigestVerifyUpdate (mdctx,
                                   g_bytes_get_data (data_a, NULL),
                                   g_bytes_get_size (data_a)))
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "Failed to update digest with data_a "
                                                     "for label '%s'",
                                                     label));
          return FALSE;
        }
    }

  if (data_b)
    {
      if (!EVP_DigestVerifyUpdate (mdctx,
                                   g_bytes_get_data (data_b, NULL),
                                   g_bytes_get_size (data_b)))
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "Failed to update digest with data_b "
                                                     "for label '%s'",
                                                     label));
          return FALSE;
        }
    }

  verify_result = EVP_DigestVerifyFinal (mdctx,
                                         g_bytes_get_data (der_sig, NULL),
                                         g_bytes_get_size (der_sig));
  if (verify_result == 0)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                 "Signature verification failed for label '%s'",
                                                 label));
      return FALSE;
    }

  if (verify_result != 1)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "OpenSSL error finalizing signature verification "
                                                 "for label '%s'",
                                                 label));
      return FALSE;
    }

  return TRUE;
}

static gboolean
fpi_sdcp_load_ca_certs_from_resource (X509_STORE  *ca_store,
                                      GResource   *resource,
                                      const gchar *resource_path,
                                      GError     **error)
{
  g_autoptr(GError) local_error = NULL;
  g_auto(GStrv) ca_cert_names = NULL;
  const gchar *ca_cert_ptr;
  gsize ca_cert_len = 0;

  ca_cert_names = g_resource_enumerate_children (resource,
                                                 resource_path,
                                                 G_RESOURCE_LOOKUP_FLAGS_NONE,
                                                 &local_error);

  if (!ca_cert_names || *ca_cert_names == NULL)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "Error loading SDCP ca_store certificates: %s",
                                                 local_error->message));
      return FALSE;
    }

  for (int i = 0; ca_cert_names[i]; i++)
    {
      g_autoptr(GBytes) ca_cert_gb = NULL;
      g_autofree gchar *ca_cert_path = NULL;
      g_autoptr(BIO) bio = NULL;
      g_autoptr(X509) ca_cert = NULL;

      fp_dbg ("Adding certificate to SDCP ca_store: %s", ca_cert_names[i]);
      ca_cert_path = g_strconcat (resource_path, ca_cert_names[i], NULL);
      ca_cert_gb = g_resource_lookup_data (resource,
                                           ca_cert_path, 0,
                                           &local_error);
      if (!ca_cert_gb)
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "Error loading SDCP ca_store "
                                                     "certificate '%s': %s",
                                                     ca_cert_names[i],
                                                     local_error->message));
          return FALSE;
        }

      ca_cert_ptr = g_bytes_get_data (ca_cert_gb, &ca_cert_len);

      bio = BIO_new (BIO_s_mem ());
      if (BIO_write (bio, ca_cert_ptr, ca_cert_len) != ca_cert_len)
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "Failed reading '%s' to buffer",
                                                     ca_cert_names[i]));
          return FALSE;
        }

      ca_cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
      //print_certificate (ca_cert);
      if (!X509_STORE_add_cert (ca_store, ca_cert))
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "Failed adding '%s' to X509 store",
                                                     ca_cert_names[i]));
          return FALSE;
        }
    }

  return TRUE;
}

static X509_STORE *
fpi_sdcp_build_ca_store (GResource *additional_ca_store,
                         GError   **error)
{
  g_autoptr(X509_STORE) ca_store = NULL;
  GResource *default_resource = NULL;

  ca_store = X509_STORE_new ();
  if (!ca_store)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "Failed initializing SDCP X509 certificate store"));
      return NULL;
    }

  default_resource = fpi_sdcp_ca_store_get_resource ();

  if (!fpi_sdcp_load_ca_certs_from_resource (ca_store,
                                             default_resource,
                                             FPI_SDCP_CA_STORE_PATH,
                                             error))
    return NULL;

  if (additional_ca_store)
    {
      if (!fpi_sdcp_load_ca_certs_from_resource (ca_store,
                                                 additional_ca_store,
                                                 FPI_SDCP_CA_STORE_PATH,
                                                 error))
        return NULL;
    }

  return g_steal_pointer (&ca_store);
}

static X509_STORE *
fpi_sdcp_get_ca_store (GResource *additional_ca_store,
                       GError   **error)
{
  static X509_STORE *default_ca_store = NULL;

  /* When a driver provides its own CA store, we build a fresh combined
   * ca_store each time since the result is driver-specific. */
  if (additional_ca_store)
    return fpi_sdcp_build_ca_store (additional_ca_store, error);

  if (g_once_init_enter_pointer (&default_ca_store))
    {
      g_once_init_leave_pointer (&default_ca_store,
                                 fpi_sdcp_build_ca_store (NULL, error));
      g_return_val_if_fail (default_ca_store != NULL, NULL);
    }

  X509_STORE_up_ref (default_ca_store);
  return default_ca_store;
}

/* Present in the real Microsoft-issued model certificates in the Egis replay
 * and tests/sdcp-hello-model-cert.pem. Drivers opt into this purpose policy. */
static gboolean
fpi_sdcp_check_biometric_eku (X509    *cert,
                              gboolean leaf,
                              GError **error)
{
  g_autoptr(ASN1_OBJECT) biometric_oid = OBJ_txt2obj ("1.3.6.1.4.1.311.76.43.1", 1);
  g_autoptr(EXTENDED_KEY_USAGE) usage = NULL;
  int critical = -1;

  usage = X509_get_ext_d2i (cert, NID_ext_key_usage, &critical, NULL);

  /* A CA without an EKU is unrestricted. A model certificate must explicitly
   * assert the biometric purpose and must not itself be a CA. */
  if (!leaf && !usage && critical == -1)
    return TRUE;

  if (biometric_oid && usage && (!leaf || X509_check_ca (cert) == 0))
    {
      for (int i = 0; i < sk_ASN1_OBJECT_num (usage); i++)
        {
          ASN1_OBJECT *oid = sk_ASN1_OBJECT_value (usage, i);

          if (OBJ_cmp (oid, biometric_oid) == 0 ||
              (!leaf && OBJ_obj2nid (oid) == NID_anyExtendedKeyUsage))
            return TRUE;
        }
    }

  g_propagate_error (error,
                     fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                             "Certificate is not authorized for biometric attestation"));
  return FALSE;
}

static X509 *
fpi_sdcp_verify_x509_certificate (GBytes                        *x509_certificate,
                                  GResource                     *additional_ca_store,
                                  FpiDeviceSdcpVerificationFlags verification_flags,
                                  GError                       **error)
{
  g_autoptr(X509_STORE) sdcp_ca_store = NULL;
  g_autoptr(X509_STORE_CTX) ctx = NULL;
  const guint8 *cert_ptr;
  const guint8 *cert_start;
  g_autoptr(X509) cert = NULL;
  gsize cert_len;

  g_return_val_if_fail (x509_certificate != NULL, NULL);

  cert_ptr = g_bytes_get_data (x509_certificate, &cert_len);
  cert_start = cert_ptr;
  cert = d2i_X509 (NULL, &cert_ptr, cert_len);
  if (!cert || cert_ptr != cert_start + cert_len)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                 "Error parsing model certificate"));
      return NULL;
    }

  print_certificate (cert);

  if ((verification_flags & FPI_DEVICE_SDCP_VERIFICATION_REQUIRE_BIOMETRIC_EKU) &&
      !fpi_sdcp_check_biometric_eku (cert, TRUE, error))
    return NULL;

  /* Skipping trust-chain validation must not skip parsing the public key
   * needed for the independently controlled attestation signature checks. */
  if (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_IGNORE_CERTIFICATES)
    return g_steal_pointer (&cert);

  sdcp_ca_store = fpi_sdcp_get_ca_store (additional_ca_store, error);
  if (!sdcp_ca_store)
    return NULL;

  ctx = X509_STORE_CTX_new ();

  if (!X509_STORE_CTX_init (ctx, sdcp_ca_store, cert, NULL))
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "OpenSSL error verifying model certificate: %s",
                                                 X509_verify_cert_error_string (X509_STORE_CTX_get_error (ctx))));
      return NULL;
    }

  if (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NO_CHECK_TIME)
    {
      /*
       * Most model certificates expire after one year and are not renewed via a
       * vendor firmware update, so we should ignore the validity time check.
       */
      if (!X509_VERIFY_PARAM_set_flags (X509_STORE_CTX_get0_param (ctx),
                                        X509_V_FLAG_NO_CHECK_TIME))
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "OpenSSL error setting up certificate verification"));
          return NULL;
        }
    }

  if (!(verification_flags & FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NON_X509_STRICT))
    {
      /* Do not allow broken certificates */
      if (!X509_VERIFY_PARAM_set_flags (X509_STORE_CTX_get0_param (ctx),
                                        X509_V_FLAG_X509_STRICT))
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "OpenSSL error setting up certificate verification"));
          return NULL;
        }
    }

  if (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_ALLOW_PARTIAL_CHAIN)
    {
      /* Skip verification of the full certificate chain. */
      if (!X509_VERIFY_PARAM_set_flags (X509_STORE_CTX_get0_param (ctx),
                                        X509_V_FLAG_PARTIAL_CHAIN))
        {
          g_propagate_error (error,
                             fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                     "OpenSSL error setting up certificate verification"));
          return NULL;
        }
    }

  if (X509_verify_cert (ctx) != 1)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                 "OpenSSL error verifying model certificate: %s",
                                                 X509_verify_cert_error_string (X509_STORE_CTX_get_error (ctx))));
      return NULL;
    }

  if (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_REQUIRE_BIOMETRIC_EKU)
    {
      STACK_OF (X509) * chain = X509_STORE_CTX_get0_chain (ctx);

      for (int i = 1; i < sk_X509_num (chain); i++)
        if (!fpi_sdcp_check_biometric_eku (sk_X509_value (chain, i), FALSE, error))
          return NULL;
    }

  return g_steal_pointer (&cert);
}

gboolean
fpi_sdcp_verify_certificate (GBytes                        *x509_certificate,
                             GResource                     *additional_ca_store,
                             FpiDeviceSdcpVerificationFlags verification_flags,
                             GError                       **error)
{
  g_autoptr(X509) cert = NULL;

  cert = fpi_sdcp_verify_x509_certificate (x509_certificate,
                                           additional_ca_store,
                                           verification_flags,
                                           error);
  return cert != NULL;
}

GBytes *
fpi_sdcp_kdf (GBytes      *key,
              const gchar *label,
              GBytes      *context_a,
              GBytes      *context_b,
              gsize        length,
              GError     **error)
{
  g_autoptr(EVP_KDF) kdf = NULL;
  g_autoptr(EVP_KDF_CTX) kdf_ctx = NULL;
  g_autofree guint8 *secret = NULL;
  g_autoptr(GByteArray) context = g_byte_array_new ();
  OSSL_PARAM params[8];
  int i = 0;

  g_assert (key);
  g_assert (strlen (label) > 0);
  g_assert (length > 0);

  params[i++] = OSSL_PARAM_construct_utf8_string (OSSL_KDF_PARAM_MODE, (gchar *) "counter", 0);
  params[i++] = OSSL_PARAM_construct_utf8_string (OSSL_KDF_PARAM_MAC, (gchar *) "HMAC", 0);
  params[i++] = OSSL_PARAM_construct_utf8_string (OSSL_KDF_PARAM_DIGEST, (gchar *) "SHA2-256", 0);

  params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_KEY,
                                                   (void *) (g_bytes_get_data (key, NULL)),
                                                   g_bytes_get_size (key));

  params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SALT,
                                                   (void *) label,
                                                   strlen (label));

  /* The KBKDF context is context_a || context_b. Pass it as one INFO
   * parameter: OpenSSL 3.0 and 3.1 read only the first INFO, while 3.2+
   * concatenate repeated ones. */
  if (context_a)
    g_byte_array_append (context,
                         g_bytes_get_data (context_a, NULL),
                         g_bytes_get_size (context_a));

  if (context_b)
    g_byte_array_append (context,
                         g_bytes_get_data (context_b, NULL),
                         g_bytes_get_size (context_b));

  if (context->len > 0)
    params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_INFO,
                                                     context->data,
                                                     context->len);

  params[i++] = OSSL_PARAM_construct_end ();

  kdf = EVP_KDF_fetch (NULL, "KBKDF", NULL);
  if (!kdf || !(kdf_ctx = EVP_KDF_CTX_new (kdf)))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "Failed to create SDCP key derivation context"));
      return NULL;
    }

  secret = g_malloc0 (length);
  if (!EVP_KDF_derive (kdf_ctx, secret, length, params))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error during key derivation "
                                                        "for label '%s'", label));
      return NULL;
    }

  return fpi_sdcp_bytes_new_secure_take (g_steal_pointer (&secret), length);
}

GBytes *
fpi_sdcp_mac (GBytes      *application_secret,
              const gchar *label,
              GBytes      *data_a,
              GBytes      *data_b,
              GError     **error)
{
  g_autoptr(EVP_MAC) hmac = NULL;
  g_autoptr(EVP_MAC_CTX) hmac_ctx = NULL;
  g_autofree guint8 *mac = NULL;
  gsize mac_len = 0;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST, (gchar *) "SHA256", 0),
    OSSL_PARAM_construct_end (),
  };

  g_return_val_if_fail (application_secret != NULL, NULL);
  g_return_val_if_fail (label != NULL, NULL);
  g_return_val_if_fail (data_a != NULL || data_b != NULL, NULL);

  hmac = EVP_MAC_fetch (NULL, "hmac", NULL);
  if (!hmac || !(hmac_ctx = EVP_MAC_CTX_new (hmac)))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "Failed to create SDCP HMAC context"));
      return NULL;
    }

  if (!EVP_MAC_init (hmac_ctx,
                     g_bytes_get_data (application_secret, NULL),
                     g_bytes_get_size (application_secret),
                     params))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "Failed to initialize HMAC for label '%s'",
                                                        label));
      return NULL;
    }

  if (label)
    {
      /* include NUL terminator per SDCP spec, that requires NUL-terminated
       * strings for MAC computation
       */
      if (!EVP_MAC_update (hmac_ctx, (guchar *) label, strlen (label) + 1))
        {
          g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                            "Failed to update HMAC with label '%s'",
                                                            label));
          return NULL;
        }
    }

  if (data_a)
    {
      gsize data_len;
      gconstpointer data = g_bytes_get_data (data_a, &data_len);

      if (!EVP_MAC_update (hmac_ctx, data, data_len))
        {
          g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                            "Failed to update HMAC with data_a "
                                                            "for label '%s'",
                                                            label));
          return NULL;
        }
    }

  if (data_b)
    {
      gsize data_len;
      gconstpointer data = g_bytes_get_data (data_b, &data_len);

      if (!EVP_MAC_update (hmac_ctx, data, data_len))
        {
          g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                            "Failed to update HMAC with data_b "
                                                            "for label '%s'",
                                                            label));
          return NULL;
        }
    }

  mac = g_malloc0 (FPI_SDCP_MAC_SIZE);
  if (!EVP_MAC_final (hmac_ctx, mac, &mac_len, FPI_SDCP_MAC_SIZE))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "Failed to finalize HMAC for label '%s'",
                                                        label));
      return NULL;
    }

  if (mac_len != FPI_SDCP_MAC_SIZE)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "Unexpected HMAC output size for label '%s'",
                                                        label));
      return NULL;
    }

  return fpi_sdcp_bytes_new_secure_take (g_steal_pointer (&mac), mac_len);
}

static GBytes *
fpi_sdcp_get_private_key (EVP_PKEY *pkey,
                          GError  **error)
{
  g_autoptr(BIGNUM) priv_bn = NULL;
  g_autofree guint8 *priv = NULL;
  gsize priv_len = 0;

  g_assert_nonnull (pkey);

  if (!EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error getting private key bytes"));
      return NULL;
    }

  /* A valid P-256 scalar may have leading zero bytes. Preserve the fixed
   * wire width instead of sporadically rejecting such generated keys. */
  priv_len = FPI_SDCP_PRIVATE_KEY_SIZE;
  priv = g_malloc0 (priv_len);
  if (BN_bn2binpad (priv_bn, priv, priv_len) != priv_len)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error exporting private key bytes"));
      return NULL;
    }

  return fpi_sdcp_bytes_new_secure_take (g_steal_pointer (&priv), priv_len);
}

static GBytes *
fpi_sdcp_get_public_key (EVP_PKEY *pkey,
                         GError  **error)
{
  g_autofree guint8 *pub = g_malloc0 (FPI_SDCP_PUBLIC_KEY_SIZE);
  gsize pub_len = 0;

  g_assert_nonnull (pkey);

  if (!EVP_PKEY_get_octet_string_param (pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, FPI_SDCP_PUBLIC_KEY_SIZE, &pub_len))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error getting public key bytes"));
      return NULL;
    }

  if (pub_len != FPI_SDCP_PUBLIC_KEY_SIZE)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "Unexpected public key size"));
      return NULL;
    }

  return fpi_sdcp_bytes_new_secure_take (g_steal_pointer (&pub), pub_len);
}

static EVP_PKEY *
fpi_sdcp_get_private_pkey (GBytes  *private_key,
                           GError **error)
{
  g_autoptr(BIGNUM) private_key_bn = NULL;
  g_autoptr(EC_GROUP) group = NULL;
  g_autoptr(EC_POINT) public_key_point = NULL;
  g_autofree guint8 *public_key_buf = NULL;
  g_autoptr(EVP_PKEY_CTX) ctx = NULL;
  g_autoptr(EVP_PKEY) key = NULL;
  g_autoptr(OSSL_PARAM_BLD) param_bld = NULL;
  g_autoptr(OSSL_PARAM) params = NULL;

  if (g_bytes_get_size (private_key) != FPI_SDCP_PRIVATE_KEY_SIZE)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "Invalid private key size"));
      return NULL;
    }

  /* import private key as a BIGNUM */
  private_key_bn = BN_bin2bn (g_bytes_get_data (private_key, NULL),
                              g_bytes_get_size (private_key),
                              NULL);

  /* set up public key based on imported private_key_bn */
  group = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  public_key_point = EC_POINT_new (group);
  if (!EC_POINT_mul (group, public_key_point, private_key_bn, NULL, NULL, NULL))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error computing public key point"));
      return NULL;
    }
  public_key_buf = g_malloc0 (FPI_SDCP_PUBLIC_KEY_SIZE);
  if (!EC_POINT_point2oct (group, public_key_point, POINT_CONVERSION_UNCOMPRESSED,
                           public_key_buf, FPI_SDCP_PUBLIC_KEY_SIZE, NULL))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error encoding public key point"));
      return NULL;
    }

  /* set up parameters */

  param_bld = OSSL_PARAM_BLD_new ();
  if (!OSSL_PARAM_BLD_push_utf8_string (param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        SN_X9_62_prime256v1, sizeof (SN_X9_62_prime256v1)))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error building EC key parameters"));
      return NULL;
    }
  if (!OSSL_PARAM_BLD_push_octet_string (param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         public_key_buf, FPI_SDCP_PUBLIC_KEY_SIZE))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error building EC key parameters"));
      return NULL;
    }
  if (!OSSL_PARAM_BLD_push_BN (param_bld, OSSL_PKEY_PARAM_PRIV_KEY, private_key_bn))
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error building EC key parameters"));
      return NULL;
    }

  params = OSSL_PARAM_BLD_to_param (param_bld);

  /* import pkey from params */
  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (!ctx || EVP_PKEY_fromdata_init (ctx) != 1)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error initializing key import"));
      return NULL;
    }
  if (EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_KEYPAIR, params) != 1)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error importing private key"));
      return NULL;
    }

  return g_steal_pointer (&key);
}

static EVP_PKEY *
fpi_sdcp_get_public_pkey (GBytes  *public_key,
                          GError **error)
{
  g_autoptr(EVP_PKEY_CTX) ctx = NULL;
  g_autoptr(EVP_PKEY) key = NULL;
  OSSL_PARAM params[3];

  params[0] = OSSL_PARAM_construct_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *) SN_X9_62_prime256v1,
                                                sizeof (SN_X9_62_prime256v1));
  params[1] = OSSL_PARAM_construct_octet_string (OSSL_PKEY_PARAM_PUB_KEY,
                                                 (char *) g_bytes_get_data (public_key, NULL),
                                                 g_bytes_get_size (public_key));
  params[2] = OSSL_PARAM_construct_end ();

  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (!ctx)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error creating EC key context"));
      return NULL;
    }

  if (EVP_PKEY_fromdata_init (ctx) != 1)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error initializing public key import"));
      return NULL;
    }

  if (EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_PUBLIC_KEY, params) != 1)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error importing public key"));
      return NULL;
    }

  return g_steal_pointer (&key);
}

GBytes *
fpi_sdcp_key_agreement (GBytes  *private_key,
                        GBytes  *peer_public_key,
                        GError **error)
{
  g_autoptr(EVP_PKEY_CTX) ctx = NULL;
  g_autoptr(EVP_PKEY) host_pkey = NULL;
  g_autoptr(EVP_PKEY) device_pkey = NULL;
  g_autofree guint8 *key_agreement = NULL;
  gsize key_agreement_len = 0;

  host_pkey = fpi_sdcp_get_private_pkey (private_key, error);
  if (!host_pkey)
    return NULL;

  device_pkey = fpi_sdcp_get_public_pkey (peer_public_key, error);
  if (!device_pkey)
    return NULL;

  ctx = EVP_PKEY_CTX_new_from_pkey (NULL, host_pkey, NULL);

  if (!ctx || EVP_PKEY_derive_init (ctx) != 1)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error initializing key agreement"));
      return NULL;
    }

  if (EVP_PKEY_derive_set_peer (ctx, device_pkey) != 1)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error setting peer key for key agreement"));
      return NULL;
    }

  /* Get the size by passing NULL as the buffer */
  if (EVP_PKEY_derive (ctx, NULL, &key_agreement_len) != 1)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error sizing key agreement output"));
      return NULL;
    }

  if (key_agreement_len != SDCP_KEY_AGREEMENT_SIZE)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "Unexpected key agreement output size"));
      return NULL;
    }

  /* Then get the derived shared secret using the fetched size */
  key_agreement = g_malloc0 (key_agreement_len);
  if (EVP_PKEY_derive (ctx, key_agreement, &key_agreement_len) != 1)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error deriving key agreement"));
      return NULL;
    }

  return fpi_sdcp_bytes_new_secure_take (g_steal_pointer (&key_agreement), key_agreement_len);
}

/******************************************************************************/

gboolean
fpi_sdcp_generate_host_key (GBytes **private_key,
                            GBytes **public_key,
                            GError **error)
{
  g_autoptr(GBytes) local_private_key = NULL;
  g_autoptr(GBytes) local_public_key = NULL;
  g_autoptr(EVP_PKEY) key = NULL;

  g_assert (private_key != NULL);
  g_assert (public_key != NULL);

  key = EVP_EC_gen ("P-256");
  if (!key)
    {
      g_propagate_error (error, fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                        "OpenSSL error generating host key"));
      return FALSE;
    }

  if (!(local_private_key = fpi_sdcp_get_private_key (key, error)))
    return FALSE;

  if (!(local_public_key = fpi_sdcp_get_public_key (key, error)))
    return FALSE;

  *private_key = g_steal_pointer (&local_private_key);
  *public_key = g_steal_pointer (&local_public_key);

  return TRUE;
}

GBytes *
fpi_sdcp_generate_random (GError **error)
{
  g_autofree guint8 *random = g_malloc0 (FPI_SDCP_RANDOM_SIZE);

  if (fpi_device_emulation_mode_enabled (NULL) &&
      g_strcmp0 (g_getenv ("FP_SDCP_FIXED_RANDOM"), "1") == 0)
    {
      /* For testing purposes, use a fixed random. */
      memset (random, 0x53, FPI_SDCP_RANDOM_SIZE);
      fp_dbg ("Using fixed random value for SDCP:");
      fp_dbg_hex_dump_bytes (random, FPI_SDCP_RANDOM_SIZE);

      return fpi_sdcp_bytes_new_secure_take (g_steal_pointer (&random),
                                             FPI_SDCP_RANDOM_SIZE);
    }

  if (RAND_bytes (random, FPI_SDCP_RANDOM_SIZE) != 1)
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                 "OpenSSL error generating random"));
      return NULL;
    }

  return fpi_sdcp_bytes_new_secure_take (g_steal_pointer (&random),
                                         FPI_SDCP_RANDOM_SIZE);
}

GBytes *
fpi_sdcp_verify_connect (GBytes                        *host_private_key,
                         GBytes                        *host_random,
                         GBytes                        *device_random,
                         FpiSdcpClaim                  *claim,
                         GBytes                        *mac,
                         GResource                     *additional_ca_store,
                         FpiDeviceSdcpVerificationFlags verification_flags,
                         GError                       **error)
{
  g_autoptr(X509) cert = NULL;
  g_autoptr(EVP_PKEY) cert_public_pkey = NULL;
  g_autoptr(EVP_PKEY) device_public_pkey = NULL;
  g_autoptr(GError) local_error = NULL;
  g_autoptr(GBytes) claim_hash = NULL;
  g_autoptr(GBytes) claim_mac = NULL;
  g_autoptr(GBytes) key_agreement = NULL;
  g_autoptr(GBytes) master_secret = NULL;
  g_autoptr(GBytes) application_keys = NULL;
  g_autoptr(GBytes) out_app_secret = NULL;
  g_autofree guint8 *app_secret_buf = NULL;

  g_return_val_if_fail (host_private_key != NULL, NULL);
  g_return_val_if_fail (host_random != NULL, NULL);
  g_return_val_if_fail (device_random != NULL, NULL);
  g_return_val_if_fail (claim != NULL, NULL);
  g_return_val_if_fail (mac != NULL, NULL);

  fp_dbg ("SDCP Verify ConnectResponse");

  /* SDCP Connect: 5.i. Perform key agreement */

  key_agreement = fpi_sdcp_key_agreement (host_private_key,
                                          claim->firmware_public_key, error);
  if (!key_agreement)
    return NULL;

  /* SDCP Connect: 5.ii. Derive master secret */

  master_secret = fpi_sdcp_kdf (key_agreement,
                                claim->master_secret_label ?
                                claim->master_secret_label :
                                FPI_SDCP_DEFAULT_LABEL_MASTER_SECRET,
                                host_random, device_random,
                                FPI_SDCP_MASTER_SECRET_SIZE, error);
  if (!master_secret)
    return NULL;

  /* SDCP Connect: 5.iii. Derive MAC secret and symmetric key */

  application_keys = fpi_sdcp_kdf (master_secret,
                                   claim->application_keys_label ?
                                   claim->application_keys_label :
                                   FPI_SDCP_DEFAULT_LABEL_APPLICATION_KEYS,
                                   NULL, NULL,
                                   FPI_SDCP_APPLICATION_KEYS_SIZE, error);
  if (!application_keys)
    return NULL;

  /* slice first half of application_keys as application_secret */
  g_assert (g_bytes_get_size (application_keys) >= FPI_SDCP_APPLICATION_SECRET_SIZE);
  app_secret_buf = g_malloc0 (FPI_SDCP_APPLICATION_SECRET_SIZE);
  memcpy (app_secret_buf,
          g_bytes_get_data (application_keys, NULL),
          FPI_SDCP_APPLICATION_SECRET_SIZE);

  out_app_secret = fpi_sdcp_bytes_new_secure_take (g_steal_pointer (&app_secret_buf),
                                                   FPI_SDCP_APPLICATION_SECRET_SIZE);

  /* SDCP Connect: 5.iv. Validate the MAC over H(claim) */

  claim_hash = fpi_sdcp_claim_hash (claim, error);
  if (!claim_hash)
    return NULL;

  claim_mac = fpi_sdcp_mac (out_app_secret,
                            claim->connect_label ?
                            claim->connect_label :
                            FPI_SDCP_DEFAULT_LABEL_CONNECT,
                            claim_hash, NULL, error);
  if (!claim_mac)
    return NULL;

  fp_dbg ("Device MAC:");
  fp_dbg_hex_dump_gbytes (mac);

  fp_dbg ("Host MAC:");
  fp_dbg_hex_dump_gbytes (claim_mac);

  if (g_bytes_get_size (mac) == g_bytes_get_size (claim_mac) &&
      CRYPTO_memcmp (g_bytes_get_data (mac, NULL),
                     g_bytes_get_data (claim_mac, NULL),
                     g_bytes_get_size (mac)) == 0)
    {
      fp_dbg ("SDCP ConnectResponse claim validated successfully");
    }
  else
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                 "SDCP ConnectResponse claim validation failed"));
      return NULL;
    }


  /* SDCP Connect: 5.v. Unpack the claim (SKIP; already done) */
  /* SDCP Connect: 5.vi. Verify the claim */

  if ((verification_flags & FPI_DEVICE_SDCP_VERIFICATION_IGNORE_CERTIFICATES) &&
      (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_IGNORE_SIGNATURES) &&
      !(verification_flags & FPI_DEVICE_SDCP_VERIFICATION_REQUIRE_BIOMETRIC_EKU))
    {
      fp_dbg ("SDCP certificate and signature verification ignored");
      return g_steal_pointer (&out_app_secret);
    }

  /* Parse and Validate the certificate */
  cert = fpi_sdcp_verify_x509_certificate (claim->model_certificate,
                                           additional_ca_store,
                                           verification_flags,
                                           error);
  if (!cert)
    {
      fp_dbg ("SDCP model certificate verification failed");
      return NULL;
    }

  fp_dbg ("SDCP model certificate verified successfully");

  if (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_IGNORE_SIGNATURES)
    {
      fp_dbg ("SDCP signatures verification ignored");
      return g_steal_pointer (&out_app_secret);
    }

  /* Get the certificate's public key */

  if (!(cert_public_pkey = X509_get_pubkey (cert)))
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                 "Error getting public key from "
                                                 "model certificate"));
      return NULL;
    }

  /* Verify(pk_m, H(pk_d), s_m) */

  fp_dbg ("model_signature:");
  fp_dbg_hex_dump_gbytes (claim->model_signature);

  if (!fpi_sdcp_verify_signature (cert_public_pkey,
                                  NULL,
                                  claim->device_public_key,
                                  NULL,
                                  claim->model_signature,
                                  &local_error))
    {
      g_propagate_prefixed_error (error, g_steal_pointer (&local_error),
                                  "SDCP model signature verification failed: ");
      return NULL;
    }

  fp_dbg ("SDCP model signature verified successfully");

  /* Verify(pk_d, H(C001||h_f||pk_f), s_d) */

  fp_dbg ("device_public_key:");
  fp_dbg_hex_dump_gbytes (claim->device_public_key);

  fp_dbg ("firmware_hash:");
  fp_dbg_hex_dump_gbytes (claim->firmware_hash);

  fp_dbg ("firmware_public_key:");
  fp_dbg_hex_dump_gbytes (claim->firmware_public_key);

  fp_dbg ("device_signature:");
  fp_dbg_hex_dump_gbytes (claim->device_signature);

  if (!(device_public_pkey = fpi_sdcp_get_public_pkey (claim->device_public_key, error)))
    return NULL;

  if (!fpi_sdcp_verify_signature (device_public_pkey,
                                  SDCP_DEVICE_SIGNATURE_HEADER,
                                  claim->firmware_hash,
                                  claim->firmware_public_key,
                                  claim->device_signature,
                                  &local_error))
    {
      g_propagate_prefixed_error (error, g_steal_pointer (&local_error),
                                  "SDCP device signature verification failed: ");
      return NULL;
    }

  fp_dbg ("SDCP device signature verified successfully");

  return g_steal_pointer (&out_app_secret);
}

gboolean
fpi_sdcp_verify_reconnect (GBytes      *application_secret,
                           const gchar *label,
                           GBytes      *random,
                           GBytes      *mac,
                           GError     **error)
{
  g_autoptr(GBytes) host_mac = NULL;

  fp_dbg ("SDCP Verify ReconnectResponse");

  host_mac = fpi_sdcp_mac (application_secret,
                           label ? label : FPI_SDCP_DEFAULT_LABEL_RECONNECT,
                           random, NULL, error);
  if (!host_mac)
    return FALSE;

  fp_dbg ("Device MAC:");
  fp_dbg_hex_dump_gbytes (mac);

  fp_dbg ("Host MAC:");
  fp_dbg_hex_dump_gbytes (host_mac);

  if (g_bytes_get_size (mac) == g_bytes_get_size (host_mac) &&
      CRYPTO_memcmp (g_bytes_get_data (mac, NULL),
                     g_bytes_get_data (host_mac, NULL),
                     g_bytes_get_size (mac)) == 0)
    {
      fp_dbg ("SDCP ReconnectResponse verified successfully");
      return TRUE;
    }
  else
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                 "SDCP ReconnectResponse verification failed"));
      return FALSE;
    }
}

gboolean
fpi_sdcp_verify_identify (GBytes      *application_secret,
                          const gchar *label,
                          GBytes      *nonce,
                          GBytes      *id,
                          GBytes      *mac,
                          GError     **error)
{
  g_autoptr(GBytes) host_mac = NULL;

  fp_dbg ("SDCP Verify AuthorizedIdentity");

  host_mac = fpi_sdcp_mac (application_secret,
                           label ? label : FPI_SDCP_DEFAULT_LABEL_IDENTIFY,
                           nonce, id, error);
  if (!host_mac)
    return FALSE;

  fp_dbg ("Device MAC:");
  fp_dbg_hex_dump_gbytes (mac);

  fp_dbg ("Host MAC:");
  fp_dbg_hex_dump_gbytes (host_mac);

  if (g_bytes_get_size (mac) == g_bytes_get_size (host_mac) &&
      CRYPTO_memcmp (g_bytes_get_data (mac, NULL),
                     g_bytes_get_data (host_mac, NULL),
                     g_bytes_get_size (mac)) == 0)
    {
      fp_dbg ("SDCP AuthorizedIdentity verified successfully");
      return TRUE;
    }
  else
    {
      g_propagate_error (error,
                         fpi_sdcp_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                 "SDCP AuthorizedIdentity verification failed"));
      return FALSE;
    }
}

GBytes *
fpi_sdcp_generate_enrollment_id (GBytes      *application_secret,
                                 const gchar *label,
                                 GBytes      *nonce,
                                 GError     **error)
{
  g_autoptr(GBytes) id = NULL;

  id = fpi_sdcp_mac (application_secret,
                     label ? label : FPI_SDCP_DEFAULT_LABEL_ENROLL,
                     nonce, NULL, error);
  if (!id)
    return NULL;

  fp_dbg ("Generated SDCP Enrollment ID:");
  fp_dbg_hex_dump_gbytes (id);

  return g_steal_pointer (&id);
}

#ifdef TOD_LIBRARY
#include "tod/tod-fpi-sdcp.c"
#endif
