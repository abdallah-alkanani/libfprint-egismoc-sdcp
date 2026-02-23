/*
 * Secure Device Connection Protocol (SDCP) support implementation
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

#define FP_COMPONENT "sdcp"
#include "fpi-log.h"

#include "fpi-sdcp.h"
#include "sdcp/fpi-sdcp-truststore-resource.h"

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

#define SDCP_KEY_AGREEMENT_SIZE 32
#define SDCP_MASTER_SECRET_SIZE 32
#define SDCP_APPLICATION_KEYS_SIZE 64

#define SDCP_DEVICE_SIGNATURE_HEADER "\xC0\x01"

/******************************************************************************/

static void
print_openssl_errors (void)
{
  gulong e = 0;

  e = ERR_get_error ();
  while (e != 0)
    {
      fp_dbg ("OpenSSL error: %s", ERR_error_string (e, NULL));
      e = ERR_get_error ();
    }
}

static void
print_certificate (X509 *certificate)
{
  BIO *bio = BIO_new (BIO_s_mem ());
  BUF_MEM *bio_mem = NULL;

  X509_print (bio, certificate);
  BIO_get_mem_ptr (bio, &bio_mem);
  fp_dbg ("SDCP Device reported the following model certificate:\n%.*s\n",
          (int) bio_mem->length, bio_mem->data);
  BIO_free (bio);
}

typedef struct
{
  void *ptr;
  gsize size;
} FpiSdcpDestroyData;

static void
fpi_sdcp_secure_destroy_notify (gpointer destroy_data)
{
  FpiSdcpDestroyData *d = destroy_data;

  OPENSSL_cleanse (d->ptr, d->size);
  g_free (d->ptr);
  g_free (d);
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
raw_ecdsa_sig_to_der (GBytes *raw_sig)
{
  gsize len;
  const guint8 *data = g_bytes_get_data (raw_sig, &len);
  ECDSA_SIG *sig = NULL;
  BIGNUM *r = NULL, *s = NULL;
  guint8 *der = NULL;
  int der_len;

  if (len != FPI_SDCP_SIGNATURE_SIZE)
    return NULL;

  sig = ECDSA_SIG_new ();
  if (!sig)
    return NULL;

  r = BN_bin2bn (data, FPI_SDCP_SIGNATURE_SIZE / 2, NULL);
  s = BN_bin2bn (data + FPI_SDCP_SIGNATURE_SIZE / 2,
                 FPI_SDCP_SIGNATURE_SIZE / 2, NULL);

  /* ECDSA_SIG_set0 takes ownership of r and s on success */
  if (!r || !s || !ECDSA_SIG_set0 (sig, r, s))
    {
      g_clear_pointer (&r, BN_free);
      g_clear_pointer (&s, BN_free);
      ECDSA_SIG_free (sig);
      return NULL;
    }

  der_len = i2d_ECDSA_SIG (sig, &der);
  ECDSA_SIG_free (sig);

  if (der_len <= 0)
    return NULL;

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
  EVP_MD_CTX *mdctx = NULL;
  int verify_result;

  /* SDCP signatures are raw 64-byte (r||s); convert to DER for OpenSSL */
  der_sig = raw_ecdsa_sig_to_der (signature);
  if (!der_sig)
    goto out_error;

  mdctx = EVP_MD_CTX_create ();

  /* Let EVP_DigestVerifyInit create and own the pctx internally */
  if (!EVP_DigestVerifyInit (mdctx, NULL, EVP_sha256 (), NULL, pkey))
    goto out_error;

  if (label)
    if (!EVP_DigestVerifyUpdate (mdctx, label, strlen (label)))
      goto out_error;

  if (data_a)
    {
      if (!EVP_DigestVerifyUpdate (mdctx,
                                   g_bytes_get_data (data_a, NULL),
                                   g_bytes_get_size (data_a)))
        goto out_error;
    }

  if (data_b)
    {
      if (!EVP_DigestVerifyUpdate (mdctx,
                                   g_bytes_get_data (data_b, NULL),
                                   g_bytes_get_size (data_b)))
        goto out_error;
    }

  verify_result = EVP_DigestVerifyFinal (mdctx,
                                         g_bytes_get_data (der_sig, NULL),
                                         g_bytes_get_size (der_sig));
  if (verify_result == 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_UNTRUSTED,
                   "Signature verification failed for label '%s'", label);
      g_clear_pointer (&mdctx, EVP_MD_CTX_free);
      return FALSE;
    }

  if (verify_result != 1)
    goto out_error;

  EVP_MD_CTX_free (mdctx);

  return TRUE;

out_error:
  g_propagate_error (error,
                     fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                               "OpenSSL error verifying signature for label '%s'",
                                               label));
  print_openssl_errors ();
  g_clear_pointer (&mdctx, EVP_MD_CTX_free);
  return FALSE;
}

static gboolean
fpi_sdcp_trust_store_includes_test_certificate (void)
{
  if (!fpi_device_emulation_mode_enabled (NULL))
    return FALSE;

  return g_strcmp0 (g_getenv ("FP_VIRTUAL_SDCP_UNTRUSTED_CERTIFICATE"), "1") != 0;
}

static X509_STORE *
fpi_sdcp_build_truststore (GError **error)
{
  g_autoptr(GError) local_error = NULL;
  g_autoptr(GResource) truststore_resource = NULL;
  g_auto(GStrv) trustcert_names = NULL;
  X509_STORE *truststore = NULL;
  const gchar *truststore_resource_path = "/org/freedesktop/fprint/sdcp/truststore/";
  const gchar *trustcert_ptr;
  gsize trustcert_len = 0;
  BIO *bio = NULL;
  X509 *trustcert = NULL;

  truststore = X509_STORE_new ();
  if (!truststore)
    {
      g_propagate_error (error,
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                   "Failed initializing SDCP X509 certificate store"));
      goto out;
    }

  fpi_sdcp_truststore_register_resource ();
  truststore_resource = fpi_sdcp_truststore_get_resource ();
  trustcert_names = g_resources_enumerate_children (truststore_resource_path,
                                                    G_RESOURCE_LOOKUP_FLAGS_NONE,
                                                    &local_error);
  if (!trustcert_names)
    {
      g_propagate_error (error,
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                   "Error loading SDCP truststore certificates: %s",
                                                   local_error->message));
      goto out;
    }

  for (int i = 0; trustcert_names[i]; i++)
    {
      g_autoptr(GBytes) trustcert_gb = NULL;
      g_autofree gchar *trustcert_path = NULL;

      if (g_str_has_prefix (trustcert_names[i], "SDCP Virtual"))
        {
          if (!fpi_sdcp_trust_store_includes_test_certificate ())
            {
              fp_dbg ("Skipping test-only certificate (test-only): %s",
                      trustcert_names[i]);
              continue;
            }
        }

      fp_dbg ("Adding certificate to SDCP truststore: %s", trustcert_names[i]);
      trustcert_path = g_strconcat (truststore_resource_path, trustcert_names[i], NULL);
      trustcert_gb = g_resource_lookup_data (truststore_resource,
                                             trustcert_path, 0,
                                             &local_error);
      if (!trustcert_gb)
        {
          g_propagate_error (error,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                       "Error loading SDCP truststore "
                                                       "certificate '%s': %s",
                                                       trustcert_names[i],
                                                       local_error->message));
          goto out;
        }

      trustcert_ptr = g_bytes_get_data (trustcert_gb, &trustcert_len);

      bio = BIO_new (BIO_s_mem ());
      if (BIO_write (bio, trustcert_ptr, trustcert_len) != trustcert_len)
        {
          g_propagate_error (error,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                       "Failed reading '%s' to buffer",
                                                       trustcert_names[i]));
          goto out;
        }

      trustcert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
      //print_certificate (trustcert);
      if (!X509_STORE_add_cert (truststore, trustcert))
        {
          g_propagate_error (error,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                       "Failed adding '%s' to X509 store",
                                                       trustcert_names[i]));
          goto out;
        }
      BIO_free (bio);
      X509_free (trustcert);
    }

  return truststore;

out:
  print_openssl_errors ();
  g_clear_pointer (&bio, BIO_free);
  g_clear_pointer (&trustcert, X509_free);
  return NULL;
}

static X509_STORE *
fpi_sdcp_get_truststore (GError **error)
{
  static X509_STORE *truststore = NULL;

  /* In emulation mode, we want to allow the use of test-only certificates,
   * so we cannot cache the truststore if it contains test-only certificates.
   */
  if (fpi_device_emulation_mode_enabled (NULL) &&
      !fpi_sdcp_trust_store_includes_test_certificate ())
    return fpi_sdcp_build_truststore (error);

  if (g_once_init_enter_pointer (&truststore))
    {
      g_once_init_leave_pointer (&truststore,
                                 fpi_sdcp_build_truststore (error));
      g_return_val_if_fail (truststore != NULL, NULL);
    }

  X509_STORE_up_ref (truststore);
  return truststore;
}

static gboolean
fpi_sdcp_verify_certificate (X509                          *certificate,
                             FpiDeviceSdcpVerificationFlags verification_flags,
                             GError                       **error)
{
  X509_STORE *sdcp_truststore = NULL;
  X509_STORE_CTX *ctx = NULL;

  if (!(sdcp_truststore = fpi_sdcp_get_truststore (error)))
    goto out_error;

  ctx = X509_STORE_CTX_new ();

  if (!X509_STORE_CTX_init (ctx, sdcp_truststore, certificate, NULL))
    goto out_verify_error;

  if (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NO_CHECK_TIME)
    {
      /*
       * Most model certificates expire after one year and are not renewed via a
       * vendor firmware update, so we should ignore the validity time check.
       */
      if (!X509_VERIFY_PARAM_set_flags (X509_STORE_CTX_get0_param (ctx),
                                        X509_V_FLAG_NO_CHECK_TIME))
        goto out_error;
    }

  if (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NON_X509_STRICT)
    {
      /* Do not allow broken certificates */
      if (!X509_VERIFY_PARAM_set_flags (X509_STORE_CTX_get0_param (ctx),
                                        X509_V_FLAG_X509_STRICT))
        goto out_error;
    }

  if (verification_flags & FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_ALLOW_PARTIAL_CHAIN)
    {
      /* Skip verification of the full certificate chain. */
      if (!X509_VERIFY_PARAM_set_flags (X509_STORE_CTX_get0_param (ctx),
                                        X509_V_FLAG_PARTIAL_CHAIN))
        goto out_error;
    }

  if (!X509_verify_cert (ctx))
    goto out_verify_error;

  X509_STORE_CTX_free (ctx);
  g_clear_pointer (&sdcp_truststore, X509_STORE_free);

  return TRUE;

out_error:
  g_propagate_error (error,
                     fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                               "OpenSSL error setting up certificate verification"));
  print_openssl_errors ();
  goto out;
out_verify_error:
  g_propagate_error (error,
                     fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                               "OpenSSL error verifying model certificate: %s",
                                               X509_verify_cert_error_string (X509_STORE_CTX_get_error (ctx))));
out:
  g_clear_pointer (&ctx, X509_STORE_CTX_free);
  g_clear_pointer (&sdcp_truststore, X509_STORE_free);
  return FALSE;
}

static GBytes *
fpi_sdcp_kdf (GBytes      *key,
              const gchar *label,
              GBytes      *context_a,
              GBytes      *context_b,
              gsize        length,
              GError     **error)
{
  g_autoptr(GBytes) res = NULL;
  guint8 *secret = NULL;
  EVP_KDF *kdf;
  EVP_KDF_CTX *kdf_ctx;
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

  if (context_a)
    params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_INFO,
                                                     (void *) (g_bytes_get_data (context_a, NULL)),
                                                     g_bytes_get_size (context_a));

  if (context_b)
    params[i++] = OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_INFO,
                                                     (void *) (g_bytes_get_data (context_b, NULL)),
                                                     g_bytes_get_size (context_b));

  params[i++] = OSSL_PARAM_construct_end ();

  kdf = EVP_KDF_fetch (NULL, "KBKDF", NULL);
  kdf_ctx = EVP_KDF_CTX_new (kdf);

  secret = g_malloc0 (length);
  if (!EVP_KDF_derive (kdf_ctx, secret, length, params))
    {
      g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                          "OpenSSL error during key derivation "
                                                          "for label '%s'", label));
      g_free (secret);
      EVP_KDF_CTX_free (kdf_ctx);
      EVP_KDF_free (kdf);
      print_openssl_errors ();
      return NULL;
    }

  EVP_KDF_CTX_free (kdf_ctx);
  EVP_KDF_free (kdf);

  res = fpi_sdcp_bytes_new_secure_take (secret, length);

  return g_steal_pointer (&res);
}

GBytes *
fpi_sdcp_mac (GBytes      *application_secret,
              const gchar *label,
              GBytes      *data_a,
              GBytes      *data_b,
              GError     **error)
{
  g_autoptr(GBytes) res = NULL;

  EVP_MAC *hmac;
  EVP_MAC_CTX *hmac_ctx;
  guint8 *mac = NULL;
  gsize mac_len = 0;

  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST, (gchar *) "SHA256", 0),
    OSSL_PARAM_construct_end (),
  };

  hmac = EVP_MAC_fetch (NULL, "hmac", NULL);
  hmac_ctx = EVP_MAC_CTX_new (hmac);

  if (!EVP_MAC_init (hmac_ctx,
                     g_bytes_get_data (application_secret, NULL),
                     g_bytes_get_size (application_secret),
                     params))
    goto out_error;

  if (label)
    if (!EVP_MAC_update (hmac_ctx, (guchar *) label, strlen (label) + 1)) /* +1 due to unsigned */
      goto out_error;

  if (data_a)
    if (!EVP_MAC_update (hmac_ctx, g_bytes_get_data (data_a, NULL), g_bytes_get_size (data_a)))
      goto out_error;

  if (data_b)
    if (!EVP_MAC_update (hmac_ctx, g_bytes_get_data (data_b, NULL), g_bytes_get_size (data_b)))
      goto out_error;

  mac = g_malloc0 (FPI_SDCP_MAC_SIZE);
  if (!EVP_MAC_final (hmac_ctx, mac, &mac_len, FPI_SDCP_MAC_SIZE))
    goto out_error;

  if (mac_len != FPI_SDCP_MAC_SIZE)
    goto out_error;

  EVP_MAC_CTX_free (hmac_ctx);
  EVP_MAC_free (hmac);

  res = fpi_sdcp_bytes_new_secure_take (mac, mac_len);
  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error generating MAC for label '%s'",
                                                      label));
  print_openssl_errors ();
  g_clear_pointer (&mac, g_free);
  g_clear_pointer (&hmac_ctx, EVP_MAC_CTX_free);
  g_clear_pointer (&hmac, EVP_MAC_free);
  return NULL;
}

static GBytes *
fpi_sdcp_get_private_key (EVP_PKEY *pkey,
                          GError  **error)
{
  g_autoptr(GBytes) res = NULL;
  BIGNUM *priv_bn = NULL;
  guint8 *priv = NULL;
  gsize priv_len = 0;

  g_assert_nonnull (pkey);

  if (!EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn))
    goto out_error;

  priv_len = BN_num_bytes (priv_bn);
  if (priv_len != FPI_SDCP_PRIVATE_KEY_SIZE)
    goto out_error;

  priv = g_malloc0 (priv_len);
  if (!BN_bn2bin (priv_bn, priv))
    goto out_error;

  BN_clear_free (priv_bn);

  res = fpi_sdcp_bytes_new_secure_take (priv, priv_len);

  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error getting private key bytes"));
  print_openssl_errors ();
  g_clear_pointer (&priv, g_free);
  g_clear_pointer (&priv_bn, BN_clear_free);
  return NULL;
}

static GBytes *
fpi_sdcp_get_public_key (EVP_PKEY *pkey,
                         GError  **error)
{
  g_autoptr(GBytes) res = NULL;
  guint8 *pub = NULL;
  gsize pub_len = 0;

  g_assert_nonnull (pkey);

  pub = g_malloc0 (FPI_SDCP_PUBLIC_KEY_SIZE);
  if (!EVP_PKEY_get_octet_string_param (pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, FPI_SDCP_PUBLIC_KEY_SIZE, &pub_len))
    goto out_error;

  if (pub_len != FPI_SDCP_PUBLIC_KEY_SIZE)
    goto out_error;

  res = fpi_sdcp_bytes_new_secure_take (pub, pub_len);

  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error getting public key bytes"));
  print_openssl_errors ();
  g_clear_pointer (&pub, g_free);
  return NULL;
}

static EVP_PKEY *
fpi_sdcp_get_private_pkey (GBytes  *private_key,
                           GError **error)
{
  BIGNUM *private_key_bn = NULL;
  EC_GROUP *group = NULL;
  EC_POINT *public_key_point = NULL;
  g_autofree guint8 *public_key_buf = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  OSSL_PARAM_BLD *param_bld = NULL;
  OSSL_PARAM *params = NULL;

  if (g_bytes_get_size (private_key) != FPI_SDCP_PRIVATE_KEY_SIZE)
    goto out_error;

  /* import private key as a BIGNUM */
  private_key_bn = BN_bin2bn (g_bytes_get_data (private_key, NULL),
                              g_bytes_get_size (private_key),
                              NULL);

  /* set up public key based on imported private_key_bn */
  group = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  public_key_point = EC_POINT_new (group);
  if (!EC_POINT_mul (group, public_key_point, private_key_bn, NULL, NULL, NULL))
    goto out_error;
  public_key_buf = g_malloc0 (FPI_SDCP_PUBLIC_KEY_SIZE);
  if (!EC_POINT_point2oct (group, public_key_point, POINT_CONVERSION_UNCOMPRESSED,
                           public_key_buf, FPI_SDCP_PUBLIC_KEY_SIZE, NULL))
    goto out_error;
  EC_POINT_free (public_key_point);
  EC_GROUP_free (group);

  /* set up parameters */

  param_bld = OSSL_PARAM_BLD_new ();
  if (!OSSL_PARAM_BLD_push_utf8_string (param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        SN_X9_62_prime256v1, sizeof (SN_X9_62_prime256v1)))
    goto out_error;
  if (!OSSL_PARAM_BLD_push_octet_string (param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         public_key_buf, FPI_SDCP_PUBLIC_KEY_SIZE))
    goto out_error;
  if (!OSSL_PARAM_BLD_push_BN (param_bld, OSSL_PKEY_PARAM_PRIV_KEY, private_key_bn))
    goto out_error;

  params = OSSL_PARAM_BLD_to_param (param_bld);

  /* import pkey from params */
  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (!EVP_PKEY_fromdata_init (ctx))
    goto out_error;
  EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_KEYPAIR, params);

  EVP_PKEY_CTX_free (ctx);
  OSSL_PARAM_free (params);
  OSSL_PARAM_BLD_free (param_bld);
  BN_clear_free (private_key_bn);

  return g_steal_pointer (&key);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error getting private key"));
  print_openssl_errors ();
  g_clear_pointer (&key, EVP_PKEY_free);
  g_clear_pointer (&ctx, EVP_PKEY_CTX_free);
  g_clear_pointer (&params, OSSL_PARAM_free);
  g_clear_pointer (&param_bld, OSSL_PARAM_BLD_free);
  g_clear_pointer (&public_key_point, EC_POINT_free);
  g_clear_pointer (&group, EC_GROUP_free);
  g_clear_pointer (&private_key_bn, BN_clear_free);
  return NULL;
}

static EVP_PKEY *
fpi_sdcp_get_public_pkey (GBytes  *public_key,
                          GError **error)
{
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
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
    goto out_error;

  if (!EVP_PKEY_fromdata_init (ctx))
    goto out_error;

  if (!EVP_PKEY_fromdata (ctx, &key, EVP_PKEY_PUBLIC_KEY, params))
    goto out_error;

  EVP_PKEY_CTX_free (ctx);

  return g_steal_pointer (&key);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error getting public key"));
  print_openssl_errors ();
  g_clear_pointer (&key, EVP_PKEY_free);
  g_clear_pointer (&ctx, EVP_PKEY_CTX_free);
  return NULL;
}

GBytes *
fpi_sdcp_hash_claim (FpiSdcpClaim *claim,
                     GError      **error)
{
  g_autoptr(GBytes) res = NULL;
  EVP_MD_CTX *sh256_ctx;
  EVP_MD *sha256;
  guint8 *hash = NULL;
  guint hash_len = 0;

  sh256_ctx = EVP_MD_CTX_create ();
  sha256 = EVP_MD_fetch (NULL, "SHA256", NULL);
  if (!EVP_DigestInit_ex (sh256_ctx, sha256, NULL))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->model_certificate, NULL),
                         g_bytes_get_size (claim->model_certificate)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->device_public_key, NULL),
                         g_bytes_get_size (claim->device_public_key)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->firmware_public_key, NULL),
                         g_bytes_get_size (claim->firmware_public_key)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->firmware_hash, NULL),
                         g_bytes_get_size (claim->firmware_hash)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->model_signature, NULL),
                         g_bytes_get_size (claim->model_signature)))
    goto out_error;

  if (!EVP_DigestUpdate (sh256_ctx,
                         g_bytes_get_data (claim->device_signature, NULL),
                         g_bytes_get_size (claim->device_signature)))
    goto out_error;

  hash = g_malloc0 (EVP_MAX_MD_SIZE);
  if (!EVP_DigestFinal_ex (sh256_ctx, hash, &hash_len))
    goto out_error;

  EVP_MD_CTX_free (sh256_ctx);
  EVP_MD_free (sha256);

  res = fpi_sdcp_bytes_new_secure_take (hash, hash_len);
  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error hashing the SDCP claim"));
  print_openssl_errors ();
  g_clear_pointer (&sh256_ctx, EVP_MD_CTX_free);
  g_clear_pointer (&sha256, EVP_MD_free);
  g_clear_pointer (&hash, g_free);
  return NULL;
}

static GBytes *
fpi_sdcp_key_agreement (GBytes  *host_private_key,
                        GBytes  *firmware_public_key,
                        GError **error)
{
  g_autoptr(GBytes) res = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *host_pkey = NULL;
  EVP_PKEY *device_pkey = NULL;
  guint8 *key_agreement = NULL;
  gsize key_agreement_len = 0;

  host_pkey = fpi_sdcp_get_private_pkey (host_private_key, error);
  if (!host_pkey)
    goto out;

  device_pkey = fpi_sdcp_get_public_pkey (firmware_public_key, error);
  if (!device_pkey)
    goto out;

  ctx = EVP_PKEY_CTX_new_from_pkey (NULL, host_pkey, NULL);

  if (!EVP_PKEY_derive_init (ctx))
    goto out_error;

  if (!EVP_PKEY_derive_set_peer (ctx, device_pkey))
    goto out_error;

  /* Get the size by passing NULL as the buffer */
  if (!EVP_PKEY_derive (ctx, NULL, &key_agreement_len))
    goto out_error;

  if (key_agreement_len != SDCP_KEY_AGREEMENT_SIZE)
    goto out_error;

  /* Then get the derived shared secret using the fetched size */
  key_agreement = g_malloc0 (key_agreement_len);
  if (!EVP_PKEY_derive (ctx, key_agreement, &key_agreement_len))
    goto out_error;

  EVP_PKEY_CTX_free (ctx);
  EVP_PKEY_free (device_pkey);
  EVP_PKEY_free (host_pkey);

  res = fpi_sdcp_bytes_new_secure_take (key_agreement, key_agreement_len);

  return g_steal_pointer (&res);

out_error:
  g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                      "OpenSSL error deriving key agreement"));
  print_openssl_errors ();
out:
  g_clear_pointer (&key_agreement, g_free);
  g_clear_pointer (&ctx, EVP_PKEY_CTX_free);
  g_clear_pointer (&host_pkey, EVP_PKEY_free);
  g_clear_pointer (&device_pkey, EVP_PKEY_free);
  return NULL;
}

/******************************************************************************/

gboolean
fpi_sdcp_generate_host_key (GBytes **private_key,
                            GBytes **public_key,
                            GError **error)
{
  g_autoptr(GBytes) local_private_key = NULL;
  g_autoptr(GBytes) local_public_key = NULL;
  EVP_PKEY *key = EVP_EC_gen ("P-256");

  g_assert (private_key != NULL);
  g_assert (public_key != NULL);

  local_private_key = fpi_sdcp_get_private_key (key, error);
  if (!local_private_key)
    goto out;

  local_public_key = fpi_sdcp_get_public_key (key, error);
  if (!local_public_key)
    goto out;

  EVP_PKEY_free (key);

  *private_key = g_steal_pointer (&local_private_key);
  *public_key = g_steal_pointer (&local_public_key);

  return TRUE;

out:
  print_openssl_errors ();
  g_clear_pointer (&key, EVP_PKEY_free);
  return FALSE;
}

GBytes *
fpi_sdcp_generate_random (GError **error)
{
  g_autoptr(GBytes) res = NULL;
  guint8 *random = g_malloc0 (FPI_SDCP_RANDOM_SIZE);

  if (!RAND_bytes (random, FPI_SDCP_RANDOM_SIZE))
    {
      g_propagate_error (error,
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                   "OpenSSL error generating random"));
      print_openssl_errors ();
      g_free (random);
      return NULL;
    }

  res = fpi_sdcp_bytes_new_secure_take (random, FPI_SDCP_RANDOM_SIZE);

  return g_steal_pointer (&res);
}

gboolean
fpi_sdcp_verify_connect (GBytes                        *host_private_key,
                         GBytes                        *host_random,
                         GBytes                        *device_random,
                         FpiSdcpClaim                  *claim,
                         GBytes                        *mac,
                         FpiDeviceSdcpVerificationFlags verification_flags,
                         GBytes                       **application_secret,
                         GError                       **error)
{
  g_autoptr(GBytes) claim_hash = NULL;
  g_autoptr(GBytes) claim_mac = NULL;
  g_autoptr(GBytes) key_agreement = NULL;
  g_autoptr(GBytes) master_secret = NULL;
  g_autoptr(GBytes) application_keys = NULL;
  g_autoptr(GBytes) out_app_secret = NULL;
  guint8 *app_secret_buf = NULL;

  const guint8 *cert_ptr;
  gsize cert_len = 0;
  X509 *cert = NULL;
  EVP_PKEY *cert_public_pkey = NULL;
  EVP_PKEY *device_public_pkey = NULL;

  fp_dbg ("SDCP Verify ConnectResponse");

  /* SDCP Connect: 5.i. Perform key agreement */

  key_agreement = fpi_sdcp_key_agreement (host_private_key, claim->firmware_public_key, error);
  if (!key_agreement)
    goto out_error;

  fp_dbg ("key_agreement:");
  fp_dbg_hex_dump_gbytes (key_agreement);

  /* SDCP Connect: 5.ii. Derive master secret */

  master_secret = fpi_sdcp_kdf (key_agreement,
                                claim->master_secret_label ?
                                claim->master_secret_label :
                                FPI_SDCP_DEFAULT_LABEL_MASTER_SECRET,
                                host_random, device_random,
                                SDCP_MASTER_SECRET_SIZE, error);
  if (!master_secret)
    goto out_error;

  fp_dbg ("master_secret:");
  fp_dbg_hex_dump_gbytes (master_secret);

  /* SDCP Connect: 5.iii. Derive MAC secret and symetric key */

  application_keys = fpi_sdcp_kdf (master_secret,
                                   claim->application_keys_label ?
                                   claim->application_keys_label :
                                   FPI_SDCP_DEFAULT_LABEL_APPLICATION_KEYS,
                                   NULL, NULL,
                                   SDCP_APPLICATION_KEYS_SIZE, error);
  if (!application_keys)
    goto out_error;

  fp_dbg ("application_keys:");
  fp_dbg_hex_dump_gbytes (application_keys);

  /* slice first half of application_keys as application_secret */
  g_assert (g_bytes_get_size (application_keys) >= FPI_SDCP_APPLICATION_SECRET_SIZE);
  app_secret_buf = g_malloc0 (FPI_SDCP_APPLICATION_SECRET_SIZE);
  memcpy (app_secret_buf,
          g_bytes_get_data (application_keys, NULL),
          FPI_SDCP_APPLICATION_SECRET_SIZE);

  out_app_secret = fpi_sdcp_bytes_new_secure_take (app_secret_buf, FPI_SDCP_APPLICATION_SECRET_SIZE);

  fp_dbg ("application_secret:");
  fp_dbg_hex_dump_gbytes (out_app_secret);

  /* SDCP Connect: 5.iv. Validate the MAC over H(claim) */

  claim_hash = fpi_sdcp_hash_claim (claim, error);
  if (!claim_hash)
    goto out_error;

  claim_mac = fpi_sdcp_mac (out_app_secret,
                            claim->connect_label ?
                            claim->connect_label :
                            FPI_SDCP_DEFAULT_LABEL_CONNECT,
                            claim_hash, NULL, error);
  if (!claim_mac)
    goto out_error;

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
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                   "SDCP ConnectResponse claim validation failed"));
      goto out;
    }


  /* SDCP Connect: 5.v. Unpack the claim (SKIP; already done) */
  /* SDCP Connect: 5.vi. Verify the claim */

  if (!(verification_flags & FPI_DEVICE_SDCP_VERIFICATION_IGNORE_CERTIFICATES))
    {
      /* Validate the certificate */

      cert_ptr = g_bytes_get_data (claim->model_certificate, &cert_len);
      cert = d2i_X509 (NULL, &cert_ptr, cert_len);
      if (!cert)
        {
          g_propagate_error (error,
                             fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                       "Error parsing model certificate"));
          goto out;
        }

      print_certificate (cert);

      if (!fpi_sdcp_verify_certificate (cert, verification_flags, error))
        {
          fp_dbg ("SDCP model certificate verification failed");
          goto out;
        }

      fp_dbg ("SDCP model certificate verified successfully");

      if (!(verification_flags & FPI_DEVICE_SDCP_VERIFICATION_IGNORE_SIGNATURES))
        {
          g_autoptr(GError) local_error = NULL;
          /* Get the certificate's public key */

          cert_public_pkey = X509_get_pubkey (cert);
          if (!cert_public_pkey)
            {
              g_propagate_error (error,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
                                                           "Error getting public key from "
                                                           "model certificate"));
              goto out_error;
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
              goto out_error;
            }

          fp_dbg ("SDCP model signature verified successfully");
          EVP_PKEY_free (cert_public_pkey);

          /* Verify(pk_d, H(C001||h_f||pk_f), s_d) */

          fp_dbg ("device_public_key:");
          fp_dbg_hex_dump_gbytes (claim->device_public_key);

          fp_dbg ("firmware_hash:");
          fp_dbg_hex_dump_gbytes (claim->firmware_hash);

          fp_dbg ("firmware_public_key:");
          fp_dbg_hex_dump_gbytes (claim->firmware_public_key);

          fp_dbg ("device_signature:");
          fp_dbg_hex_dump_gbytes (claim->device_signature);

          device_public_pkey = fpi_sdcp_get_public_pkey (claim->device_public_key, error);
          if (!device_public_pkey)
            goto out_error;

          if (!fpi_sdcp_verify_signature (device_public_pkey,
                                          SDCP_DEVICE_SIGNATURE_HEADER,
                                          claim->firmware_hash,
                                          claim->firmware_public_key,
                                          claim->device_signature,
                                          &local_error))
            {
              g_propagate_prefixed_error (error, g_steal_pointer (&local_error),
                                          "SDCP device signature verification failed: ");
              goto out_error;
            }

          fp_dbg ("SDCP device signature verified successfully");
          EVP_PKEY_free (device_public_pkey);
        }
      X509_free (cert);
    }

  /* output application_secret */

  if (*application_secret)
    g_bytes_unref (*application_secret);

  *application_secret = g_steal_pointer (&out_app_secret);

  return TRUE;

out_error:
  print_openssl_errors ();
out:
  if (!out_app_secret)
    g_clear_pointer (&app_secret_buf, g_free);
  g_clear_pointer (&device_public_pkey, EVP_PKEY_free);
  g_clear_pointer (&cert_public_pkey, EVP_PKEY_free);
  g_clear_pointer (&cert, X509_free);
  return FALSE;
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
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
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
                         fpi_device_error_new_msg (FP_DEVICE_ERROR_UNTRUSTED,
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
