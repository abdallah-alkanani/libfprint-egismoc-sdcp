/*
 * FpiSdcpClaim - SDCP claim structure and lifecycle functions
 * Copyright (C) 2020 Benjamin Berg <bberg@redhat.com>
 * Copyright (C) 2025 Joshua Grisham <josh@joshuagrisham.com>
 * Copyright (C) 2026 Marco Trevisan (Treviño) <mail@3v1n0.net>
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

#include "fpi-sdcp-claim.h"
#include "fpi-sdcp-device.h"

#include <openssl/evp.h>
#include <openssl/err.h>

G_DEFINE_BOXED_TYPE (FpiSdcpClaim, fpi_sdcp_claim, fpi_sdcp_claim_copy, fpi_sdcp_claim_free)

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

/**
 * fpi_sdcp_claim_new:
 *
 * Create an empty #FpiSdcpClaim to provide to the base class.
 *
 * Returns: (transfer full): A newly created #FpiSdcpClaim
 */
FpiSdcpClaim *
fpi_sdcp_claim_new (void)
{
  FpiSdcpClaim *res = NULL;

  res = g_new0 (FpiSdcpClaim, 1);

  res->master_secret_label    = FPI_SDCP_DEFAULT_LABEL_MASTER_SECRET;
  res->application_keys_label = FPI_SDCP_DEFAULT_LABEL_APPLICATION_KEYS;
  res->connect_label          = FPI_SDCP_DEFAULT_LABEL_CONNECT;
  res->reconnect_label        = FPI_SDCP_DEFAULT_LABEL_RECONNECT;
  res->enroll_label           = FPI_SDCP_DEFAULT_LABEL_ENROLL;
  res->identify_label         = FPI_SDCP_DEFAULT_LABEL_IDENTIFY;
  res->sample_label           = FPI_SDCP_DEFAULT_LABEL_SAMPLE;

  return res;
}

/**
 * fpi_sdcp_claim_free:
 * @claim: a #FpiSdcpClaim
 *
 * Release the memory used by an #FpiSdcpClaim.
 */
void
fpi_sdcp_claim_free (FpiSdcpClaim *claim)
{
  g_return_if_fail (claim);

  g_clear_pointer (&claim->model_certificate, g_bytes_unref);
  g_clear_pointer (&claim->device_public_key, g_bytes_unref);
  g_clear_pointer (&claim->firmware_public_key, g_bytes_unref);
  g_clear_pointer (&claim->firmware_hash, g_bytes_unref);
  g_clear_pointer (&claim->model_signature, g_bytes_unref);
  g_clear_pointer (&claim->device_signature, g_bytes_unref);

  g_free (claim);
}

/**
 * fpi_sdcp_claim_copy:
 * @other: The #FpiSdcpClaim to copy
 *
 * Create a (shallow) copy of a #FpiSdcpClaim.
 *
 * Returns: (transfer full): A newly created #FpiSdcpClaim
 */
FpiSdcpClaim *
fpi_sdcp_claim_copy (FpiSdcpClaim *other)
{
  FpiSdcpClaim *res = NULL;

  res = fpi_sdcp_claim_new ();

  res->master_secret_label    = other->master_secret_label;
  res->application_keys_label = other->application_keys_label;
  res->connect_label          = other->connect_label;
  res->reconnect_label        = other->reconnect_label;
  res->enroll_label           = other->enroll_label;
  res->identify_label         = other->identify_label;
  res->sample_label           = other->sample_label;

  if (other->model_certificate)
    res->model_certificate = g_bytes_ref (other->model_certificate);
  if (other->device_public_key)
    res->device_public_key = g_bytes_ref (other->device_public_key);
  if (other->firmware_public_key)
    res->firmware_public_key = g_bytes_ref (other->firmware_public_key);
  if (other->firmware_hash)
    res->firmware_hash = g_bytes_ref (other->firmware_hash);
  if (other->model_signature)
    res->model_signature = g_bytes_ref (other->model_signature);
  if (other->device_signature)
    res->device_signature = g_bytes_ref (other->device_signature);

  return res;
}

/**
 * fpi_sdcp_claim_hash:
 * @claim: The #FpiSdcpClaim to hash
 * @error: (out): #GError in case the return value is %NULL
 *
 * Computes SHA256 over the claim fields (model_certificate || device_public_key
 * || firmware_public_key || firmware_hash || model_signature || device_signature).
 *
 * Returns: A new #GBytes with the SHA256 hash
 */
GBytes *
fpi_sdcp_claim_hash (FpiSdcpClaim *claim,
                     GError      **error)
{
  g_autoptr(GBytes) res = NULL;
  EVP_MD_CTX *sh256_ctx;
  EVP_MD *sha256;
  guint8 *hash = NULL;
  guint hash_len = 0;
  const guint8 *data;
  gsize data_size = 0;

  sh256_ctx = EVP_MD_CTX_create ();
  sha256 = EVP_MD_fetch (NULL, "SHA256", NULL);
  if (!EVP_DigestInit_ex (sh256_ctx, sha256, NULL))
    goto out_error;

  data = g_bytes_get_data (claim->model_certificate, &data_size);
  if (!EVP_DigestUpdate (sh256_ctx, data, data_size))
    goto out_error;

  data = g_bytes_get_data (claim->device_public_key, &data_size);
  if (!EVP_DigestUpdate (sh256_ctx, data, data_size))
    goto out_error;

  data = g_bytes_get_data (claim->firmware_public_key, &data_size);
  if (!EVP_DigestUpdate (sh256_ctx, data, data_size))
    goto out_error;

  data = g_bytes_get_data (claim->firmware_hash, &data_size);
  if (!EVP_DigestUpdate (sh256_ctx, data, data_size))
    goto out_error;

  data = g_bytes_get_data (claim->model_signature, &data_size);
  if (!EVP_DigestUpdate (sh256_ctx, data, data_size))
    goto out_error;

  data = g_bytes_get_data (claim->device_signature, &data_size);
  if (!EVP_DigestUpdate (sh256_ctx, data, data_size))
    goto out_error;

  hash = g_malloc0 (EVP_MAX_MD_SIZE);
  if (!EVP_DigestFinal_ex (sh256_ctx, hash, &hash_len))
    goto out_error;

  EVP_MD_CTX_free (sh256_ctx);
  EVP_MD_free (sha256);

  res = g_bytes_new_take (hash, hash_len);
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
