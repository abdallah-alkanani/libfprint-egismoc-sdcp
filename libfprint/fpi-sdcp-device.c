/*
 * FpSdcpDevice - A base class for SDCP enabled devices
 * Copyright (C) 2020 Benjamin Berg <bberg@redhat.com>
 * Copyright (C) 2025 Joshua Grisham <josh@joshuagrisham.com>
 * Copyright (C) 2026 Philip Walsh <packages@drphilth.com>
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

#define FP_COMPONENT "sdcp_device"
#include "fpi-log.h"

#include "fpi-compat.h"
#include "fpi-print.h"

#include "fp-sdcp-device-private.h"
#include "fpi-sdcp.h"
#include "fpi-sdcp-device.h"

/**
 * SECTION: fpi-sdcp-device
 * @title: Internal FpSdcpDevice
 * @short_description: Internal SDCP device routines
 *
 * Internal SDCP handling routines. See #FpSdcpDevice for public routines.
 */

/* Manually redefine what G_DEFINE_* macro does */
static inline gpointer
fp_sdcp_device_get_instance_private (FpSdcpDevice *self)
{
  FpSdcpDeviceClass *sdcp_class = g_type_class_peek_static (FP_TYPE_SDCP_DEVICE);

  return G_STRUCT_MEMBER_P (self,
                            g_type_class_get_instance_private_offset (sdcp_class));
}

/* Example values from Microsoft's SDCP documentation to use when testing (FP_DEVICE_EMULATION=1) */
static const guchar test_host_private_key[] = {
  0x84, 0x00, 0xed, 0x14, 0x57, 0x9c, 0xdf, 0x11, 0x58, 0x64, 0x77, 0xe8, 0x36, 0xe8, 0xcb, 0x52,
  0x70, 0x84, 0x41, 0xc1, 0xc2, 0xa4, 0x47, 0xc2, 0x18, 0xc5, 0xbb, 0xc2, 0xd1, 0x18, 0xfb, 0xc7
};
static const guchar test_host_public_key[] = {
  0x04, 0x52, 0xf0, 0x56, 0xff, 0xb9, 0xc6, 0x72, 0x86, 0x54, 0x77, 0x1a, 0x36, 0x29, 0xb7, 0x70,
  0x76, 0x7b, 0x19, 0xa2, 0x10, 0x6a, 0x49, 0x16, 0xfb, 0x81, 0xba, 0x06, 0xef, 0x67, 0x97, 0xc4,
  0xa3, 0xdf, 0x67, 0x2a, 0xde, 0x0e, 0x91, 0x16, 0xd1, 0xab, 0xe2, 0x78, 0xa8, 0x22, 0x3a, 0xbd,
  0xe4, 0x95, 0x8d, 0x62, 0xd4, 0xff, 0x68, 0x82, 0x15, 0x9f, 0x06, 0x17, 0xc6, 0xf8, 0xce, 0x10,
  0xbf
};
static const gchar test_host_random[] = {
  0xd8, 0x77, 0x40, 0x3a, 0xbe, 0x82, 0xf4, 0xd9, 0x7e, 0x14, 0x48, 0xc5, 0x05, 0x2d, 0x83, 0xa5,
  0x32, 0xa4, 0x5e, 0x56, 0xef, 0x04, 0x9c, 0xbb, 0xf9, 0x81, 0x13, 0x75, 0x20, 0xe7, 0x13, 0xbf
};
static const gchar test_reconnect_random[] = {
  0x8a, 0x74, 0x51, 0xc1, 0xd3, 0xa8, 0xdc, 0xa1, 0xc1, 0x33, 0x0c, 0xa5, 0x0d, 0x73, 0x45, 0x4b,
  0x35, 0x1a, 0x49, 0xf4, 0x6c, 0x8e, 0x9d, 0xce, 0xe1, 0x5c, 0x96, 0x4d, 0x29, 0x5c, 0x31, 0xc9
};
static const gchar test_identify_nonce[] = {
  0x3a, 0x1b, 0x50, 0x6f, 0x5b, 0xec, 0x08, 0x90, 0x59, 0xac, 0xef, 0xb9, 0xb4, 0x4d, 0xfb, 0xde,
  0xa7, 0xa5, 0x99, 0xee, 0x9a, 0xa2, 0x67, 0xe5, 0x25, 0x26, 0x64, 0xd6, 0x0b, 0x79, 0x80, 0x53
};

/* FpiSdcpDevice */

/* Internal functions of FpSdcpDevice */

/**
 * fpi_sdcp_device_get_application_secret:
 * @self: a #FpSdcpDevice fingerprint device
 *
 * Returns the SDCP application secret derived during the connect phase.
 * This is the shared symmetric secret established via ECDH key agreement
 * and used as the HMAC key for all subsequent SDCP MAC operations
 * (reconnect, identify, enrollment ID derivation).
 *
 * This function is intended mostly for testing purposes.
 *
 * Returns: (transfer full): A #GBytes containing the application secret,
 *   or %NULL if no SDCP session has been established yet. The caller owns
 *   the returned value and must call g_bytes_unref() when done.
 */
GBytes *
fpi_sdcp_device_get_application_secret (FpSdcpDevice *self)
{
  GBytes *data = NULL;

  g_object_get (G_OBJECT (self), "sdcp-data", &data, NULL);

  if (!data)
    return NULL;

  return g_steal_pointer (&data);
}

/**
 * fpi_sdcp_device_set_application_secret:
 * @self: a #FpSdcpDevice fingerprint device
 * @application_secret: (transfer none): A #GBytes containing the application secret
 *
 * Stores the SDCP application secret for the current session.
 * This is called internally by the base class after a successful connect.
 * It should not be called by drivers directly.
 */
void
fpi_sdcp_device_set_application_secret (FpSdcpDevice *self,
                                        GBytes       *application_secret)
{
  g_return_if_fail (application_secret);

  g_object_set (G_OBJECT (self), "sdcp-data", application_secret, NULL);
}

void
fpi_sdcp_device_open (FpSdcpDevice *self)
{
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  g_return_if_fail (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_OPEN);

  cls->open (self);
}

void
fpi_sdcp_device_connect (FpSdcpDevice *self)
{
  g_autoptr(GError) error = NULL;
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_object_set (self, "sdcp-data", NULL, NULL);

  g_clear_pointer (&priv->host_private_key, g_bytes_unref);
  g_clear_pointer (&priv->host_public_key, g_bytes_unref);
  g_clear_pointer (&priv->host_random, g_bytes_unref);

  if (!fpi_device_emulation_mode_enabled (FP_DEVICE (self)))
    {
      /* SDCP Connect: 3.i. Generate host ephemeral ECDH key pair */;
      if (!fpi_sdcp_generate_host_key (&priv->host_private_key,
                                       &priv->host_public_key,
                                       &error))
        {
          fpi_sdcp_device_connect_complete (self,
                                            NULL, NULL, NULL,
                                            g_steal_pointer (&error));
          return;
        }

      /* SDCP Connect: 3.ii. Generate host random */
      priv->host_random = fpi_sdcp_generate_random (&error);
      if (!priv->host_random)
        {
          fpi_sdcp_device_connect_complete (self,
                                            NULL, NULL, NULL,
                                            g_steal_pointer (&error));
          return;
        }
    }
  else
    {
      /* Use Microsoft's SDCP documentation example values in emulation mode */
      priv->host_private_key = g_bytes_new (test_host_private_key, sizeof (test_host_private_key));
      priv->host_public_key = g_bytes_new (test_host_public_key, sizeof (test_host_public_key));
      priv->host_random = g_bytes_new (test_host_random, sizeof (test_host_random));
    }

  /* SDCP Connect: 3.iii. Send the Connect message */
  cls->connect (self);

  return;
}

void
fpi_sdcp_device_reconnect (FpSdcpDevice *self)
{
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);
  GError *error = NULL;

  g_clear_pointer (&priv->reconnect_random, g_bytes_unref);

  if (!fpi_device_emulation_mode_enabled (FP_DEVICE (self)))
    {
      /* SDCP Reconnect: 2.i. Generate host random */
      priv->reconnect_random = fpi_sdcp_generate_random (&error);
      if (error)
        {
          fpi_sdcp_device_reconnect_complete (self, NULL, error);
          return;
        }
    }
  else
    {
      /* Use Microsoft's SDCP documentation example value in emulation mode */
      priv->reconnect_random = g_bytes_new (test_reconnect_random, sizeof (test_reconnect_random));
    }

  /* SDCP Reconnect: 2.ii. Send the Reconnect message */
  if (cls->reconnect)
    cls->reconnect (self);
  else
    fpi_sdcp_device_connect (self);
}

void
fpi_sdcp_device_list (FpSdcpDevice *self)
{
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  g_return_if_fail (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_LIST);

  cls->list (self);
}

void
fpi_sdcp_device_enroll (FpSdcpDevice *self)
{
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_autoptr(GBytes) application_secret = NULL;
  FpPrint *print;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  g_return_if_fail (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL);
  application_secret = fpi_sdcp_device_get_application_secret (self);
  g_return_if_fail (application_secret != NULL);

  fpi_device_get_enroll_data (FP_DEVICE (self), &print);

  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data", NULL, NULL);

  g_clear_error (&priv->enroll_error);
  cls->enroll (self);
}

void
fpi_sdcp_device_identify (FpSdcpDevice *self)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);

  g_autoptr(GBytes) application_secret = NULL;
  FpiDeviceAction action;
  GError *error = NULL;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  action = fpi_device_get_current_action (FP_DEVICE (self));
  g_return_if_fail (action == FPI_DEVICE_ACTION_IDENTIFY || action == FPI_DEVICE_ACTION_VERIFY);
  application_secret = fpi_sdcp_device_get_application_secret (self);
  g_return_if_fail (application_secret != NULL);

  g_clear_pointer (&priv->identify_nonce, g_bytes_unref);

  if (!fpi_device_emulation_mode_enabled (FP_DEVICE (self)))
    {
      /* Generate a new nonce. */
      priv->identify_nonce = fpi_sdcp_generate_random (&error);
      if (error)
        {
          fpi_device_action_error (FP_DEVICE (self), error);
          return;
        }
    }
  else
    {
      /* Use Microsoft's SDCP documentation example value in emulation mode */
      priv->identify_nonce = g_bytes_new (test_identify_nonce, sizeof (test_identify_nonce));
    }

  cls->identify (self);
}

/*********************************************************/
/* Private API */

/**
 * fpi_sdcp_device_open_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @error: A #GError or %NULL on success
 *
 * Reports completion of open operation. Responsible for triggering SDCP connect
 * or reconnect as necessary.
 */
void
fpi_sdcp_device_open_complete (FpSdcpDevice *self,
                               GError       *error)
{
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);

  g_autoptr(GBytes) application_secret = NULL;

  if (error)
    {
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }


  application_secret = fpi_sdcp_device_get_application_secret (self);

  /* Try a reconnect if implemented and we already have an application_secret */
  if (cls->reconnect && application_secret)
    fpi_sdcp_device_reconnect (self);

  /* Otherwise connect. A device must not keep its master secret across power
   * loss, so an old secret is only reused once Reconnect proves it. */
  else
    fpi_sdcp_device_connect (self);
}

/**
 * fp_sdcp_device_get_connect_data:
 * @self: a #FpSdcpDevice fingerprint device
 * @host_random: (out) (transfer full): The host-generated random
 * @host_public_key: (out) (transfer full): The host public key
 *
 * Get data required to connect to (i.e. open) the device securely.
 */
void
fpi_sdcp_device_get_connect_data (FpSdcpDevice *self,
                                  GBytes      **host_random,
                                  GBytes      **host_public_key)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_return_if_fail (host_random != NULL);
  g_return_if_fail (host_public_key != NULL);
  g_return_if_fail (priv->host_random);
  g_return_if_fail (priv->host_public_key);

  *host_random = g_bytes_new_from_bytes (priv->host_random, 0,
                                         g_bytes_get_size (priv->host_random));
  *host_public_key = g_bytes_new_from_bytes (priv->host_public_key, 0,
                                             g_bytes_get_size (priv->host_public_key));
}

/**
 * fp_sdcp_device_get_reconnect_data:
 * @self: a #FpSdcpDevice fingerprint device
 * @reconnect_random: (out) (transfer full): The host-generated random
 *
 * Get data required to reconnect to (i.e. open) to the device securely.
 */
void
fpi_sdcp_device_get_reconnect_data (FpSdcpDevice *self,
                                    GBytes      **reconnect_random)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_return_if_fail (reconnect_random != NULL);
  g_return_if_fail (priv->reconnect_random);

  *reconnect_random = g_bytes_new_from_bytes (priv->reconnect_random, 0,
                                              g_bytes_get_size (priv->reconnect_random));
}

/**
 * fp_sdcp_device_get_identify_data:
 * @self: a #FpSdcpDevice fingerprint device
 * @nonce: (out) (transfer full): A new host-generated nonce
 *
 * Get data required to identify a new print.
 */
void
fpi_sdcp_device_get_identify_data (FpSdcpDevice *self,
                                   GBytes      **nonce)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_return_if_fail (nonce != NULL);
  g_return_if_fail (priv->identify_nonce);

  *nonce = g_bytes_new_from_bytes (priv->identify_nonce, 0,
                                   g_bytes_get_size (priv->identify_nonce));
}

/**
 * fp_sdcp_device_set_identify_data:
 * @self: a #FpSdcpDevice fingerprint device
 * @nonce: A driver-specified nonce
 *
 * Sets data required to identify a new print.
 *
 * Most drivers should not use this function, but instead use the automatically
 * generated values retrieved from fpi_sdcp_device_get_identify_data() when
 * executing the device-specific Identify command.
 *
 * In cases where a device's Identify command does not accept a randomly
 * generated nonce, this function can be used to override the randomly generated
 * nonce to the nonce that was actually sent to the device.
 */
void
fpi_sdcp_device_set_identify_data (FpSdcpDevice *self,
                                   GBytes       *nonce)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_return_if_fail (nonce != NULL);

  g_clear_pointer (&priv->identify_nonce, g_bytes_unref);

  priv->identify_nonce = g_steal_pointer (&nonce);
}

/**
 * fpi_sdcp_device_connect_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @device_random: (transfer none): The device random
 * @claim: (transfer none): The device #FpiSdcpClaim
 * @mac: (transfer none): The MAC authenticating @claim
 * @error: (transfer full): A #GError or %NULL on success
 *
 * Reports completion of connect operation. Responsible for performing SDCP key
 * agreement, deriving secrets necessary for processing all other SDCP-related
 * payloads, and verifying the device connection is trusted.
 */
gboolean
fpi_sdcp_device_connect_complete (FpSdcpDevice *self,
                                  GBytes       *device_random,
                                  FpiSdcpClaim *claim,
                                  GBytes       *mac,
                                  GError       *error)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);

  g_autoptr(GBytes) application_secret = NULL;
  FpiDeviceAction action;
  gboolean success;

  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_val_if_fail (action == FPI_DEVICE_ACTION_OPEN, FALSE);

  if (error)
    goto out;

  if (!priv->host_private_key || !priv->host_random ||
      !device_random || !claim || !mac ||
      !claim->model_certificate || !claim->device_public_key || !claim->firmware_public_key ||
      !claim->firmware_hash || !claim->model_signature || !claim->device_signature)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Incomplete SDCP Connect information");
      goto out;
    }

  /* Verify connect and store the application_secret */
  application_secret = fpi_sdcp_verify_connect (priv->host_private_key,
                                                priv->host_random,
                                                device_random,
                                                claim,
                                                mac,
                                                cls->get_ca_store ? cls->get_ca_store (self) : NULL,
                                                cls->verification_flags,
                                                &error);
  if (!application_secret)
    {
      g_prefix_error (&error, "SDCP Connect verification failed: ");
      goto out;
    }

  fpi_sdcp_device_set_application_secret (self, application_secret);

  /* Store per-session labels from the claim for post-connect operations */
  priv->reconnect_label = claim->reconnect_label ?
                          claim->reconnect_label :
                          FPI_SDCP_DEFAULT_LABEL_RECONNECT;
  priv->identify_label  = claim->identify_label ?
                          claim->identify_label :
                          FPI_SDCP_DEFAULT_LABEL_IDENTIFY;
  priv->enroll_label    = claim->enroll_label ?
                          claim->enroll_label :
                          FPI_SDCP_DEFAULT_LABEL_ENROLL;

out:
  /* Clear ephemeral host material on both success and failure. Input claim,
   * random and MAC remain owned by the driver. */
  g_clear_pointer (&priv->host_private_key, g_bytes_unref);
  g_clear_pointer (&priv->host_public_key, g_bytes_unref);
  g_clear_pointer (&priv->host_random, g_bytes_unref);

  success = error == NULL;
  fpi_device_open_complete (FP_DEVICE (self), error);
  return success;
}

/**
 * fpi_sdcp_device_reconnect_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @mac: (transfer none) (nullable): The MAC authenticating the reconnect
 * @error: (transfer full): A #GError or %NULL on success
 *
 * Reports completion of a reconnect (i.e. open) operation.
 */
void
fpi_sdcp_device_reconnect_complete (FpSdcpDevice *self,
                                    GBytes       *mac,
                                    GError       *error)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  FpiDeviceAction action;

  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_if_fail (action == FPI_DEVICE_ACTION_OPEN);
  if (!priv->reconnect_random)
    {
      /* Random generation can fail before a reconnect message is sent. */
      if (!error)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                          "Missing SDCP reconnect random");
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  if (error)
    {
      /* The caller retains ownership of the ignored MAC. */
      if (mac)
        fp_warn ("Driver provided a reconnect MAC but also reported an error.");

      fp_warn ("SDCP Reconnect failed with error: %s. Falling back to full connect.",
               error->message);
      g_clear_error (&error);

      /* Silently try a normal connect instead. */
      fpi_sdcp_device_connect (self);
    }
  else if (mac)
    {
      g_autoptr(GBytes) application_secret = NULL;

      application_secret = fpi_sdcp_device_get_application_secret (self);

      if (fpi_sdcp_verify_reconnect (application_secret,
                                     priv->reconnect_label,
                                     priv->reconnect_random,
                                     mac, &error))
        {
          fp_dbg ("SDCP Reconnect succeeded");
          fpi_device_open_complete (FP_DEVICE (self), NULL);
        }
      else
        {
          fp_dbg ("SDCP Reconnect failed: %s; doing a full connect",
                  error->message);
          g_clear_error (&error);
          fpi_sdcp_device_connect (self);
        }
    }
  else
    {
      fpi_device_open_complete (FP_DEVICE (self),
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "Driver called reconnect complete with wrong arguments"));
    }

  /* Clear no longer needed private data */
  g_clear_pointer (&priv->reconnect_random, g_bytes_unref);
}

/**
 * fpi_sdcp_device_list_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @ids: A #GPtrArray of #GBytes of each SDCP enrollment ID stored on the device
 * @error: A #GError or %NULL on success
 *
 * Convenience function to create the minimally required #FpPrint list for
 * #FpSdcpDevice prints using the provided @ids, then uses that #FpPrint list to
 * report completion of the list operation.
 *
 * If the device provides additional attributes that should be stored on each
 * #FpPrint as part of the list operation, a #GPtrArray of #FpPrint can instead
 * be created with the additional attributes and fpi_device_list_complete() can
 * be used instead of this function.
 *
 * Please note that the @ids array will be freed using g_ptr_array_unref() and
 * the elements are destroyed automatically. As such, you must use
 * g_ptr_array_new_with_free_func() with `(GDestroyNotify) g_bytes_unref` as the
 * free func when creating the #GPtrArray.
 */
void
fpi_sdcp_device_list_complete (FpSdcpDevice *self,
                               GPtrArray    *ids,
                               GError       *error)
{
  g_autoptr(GPtrArray) prints = NULL;
  gint prints_len = 0;
  FpiDeviceAction action;

  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_if_fail (action == FPI_DEVICE_ACTION_LIST);

  if (error)
    {
      fpi_device_list_complete (FP_DEVICE (self), NULL, error);
      g_clear_pointer (&ids, g_ptr_array_unref);
      return;
    }

  prints = g_ptr_array_new_with_free_func (g_object_unref);

  /* Allow an empty array (prints_len=0) but if ids has been passed, use it */
  if (ids)
    prints_len = ids->len;

  for (gint i = 0; i < prints_len; i++)
    {
      FpPrint *print = fp_print_new (FP_DEVICE (self));
      fpi_print_set_type (print, FPI_PRINT_SDCP);
      /* Every ID returned by list refers to an existing on-device print. */
      fpi_print_set_device_stored (print, TRUE);
      fpi_print_sdcp_set_id (print, g_ptr_array_index (ids, i));
      g_ptr_array_add (prints, g_object_ref_sink (print));
    }

  fpi_device_list_complete (FP_DEVICE (self), g_steal_pointer (&prints), NULL);

  g_clear_pointer (&ids, g_ptr_array_unref);
}

/**
 * fpi_sdcp_device_enroll_commit:
 * @self: a #FpSdcpDevice fingerprint device
 * @nonce: The device generated nonce
 * @error: a #GError or %NULL on success
 *
 * Called when the print is ready to be committed to device memory.
 * During enrollment, fpi_device_enroll_progress() must be called for each
 * successful stage before the print can be committed.
 * The @nonce generated by the device-specific EnrollmentNonce response must be
 * provided in order for the enrollment ID to be generated.
 * The driver's enroll_commit() vfunc will be triggered upon successfully
 * generating the enrollment ID.
 */
void
fpi_sdcp_device_enroll_commit (FpSdcpDevice *self,
                               GBytes       *nonce,
                               GError       *error)
{
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_autoptr(GBytes) application_secret = NULL;
  GBytes *id = NULL;
  FpPrint *print;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  g_return_if_fail (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL);

  fpi_device_get_enroll_data (FP_DEVICE (self), &print);
  application_secret = fpi_sdcp_device_get_application_secret (self);

  if (!error && !nonce)
    error = fpi_device_error_new (FP_DEVICE_ERROR_PROTO);
  if (!error)
    id = fpi_sdcp_generate_enrollment_id (application_secret, priv->enroll_label, nonce, &error);
  if (!id || error)
    {
      /* Finish only after the driver has aborted its device-side enrollment. */
      g_clear_pointer (&id, g_bytes_unref);
      g_clear_error (&priv->enroll_error);
      priv->enroll_error = error;
      cls->enroll_commit (self, NULL);
      return;
    }

  /* Set to true once committed */
  fpi_print_set_device_stored (print, FALSE);

  /* Attach the ID to the print */
  fpi_print_sdcp_set_id (print, id);

  cls->enroll_commit (self, id);

  g_clear_pointer (&id, g_bytes_unref);
}

/**
 * fpi_sdcp_device_enroll_commit_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @error: a #GError or %NULL on success
 *
 * Called when device has committed the given print to memory.
 * This finalizes the enroll operation.
 */
void
fpi_sdcp_device_enroll_commit_complete (FpSdcpDevice *self,
                                        GError       *error)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_autoptr(GBytes) id = NULL;
  FpPrint *print;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  g_return_if_fail (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL);

  if (priv->enroll_error)
    {
      g_clear_error (&error);
      error = g_steal_pointer (&priv->enroll_error);
    }

  if (error)
    {
      fpi_device_enroll_complete (FP_DEVICE (self), NULL, error);
      return;
    }

  fpi_device_get_enroll_data (FP_DEVICE (self), &print);

  id = fpi_print_sdcp_get_id (print);
  if (!id)
    {
      g_error ("Inconsistent state; the print must have the enrolled ID attached at this point");
      return;
    }

  fpi_print_set_type (print, FPI_PRINT_SDCP);
  fpi_print_set_device_stored (print, TRUE);

  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
}

/**
 * fpi_sdcp_device_identify_retry:
 * @self: a #FpSdcpDevice fingerprint device
 * @error: a #GError containing the retry condition
 *
 * Called when the device requires the finger to be presented again.
 * This should not be called for a verified no-match, it should only
 * be called if e.g. the finger was not centered properly or similar.
 *
 * Effectively this simply raises the error up. This function exists
 * to bridge the difference in semantics that SDPC has from how
 * libfprint works internally.
 */
void
fpi_sdcp_device_identify_retry (FpSdcpDevice *self,
                                GError       *error)
{
  FpiDeviceAction action;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_if_fail (action == FPI_DEVICE_ACTION_IDENTIFY || action == FPI_DEVICE_ACTION_VERIFY);

  if (action == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_ERROR, NULL, error);
  else if (action == FPI_DEVICE_ACTION_IDENTIFY)
    fpi_device_identify_report (FP_DEVICE (self), NULL, NULL, error);
}

/**
 * fpi_sdcp_device_identify_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @id: (transfer none): the ID as reported by the device
 * @mac: (transfer none): MAC authenticating the message
 * @error: (transfer full): #GError if an error occured
 *
 * Called when device is done with the identification routine. The
 * returned ID may be %NULL if none of the in-device templates matched.
 */
void
fpi_sdcp_device_identify_complete (FpSdcpDevice *self,
                                   GBytes       *id,
                                   GBytes       *mac,
                                   GError       *error)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_autoptr(GBytes) application_secret = NULL;
  FpPrint *identified_print;
  FpiDeviceAction action;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_if_fail (action == FPI_DEVICE_ACTION_IDENTIFY || action == FPI_DEVICE_ACTION_VERIFY);
  g_return_if_fail (priv->identify_nonce);

  if (error)
    {
      g_clear_pointer (&priv->identify_nonce, g_bytes_unref);
      fpi_device_action_error (FP_DEVICE (self), error);
      return;
    }

  /* Both values absent is the one valid representation of no match. */
  if (!id && !mac)
    {
      g_clear_pointer (&priv->identify_nonce, g_bytes_unref);
      if (action == FPI_DEVICE_ACTION_VERIFY)
        {
          fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_FAIL, NULL, NULL);
          fpi_device_verify_complete (FP_DEVICE (self), NULL);
        }
      else
        {
          fpi_device_identify_report (FP_DEVICE (self), NULL, NULL, NULL);
          fpi_device_identify_complete (FP_DEVICE (self), NULL);
        }
      return;
    }

  if (!id || !mac || g_bytes_get_size (id) != FPI_SDCP_ENROLLMENT_ID_SIZE ||
      g_bytes_get_size (mac) != FPI_SDCP_MAC_SIZE)
    {
      g_clear_pointer (&priv->identify_nonce, g_bytes_unref);
      fpi_device_action_error (FP_DEVICE (self),
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Malformed SDCP Identify result"));
      return;
    }

  application_secret = fpi_sdcp_device_get_application_secret (self);

  if (!fpi_sdcp_verify_identify (application_secret,
                                 priv->identify_label,
                                 priv->identify_nonce,
                                 id, mac, &error))
    {
      g_clear_pointer (&priv->identify_nonce, g_bytes_unref);
      fpi_device_action_error (FP_DEVICE (self), error);
      return;
    }

  /* Clear no longer needed private data */
  g_clear_pointer (&priv->identify_nonce, g_bytes_unref);

  /* Create a new print */
  identified_print = fp_print_new (FP_DEVICE (self));

  fpi_print_set_type (identified_print, FPI_PRINT_SDCP);

  /* Identification returns an existing on-device enrollment. */
  fpi_print_set_device_stored (identified_print, TRUE);

  /* Attach the ID to the print */
  fpi_print_sdcp_set_id (identified_print, id);


  /* The surrounding API expects a match/no-match against a given set. */
  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *print;

      fpi_device_get_verify_data (FP_DEVICE (self), &print);

      if (fp_print_equal (print, identified_print))
        fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_SUCCESS, identified_print, NULL);
      else
        fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_FAIL, identified_print, NULL);

      fpi_device_verify_complete (FP_DEVICE (self), NULL);
    }
  else
    {
      GPtrArray *prints;
      gint i;

      fpi_device_get_identify_data (FP_DEVICE (self), &prints);

      for (i = 0; i < prints->len; i++)
        {
          FpPrint *print = g_ptr_array_index (prints, i);

          if (fp_print_equal (print, identified_print))
            {
              fpi_device_identify_report (FP_DEVICE (self), print, identified_print, NULL);
              fpi_device_identify_complete (FP_DEVICE (self), NULL);
              return;
            }
        }

      /* Print wasn't in database. */
      fpi_device_identify_report (FP_DEVICE (self), NULL, identified_print, NULL);
      fpi_device_identify_complete (FP_DEVICE (self), NULL);
    }
}

#ifdef TOD_LIBRARY
#include "tod/tod-fpi-sdcp-device.c"
#endif
