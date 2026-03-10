/*
 * FpSdcpDevice - A base class for SDCP enabled devices
 * Copyright (C) 2020 Benjamin Berg <bberg@redhat.com>
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

#pragma once

#include "fpi-device.h"
#include "fpi-enums.h"

#include "fpi-sdcp-claim.h"
#include "fp-sdcp-device.h"
#include "tod/tod-macros.h"

#define FPI_SDCP_RANDOM_SIZE 32
#define FPI_SDCP_APPLICATION_SECRET_SIZE 32
#define FPI_SDCP_ENROLLMENT_ID_SIZE 32
#define FPI_SDCP_NONCE_SIZE 32
#define FPI_SDCP_MAC_SIZE 32
#define FPI_SDCP_DIGEST_SIZE 32           /* SHA256 */
#define FPI_SDCP_CURVE_FIELD_SIZE 32      /* P256 */
#define FPI_SDCP_PUBLIC_KEY_SIZE 65       /* 0x04||x||y */
#define FPI_SDCP_PRIVATE_KEY_SIZE 32      /* log_2(n)/8 */
#define FPI_SDCP_SIGNATURE_SIZE 64        /* r||s */
#define FPI_SDCP_ENCRYPTION_BLOCK_SIZE 16 /* AES */
#define FPI_SDCP_ENCRYPTION_KEY_SIZE 32   /* AES256 */
#define FPI_SDCP_MASTER_SECRET_SIZE 32
#define FPI_SDCP_APPLICATION_KEYS_SIZE 64


#define FPI_SDCP_DEFAULT_LABEL_MASTER_SECRET "master secret"
#define FPI_SDCP_DEFAULT_LABEL_APPLICATION_KEYS "application keys"
#define FPI_SDCP_DEFAULT_LABEL_CONNECT "connect"
#define FPI_SDCP_DEFAULT_LABEL_RECONNECT "reconnect"
#define FPI_SDCP_DEFAULT_LABEL_SAMPLE "sample"
#define FPI_SDCP_DEFAULT_LABEL_ENROLL "enroll"
#define FPI_SDCP_DEFAULT_LABEL_IDENTIFY "identify"

#define FPI_SDCP_CA_STORE_PATH "/org/freedesktop/fprint/SDCP/ca-store/"

/**
 * FpiDeviceSdcpVerificationFlags:
 * @FPI_DEVICE_SDCP_VERIFICATION_DEFAULT: No flags. Perform all verifications.
 * @FPI_DEVICE_SDCP_VERIFICATION_IGNORE_CERTIFICATES: Skip validating the
 *   device's #FpiSdcpClaim.model_certificate against the SDCP CA store.
 *   SDCP CA store.
 *   It determines if the model certificate (cert_m) should be parsed and
 *   its trust chain validated as issued from Microsoft's well-known issuers.
 * @FPI_DEVICE_SDCP_VERIFICATION_IGNORE_SIGNATURES: Skip validating the
 *   #FpiSdcpClaim.model_signature and #FpiSdcpClaim.device_signature.
 *   It determines if the model signature (s_m) and device signature (s_d)
 *   should be validated against the certificate and keys provided in the claim.
 * @FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NO_CHECK_TIME: Skip validating the
 *   certificate's validity period.
 * @FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NON_X509_STRICT: Use a less strict
 *   validation approach for the certificate, allowing certain non-critical
 *   issues to be ignored.
 * @FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_ALLOW_PARTIAL_CHAIN: Allow
 *   validation of the certificate even if the trust chain is incomplete.
 *
 * Bitfield of SDCP verification flags for a device.
 */
typedef enum {
  FPI_DEVICE_SDCP_VERIFICATION_DEFAULT = 0,
  FPI_DEVICE_SDCP_VERIFICATION_IGNORE_CERTIFICATES = 1 << 0,
  FPI_DEVICE_SDCP_VERIFICATION_IGNORE_SIGNATURES = 1 << 1,

  FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NO_CHECK_TIME = 1 << 8,
  FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NON_X509_STRICT = 1 << 9,
  FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_ALLOW_PARTIAL_CHAIN = 1 << 10,
} FpiDeviceSdcpVerificationFlags;

/**
 * FpSdcpDeviceClass:
 * @verification_flags: Bitfield of #FpiDeviceSdcpVerificationFlags to control
 *   verification behavior.
 * @open: Open the device. Similar to #FpDeviceClass.open except that
 *   completion with fpi_sdcp_device_open_complete() will also take care of
 *   executing @connect and @reconnect as necessary.
 * @connect: Establish SDCP connection.
 * @reconnect: Perform a faster reconnect. Drivers do not need to provide this
 *   function. If reconnect fails, then a normal connect will be tried.
 * @list: List prints stored on the device. The driver must create a #GPtrArray
 *   of #GBytes with each enrollment ID stored on the device and use it to call
 *   fpi_sdcp_device_list_complete() in order to complete the operation.
 * @enroll: Start the enrollment procedure and capture all samples. The driver
 *   must report enrollment progress using fpi_device_enroll_progress(). It
 *   should also store available metadata about the print in device memory. The
 *   driver must call fpi_sdcp_device_enroll_commit() when all enrollment stages
 *   are complete and the print is ready to be commited to the device.
 * @enroll_commit: Commit the newly-enrolled print to the device memory using
 *   the passed id. id may be %NULL, in which case the driver must abort the
 *   enrollment process. id is owned by the base class and remains valid
 *   throughout the operation. On completion, the driver must call
 *   fpi_sdcp_device_enroll_commit_complete().
 * @identify: Start identification process. On completion, the driver must call
 *   fpi_sdcp_device_identify_complete(). To request the user to retry the
 *   fpi_sdcp_device_identify_retry() function is used.
 * @get_ca_store: (optional): Return a #GResource containing additional PEM
 *   certificates at the path %FPI_SDCP_CA_STORE_PATH that will be merged
 *   into the default SDCP CA store during certificate verification.
 *   This allows drivers to supply device-specific CA certificates
 *   without affecting other devices. If not implemented, only the default CA
 *   store is used.
 *
 * These are the main entry points for drivers implementing SDCP.
 *
 * Drivers *must* eventually call the corresponding function to finish the
 * operation.
 *
 * The following #FpDeviceClass entry points are also compatible and can be set
 * on the #FpDeviceClass if supported for a given device:
 * - #FpDeviceClass.probe
 * - #FpDeviceClass.close
 * - #FpDeviceClass.delete
 * - #FpDeviceClass.clear_storage
 * - #FpDeviceClass.cancel
 * - #FpDeviceClass.suspend
 * - #FpDeviceClass.resume
 *
 * Drivers *must* also handle cancellation properly for any long running
 * operation (i.e. any operation that requires capturing). It is entirely fine
 * to ignore cancellation requests for short operations (e.g. open/close).
 *
 * This API is solely intended for drivers. It is purely internal and neither
 * API nor ABI stable.
 */
struct _FpSdcpDeviceClass
{
  FpDeviceClass                  parent_class;

  FpiDeviceSdcpVerificationFlags verification_flags;

  void                           (*open)            (FpSdcpDevice *sdcp_device);
  void                           (*connect)         (FpSdcpDevice *sdcp_device);
  void                           (*reconnect)       (FpSdcpDevice *sdcp_device);
  void                           (*list)            (FpSdcpDevice *sdcp_device);
  void                           (*enroll)          (FpSdcpDevice *sdcp_device);
  void                           (*enroll_commit)   (FpSdcpDevice *sdcp_device,
                                                     GBytes       *id);
  void                           (*identify)        (FpSdcpDevice *sdcp_device);

  GResource                    * (*get_ca_store)    (FpSdcpDevice *sdcp_device);

  /*< private >*/
  /* padding for future expansion */
  TOD_PADDING_ALIGNED (32, sizeof (GResource * (*)(FpSdcpDevice *)));
};

void fpi_sdcp_device_open_complete (FpSdcpDevice *self,
                                    GError       *error);

void fpi_sdcp_device_get_connect_data (FpSdcpDevice *self,
                                       GBytes      **host_random,
                                       GBytes      **host_public_key);
void fpi_sdcp_device_connect_complete (FpSdcpDevice *self,
                                       GBytes       *device_random,
                                       FpiSdcpClaim *claim,
                                       GBytes       *mac,
                                       GError       *error);

void fpi_sdcp_device_get_reconnect_data (FpSdcpDevice *self,
                                         GBytes      **reconnect_random);
void fpi_sdcp_device_reconnect_complete (FpSdcpDevice *self,
                                         GBytes       *mac,
                                         GError       *error);

void fpi_sdcp_device_list_complete (FpSdcpDevice *self,
                                    GPtrArray    *ids,
                                    GError       *error);

void fpi_sdcp_device_enroll_commit (FpSdcpDevice *self,
                                    GBytes       *nonce,
                                    GError       *error);
void fpi_sdcp_device_enroll_commit_complete (FpSdcpDevice *self,
                                             GError       *error);

void fpi_sdcp_device_get_identify_data (FpSdcpDevice *self,
                                        GBytes      **nonce);
void fpi_sdcp_device_set_identify_data (FpSdcpDevice *self,
                                        GBytes       *nonce);
void fpi_sdcp_device_identify_retry (FpSdcpDevice *self,
                                     GError       *error);
void fpi_sdcp_device_identify_complete (FpSdcpDevice *self,
                                        GBytes       *id,
                                        GBytes       *mac,
                                        GError       *error);
