/*
 * FpDevice - A fingerprint reader device
 * Copyright (C) 2021 Marco Trevisan <marco.trevisan@canonical.com>
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

#include <glib.h>
#include <glib-object.h>

#include "fpi-device.h"

typedef struct _FpSdcpDevice  FpSdcpDevice;
typedef struct _FpDeviceClass FpDeviceClass;

typedef enum {
  FPI_DEVICE_SDCP_VERIFICATION_TODV1_95_0_IGNORE_CERTIFICATES = 1 << 0,
  FPI_DEVICE_SDCP_VERIFICATION_TODV1_95_0_IGNORE_SIGNATURES = 1 << 1,

  FPI_DEVICE_SDCP_VERIFICATION_TODV1_95_0_CERTIFICATE_NO_CHECK_TIME = 1 << 8,
  FPI_DEVICE_SDCP_VERIFICATION_TODV1_95_0_CERTIFICATE_NON_X509_STRICT = 1 << 9,
  FPI_DEVICE_SDCP_VERIFICATION_TODV1_95_0_CERTIFICATE_ALLOW_PARTIAL_CHAIN = 1 << 10,
} FpiDeviceSdcpVerificationFlagsTODV1_95_0;


struct _FpiSdcpClaimTODV1_95_0
{
  /*< public >*/
  const char *master_secret_label;
  const char *application_keys_label;
  const char *connect_label;
  const char *reconnect_label;
  const char *enroll_label;
  const char *identify_label;
  const char *sample_label;

  GBytes     *model_certificate;   /* cert_m */
  GBytes     *device_public_key;   /* pk_d   */
  GBytes     *firmware_public_key; /* pk_f   */
  GBytes     *firmware_hash;       /* h_f    */
  GBytes     *model_signature;     /* s_m    */
  GBytes     *device_signature;    /* s_d    */

  /*< private >*/
  /* padding for future expansion */
  TOD_PADDING_ALIGNED (16, 0);
} FpiSdcpClaim;

typedef struct _FpiSdcpClaimTODV1_95_0 FpiSdcpClaimTODV1_95_0;


struct _FpSdcpDeviceClassTODV1_95_0
{
  FpDeviceClass                            parent_class;

  FpiDeviceSdcpVerificationFlagsTODV1_95_0 verification_flags;

  void                                     (*open)          (FpSdcpDevice *sdcp_device);
  void                                     (*connect)       (FpSdcpDevice *sdcp_device);
  void                                     (*reconnect)     (FpSdcpDevice *sdcp_device);
  void                                     (*list)          (FpSdcpDevice *sdcp_device);
  void                                     (*enroll)        (FpSdcpDevice *sdcp_device);
  void                                     (*enroll_commit) (FpSdcpDevice *sdcp_device,
                                                             GBytes       *id);
  void                                     (*identify)      (FpSdcpDevice *sdcp_device);

  /*< private >*/
  /* padding for future expansion */
  TOD_PADDING_ALIGNED (32, 0);
};

typedef struct _FpSdcpDeviceClassTODV1_95_0 FpSdcpDeviceClassTODV1_95_0;

struct _FpSdcpDeviceClassTODV1_95_1
{
  FpDeviceClass                            parent_class;

  FpiDeviceSdcpVerificationFlagsTODV1_95_0 verification_flags;

  void                                     (*open)            (FpSdcpDevice *sdcp_device);
  void                                     (*connect)         (FpSdcpDevice *sdcp_device);
  void                                     (*reconnect)       (FpSdcpDevice *sdcp_device);
  void                                     (*list)            (FpSdcpDevice *sdcp_device);
  void                                     (*enroll)          (FpSdcpDevice *sdcp_device);
  void                                     (*enroll_commit)   (FpSdcpDevice *sdcp_device,
                                                               GBytes       *id);
  void                                     (*identify)        (FpSdcpDevice *sdcp_device);

  GResource                              * (*get_trust_store) (FpSdcpDevice *sdcp_device);

  /*< private >*/
  /* padding for future expansion */
  TOD_PADDING_ALIGNED (32, sizeof (GResource * (*)(FpSdcpDevice *)));
};

typedef struct _FpSdcpDeviceClassTODV1_95_1 FpSdcpDeviceClassTODV1_95_1;
