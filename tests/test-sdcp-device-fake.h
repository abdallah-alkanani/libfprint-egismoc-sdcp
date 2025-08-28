/*
 * Virtual driver for SDCP unit testing
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

#include "fpi-sdcp-device.h"

#include "test-sdcp-utils.h"

#define FPI_TYPE_SDCP_DEVICE_FAKE (fpi_sdcp_device_fake_get_type ())
G_DECLARE_FINAL_TYPE (FpiSdcpDeviceFake, fpi_sdcp_device_fake, FPI, SDCP_DEVICE_FAKE, FpSdcpDevice)

struct _FpiSdcpDeviceFake
{
  FpDevice parent;
  gboolean reconnect_called;
};
