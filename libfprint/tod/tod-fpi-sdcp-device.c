/*
 * Shared library loader for libfprint
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

#include "tod-wrappers.h"
#include "fpi-sdcp-device.h"

void
fpi_sdcp_device_get_application_secret_1_95 (FpSdcpDevice *device,
                                             GBytes      **secret)
{
  g_return_if_fail (secret != NULL);

  *secret = fpi_sdcp_device_get_application_secret (device);
}
