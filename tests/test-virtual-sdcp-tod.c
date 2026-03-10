/*
 * TOD entry point for the virtual SDCP driver test module
 * Copyright (C) 2026 Marco Trevisan (Treviño) <marco.trevisan@canonical.com>
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

/* The driver implementation is compiled from virtual-sdcp.c with
 * -DTEST_TOD_DRIVER=1; this file only provides the TOD entry point. */

#include <glib-object.h>
#include <gmodule.h>

/* Provided by virtual-sdcp.c compiled with -DTEST_TOD_DRIVER. */
extern GType fpi_device_virtual_sdcp_get_type (void);

G_MODULE_EXPORT GType fpi_tod_shared_driver_get_type (void);

G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_virtual_sdcp_get_type ();
}
