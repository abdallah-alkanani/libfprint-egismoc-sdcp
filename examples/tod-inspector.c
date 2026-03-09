/*
 * Shared library loader for libfprint
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

#include <glib-object.h>
#include <libfprint/fprint.h>

#include "libfprint/tod/tod-shared-loader.h"
#include "libfprint/fpi-sdcp-device.h"
#include "libfprint/fpi-image-device.h"
#include "libfprint/fpi-device.h"

static char *
id_table_to_string (FpDeviceType     device_type,
                    const FpIdEntry *id_table)
{
  const FpIdEntry *entry;
  char *str = NULL;

  if (!id_table)
    return g_strdup ("INVALID: Empty ID table");

  entry = id_table;
  while (TRUE)
    {
      g_autofree char *value = NULL;

      if (device_type == FP_DEVICE_TYPE_VIRTUAL)
        {
          if (entry->virtual_envvar)
            value = g_strdup (entry->virtual_envvar);
        }
      else if (device_type == FP_DEVICE_TYPE_USB)
        {
          if (entry->vid)
            value = g_strdup_printf ("%04x:%04x", entry->vid, entry->pid);
        }
      else if (device_type == FP_DEVICE_TYPE_UDEV)
        {
          if (entry->hid_id.vid)
            {
              g_autofree gchar *udev_flags = NULL;

              udev_flags = g_flags_to_string (fpi_device_udev_subtype_flags_get_type (),
                                              entry->udev_types);
              value = g_strdup_printf ("%s (%04x:%04x) [%s]",
                                       entry->spi_acpi_id,
                                       entry->hid_id.vid, entry->hid_id.pid,
                                       udev_flags);
            }
          else
            {
              value = g_strdup (entry->spi_acpi_id);
            }
        }
      else
        {
          return g_strdup ("Unsupported device type");
        }

      if (!value)
        return str;

      if (!str)
        {
          str = g_steal_pointer (&value);
        }
      else
        {
          g_autofree char *tmp = g_steal_pointer (&str);
          str = g_strconcat (tmp, ", ", value, NULL);
        }

      entry++;
    }

  return str;
}

static const char *
device_type_to_string (FpDeviceType device_type)
{
  g_autoptr(GEnumClass) device_types = g_type_class_ref (fp_device_type_get_type ());
  GEnumValue *value = g_enum_get_value (device_types, device_type);

  return value->value_nick;
}

static const char *
scan_type_to_string (FpScanType scan_type)
{
  g_autoptr(GEnumClass) scan_types = g_type_class_ref (fp_scan_type_get_type ());
  GEnumValue *value = g_enum_get_value (scan_types, scan_type);

  return value->value_nick;
}

int
main (void)
{
  g_autoptr(GArray) shared_drivers = NULL;
  guint i;

  tod_shared_drivers_register ();

  shared_drivers = tod_shared_drivers_get ();
  g_print ("Found %u drivers\n", shared_drivers->len);

  for (i = 0; i < shared_drivers->len; i++)
    {
      GType driver = g_array_index (shared_drivers, GType, i);
      g_autoptr(FpDeviceClass) cls = g_type_class_ref (driver);
      GObjectClass *object_cls = G_OBJECT_CLASS (cls);
      g_autofree char *id_table = NULL;
      g_autofree char *features = NULL;

      id_table = id_table_to_string (cls->type, cls->id_table);
      features = g_flags_to_string (fp_device_feature_get_type (), cls->features);

      g_print ("ID: %s\n", cls->id);
      g_print ("Full Name: %s\n", cls->full_name);
      g_print ("Type: %s\n", device_type_to_string (cls->type));
      g_print ("Type name: %s\n", g_type_name (object_cls->g_type_class.g_type));
      g_print ("Base type: %s\n", g_type_name (g_type_parent (object_cls->g_type_class.g_type)));
      g_print ("Enroll stages: %d\n", cls->nr_enroll_stages);
      g_print ("Scan type: %s\n", scan_type_to_string (cls->scan_type));
      g_print ("Seconds to get Hot: %d\n", cls->temp_hot_seconds);
      g_print ("Seconds to get Cold: %d\n", cls->temp_cold_seconds);
      g_print ("Supported Devices: %s\n", id_table);
      g_print ("Supported features: %s\n", features);
      g_print ("Implemented VFuncs:\n");
      g_print ("  usb_discover: %s\n", cls->usb_discover ? "true" : "false");
      g_print ("  probe: %s\n", cls->probe ? "true" : "false");
      g_print ("  open: %s\n", cls->open ? "true" : "false");
      g_print ("  close: %s\n", cls->close ? "true" : "false");
      g_print ("  suspend: %s\n", cls->suspend ? "true" : "false");
      g_print ("  resume: %s\n", cls->resume ? "true" : "false");
      g_print ("  enroll: %s\n", cls->enroll ? "true" : "false");
      g_print ("  verify: %s\n", cls->verify ? "true" : "false");
      g_print ("  identify: %s\n", cls->identify ? "true" : "false");
      g_print ("  capture: %s\n", cls->capture ? "true" : "false");
      g_print ("  list: %s\n", cls->list ? "true" : "false");
      g_print ("  delete: %s\n", cls->delete ? "true" : "false");
      g_print ("  clear_storage: %s\n", cls->clear_storage ? "true" : "false");
      g_print ("  cancel: %s\n", cls->cancel ? "true" : "false");

      if (g_type_is_a (driver, FP_TYPE_IMAGE_DEVICE))
        {
          FpImageDeviceClass *image_cls = FP_IMAGE_DEVICE_CLASS (cls);

          g_print ("  Image bz3 threshold: %d\n", image_cls->bz3_threshold);
          g_print ("  Image width: %d\n", image_cls->img_width);
          g_print ("  Image height: %d\n", image_cls->img_height);

          g_print ("  Image img_open: %s\n", image_cls->img_open ? "true" : "false");
          g_print ("  Image img_close: %s\n", image_cls->img_close ? "true" : "false");
          g_print ("  Image activate: %s\n", image_cls->activate ? "true" : "false");
          g_print ("  Image change_state: %s\n", image_cls->change_state ? "true" : "false");
          g_print ("  Image deactivate: %s\n", image_cls->deactivate ? "true" : "false");
        }

      if (g_type_is_a (driver, FP_TYPE_SDCP_DEVICE))
        {
          FpSdcpDeviceClass *sdcp_cls = FP_SDCP_DEVICE_CLASS (cls);
          g_autofree char *verification_flags = NULL;

          verification_flags = g_flags_to_string (fpi_device_sdcp_verification_flags_get_type (),
                                                  sdcp_cls->verification_flags);

          g_print ("  SDCP Verification Flags: %s\n", verification_flags);
          g_print ("  SDCP get_ca_store: %s\n", sdcp_cls->get_ca_store ? "true" : "false");
          g_print ("  SDCP connect: %s\n", sdcp_cls->connect ? "true" : "false");
          g_print ("  SDCP reconnect: %s\n", sdcp_cls->reconnect ? "true" : "false");
          g_print ("  SDCP list: %s\n", sdcp_cls->list ? "true" : "false");
          g_print ("  SDCP enroll_commit: %s\n", sdcp_cls->enroll_commit ? "true" : "false");
        }

      if (i < shared_drivers->len - 1)
        g_print ("------------\n");
    }

  tod_shared_drivers_unregister ();
}
