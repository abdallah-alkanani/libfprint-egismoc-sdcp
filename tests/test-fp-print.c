/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <gio/gio.h>

#include "fprint.h"
#include "fpi-print.h"
#include "fpi-sdcp-device.h"

/* Construct the persisted FP3 format independently of fp_print_serialize().
 * The nested variant containing (ay) is also the experimental SDCP format. */
static GBytes *
serialized_print_full (gint type, GVariant *payload, guint8 finger, gint date)
{
  g_autoptr(GVariant) value = NULL;
  gsize length;
  guint8 *data;

  value = g_variant_ref_sink (g_variant_new ("(issbymsmsi@a{sv}v)",
                                             type, "egismoc", "0", TRUE,
                                             finger,
                                             "compatibility-test", "test print", date,
                                             g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0),
                                             payload));
#if (G_BYTE_ORDER == G_BIG_ENDIAN)
  {
    GVariant *swapped = g_variant_byteswap (value);
    g_variant_unref (value);
    value = swapped;
  }
#endif
  length = g_variant_get_size (value);
  data = g_malloc (length + 3);
  memcpy (data, "FP3", 3);
  memcpy (data + 3, g_variant_get_data (value), length);
  return g_bytes_new_take (data, length + 3);
}

static GBytes *
serialized_print (gint type, GVariant *payload)
{
  return serialized_print_full (type, payload, FP_FINGER_LEFT_INDEX, 739879);
}

static GVariant *
id_payload (gsize length)
{
  guint8 id[FPI_SDCP_ENROLLMENT_ID_SIZE + 1];

  g_assert_cmpuint (length, <=, sizeof (id));
  for (guint i = 0; i < sizeof (id); i++)
    id[i] = i;
  return g_variant_new_variant (g_variant_new ("(@ay)",
                                               g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                                          id, length, 1)));
}

static void
assert_invalid (GBytes *serialized)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) print = NULL;

  print = fp_print_deserialize (g_bytes_get_data (serialized, NULL),
                                g_bytes_get_size (serialized), &error);
  g_assert_null (print);
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
}

static void
test_legacy_sdcp (void)
{
  g_autoptr(GBytes) serialized = serialized_print (FPI_PRINT_SDCP,
                                                   id_payload (FPI_SDCP_ENROLLMENT_ID_SIZE));
  g_autoptr(GBytes) id = NULL;
  g_autoptr(FpPrint) print = NULL;
  g_autoptr(FpPrint) roundtrip = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *data = NULL;
  gsize length;
  const guint8 *id_data;

  print = fp_print_deserialize (g_bytes_get_data (serialized, NULL),
                                g_bytes_get_size (serialized), &error);
  g_assert_no_error (error);
  g_assert_nonnull (print);
  g_assert_cmpstr (fp_print_get_driver (print), ==, "egismoc");
  g_assert_cmpstr (fp_print_get_device_id (print), ==, "0");
  g_assert_cmpstr (fp_print_get_username (print), ==, "compatibility-test");
  g_assert_cmpstr (fp_print_get_description (print), ==, "test print");
  g_assert_cmpuint (fp_print_get_finger (print), ==, FP_FINGER_LEFT_INDEX);
  g_assert_true (fp_print_get_device_stored (print));
  g_assert_cmpuint (g_date_get_julian (fp_print_get_enroll_date (print)), ==, 739879);
  id = fpi_print_sdcp_get_id (print);
  g_assert_nonnull (id);
  g_assert_cmpuint (g_bytes_get_size (id), ==, FPI_SDCP_ENROLLMENT_ID_SIZE);
  id_data = g_bytes_get_data (id, NULL);
  for (guint i = 0; i < g_bytes_get_size (id); i++)
    g_assert_cmpuint (id_data[i], ==, i);

  g_assert_true (fp_print_serialize (print, &data, &length, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (data, length, g_bytes_get_data (serialized, NULL),
                   g_bytes_get_size (serialized));
  roundtrip = fp_print_deserialize (data, length, &error);
  g_assert_no_error (error);
  g_assert_true (fp_print_equal (print, roundtrip));
}

static void
test_invalid_id_length (gconstpointer user_data)
{
  g_autoptr(GBytes) serialized = serialized_print (FPI_PRINT_SDCP,
                                                   id_payload (GPOINTER_TO_SIZE (user_data)));
  assert_invalid (serialized);
}

static void
test_invalid_payload (gconstpointer user_data)
{
  const char *payload = user_data;

  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) value = g_variant_parse (NULL, payload, NULL, NULL, &error);
  g_autoptr(GBytes) serialized = NULL;

  g_assert_no_error (error);
  serialized = serialized_print (FPI_PRINT_SDCP, value);
  assert_invalid (serialized);
}

static void
test_invalid_type (gconstpointer user_data)
{
  g_autoptr(GBytes) serialized = serialized_print (GPOINTER_TO_INT (user_data),
                                                   id_payload (FPI_SDCP_ENROLLMENT_ID_SIZE));
  assert_invalid (serialized);
}

static void
test_truncated (void)
{
  g_autoptr(GBytes) serialized = serialized_print (FPI_PRINT_SDCP,
                                                   id_payload (FPI_SDCP_ENROLLMENT_ID_SIZE));

  for (gsize length = 0; length < g_bytes_get_size (serialized); length++)
    {
      g_autoptr(GBytes) truncated = g_bytes_new_from_bytes (serialized, 0, length);
      assert_invalid (truncated);
    }
}

static void
test_other_print_type (gconstpointer user_data)
{
  gint type = GPOINTER_TO_INT (user_data);

  g_autoptr(GVariant) payload = NULL;

  g_autoptr(GBytes) serialized = NULL;
  g_autoptr(FpPrint) print = NULL;
  g_autoptr(FpPrint) roundtrip = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *data = NULL;
  gsize length;

  if (type == FPI_PRINT_RAW)
    payload = g_variant_new_variant (g_variant_new_string ("opaque driver data"));
  else
    payload = g_variant_parse (G_VARIANT_TYPE ("(a(aiaiai))"),
                               "([([10, 20], [30, 40], [50, 60])],)",
                               NULL, NULL, &error);
  g_assert_no_error (error);
  payload = g_variant_take_ref (payload);
  serialized = serialized_print (type, payload);
  print = fp_print_deserialize (g_bytes_get_data (serialized, NULL),
                                g_bytes_get_size (serialized), &error);
  g_assert_no_error (error);
  g_assert_nonnull (print);
  g_assert_true (fp_print_serialize (print, &data, &length, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (data, length, g_bytes_get_data (serialized, NULL),
                   g_bytes_get_size (serialized));
  roundtrip = fp_print_deserialize (data, length, &error);
  g_assert_no_error (error);
  g_assert_true (fp_print_equal (print, roundtrip));
}

static void
test_invalid_other_payload (gconstpointer user_data)
{
  g_autoptr(GBytes) serialized = serialized_print (GPOINTER_TO_INT (user_data),
                                                   g_variant_new_string ("invalid"));
  assert_invalid (serialized);
}

static void
test_incomplete_sdcp (void)
{
  g_autoptr(FpPrint) print = g_object_ref_sink (g_object_new (FP_TYPE_PRINT,
                                                              "driver", "egismoc",
                                                              "device-id", "0",
                                                              "fpi-type", FPI_PRINT_SDCP,
                                                              NULL));
  const gint sizes[] = {-1, 0, 31, 33};
  guint8 id[33] = {0};

  for (guint i = 0; i < G_N_ELEMENTS (sizes); i++)
    {
      g_autoptr(GError) error = NULL;
      g_autofree guint8 *data = NULL;
      gsize length = 0;

      if (sizes[i] >= 0)
        {
          g_autoptr(GBytes) invalid_id = g_bytes_new (id, sizes[i]);
          fpi_print_sdcp_set_id (print, invalid_id);
        }
      g_assert_false (fp_print_serialize (print, &data, &length, &error));
      g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
      g_assert_null (data);
      g_assert_cmpuint (length, ==, 0);
    }
}

static void
test_metadata (void)
{
  const struct
  {
    guint8 finger;
    gint   date;
  } invalid[] = {{255, 739879}, {FP_FINGER_LEFT_INDEX, 0}, {FP_FINGER_LEFT_INDEX, -1}};
  g_autoptr(GBytes) serialized = NULL;
  g_autoptr(FpPrint) print = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *data = NULL;
  gsize length;

  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++)
    {
      g_autoptr(GBytes) bad = serialized_print_full (FPI_PRINT_SDCP, id_payload (32),
                                                     invalid[i].finger, invalid[i].date);
      assert_invalid (bad);
    }

  serialized = serialized_print_full (FPI_PRINT_SDCP, id_payload (32),
                                      FP_FINGER_UNKNOWN, G_MININT32);
  print = fp_print_deserialize (g_bytes_get_data (serialized, NULL),
                                g_bytes_get_size (serialized), &error);
  g_assert_no_error (error);
  g_assert_nonnull (print);
  g_assert_null (fp_print_get_enroll_date (print));
  g_assert_true (fp_print_serialize (print, &data, &length, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (data, length, g_bytes_get_data (serialized, NULL),
                   g_bytes_get_size (serialized));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/print/sdcp/legacy-format", test_legacy_sdcp);
  g_test_add_data_func ("/print/sdcp/empty-id", GSIZE_TO_POINTER (0), test_invalid_id_length);
  g_test_add_data_func ("/print/sdcp/short-id", GSIZE_TO_POINTER (31), test_invalid_id_length);
  g_test_add_data_func ("/print/sdcp/long-id", GSIZE_TO_POINTER (33), test_invalid_id_length);
  g_test_add_data_func ("/print/sdcp/scalar-payload", "'invalid'", test_invalid_payload);
  g_test_add_data_func ("/print/sdcp/empty-tuple", "<()>", test_invalid_payload);
  g_test_add_data_func ("/print/sdcp/wrong-tuple", "<(uint32 1,)>", test_invalid_payload);
  g_test_add_data_func ("/print/sdcp/wrong-nesting", "<( <(@ay [],)> ,)>", test_invalid_payload);
  g_test_add_data_func ("/print/undefined-type", GINT_TO_POINTER (0), test_invalid_type);
  g_test_add_data_func ("/print/unknown-type", GINT_TO_POINTER (99), test_invalid_type);
  g_test_add_func ("/print/truncated", test_truncated);
  g_test_add_data_func ("/print/raw-roundtrip", GINT_TO_POINTER (FPI_PRINT_RAW), test_other_print_type);
  g_test_add_data_func ("/print/nbis-roundtrip", GINT_TO_POINTER (FPI_PRINT_NBIS), test_other_print_type);
  g_test_add_data_func ("/print/raw-invalid-payload", GINT_TO_POINTER (FPI_PRINT_RAW), test_invalid_other_payload);
  g_test_add_data_func ("/print/nbis-invalid-payload", GINT_TO_POINTER (FPI_PRINT_NBIS), test_invalid_other_payload);
  g_test_add_func ("/print/sdcp/incomplete-serialization", test_incomplete_sdcp);
  g_test_add_func ("/print/metadata", test_metadata);
  return g_test_run ();
}
