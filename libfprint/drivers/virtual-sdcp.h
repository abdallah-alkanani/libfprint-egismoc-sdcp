/*
 * Virtual driver test payloads for SDCP device debugging
 *
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

#include "fpi-compat.h"

/* host keys */

static const gchar host_private_key_hex[] = "8400ed14579cdf11586477e836e8cb52708441c1c2a447c218c5bbc2d118fbc7";
static const gchar host_public_key_hex[]  = "0452f056ffb9c6728654771a3629b770767b19a2106a4916fb81ba06ef6797c4"
                                            "a3df672ade0e9116d1abe278a8223abde4958d62d4ff6882159f0617c6f8ce10"
                                            "bf";
static const gchar host_random_hex[]      = "d877403abe82f4d97e1448c5052d83a532a45e56ef049cbbf981137520e713bf";

/* device keys */

static const gchar device_random_hex[]       = "6e2f6c1abef2a1973fb1315a17e209fdb0c78520f1fd6a85d294d7aeb40a04a7";
static const gchar model_certificate_hex[]   = "308201873082012da003020102020102300a06082a8648ce3d04030230243122"
                                               "302006035504030c1953444350205669727475616c205465737420526f6f7420"
                                               "43413020170d3230303130313030303030305a180f3230393930313031303030"
                                               "3030305a30223120301e06035504030c1753444350205669727475616c205465"
                                               "7374204d6f64656c3059301306072a8648ce3d020106082a8648ce3d03010703"
                                               "420004c5eb2c24de08a4dd9cfd42c5bc5610277d492111f151bf33ad71ad9525"
                                               "401d00d9320976c3c83980fab279d04d1fc9f4196da4d68a2f3b6891189af231"
                                               "bf5088a350304e300c0603551d130101ff04023000301d0603551d0e04160414"
                                               "9244cf70371e7e61c71a80d7066d20427162c1d3301f0603551d230418301680"
                                               "146ed6652bb4f2fb15f2adfa6388b7317b38b37b26300a06082a8648ce3d0403"
                                               "020348003045022014f13002c4eb62bf33301223a61fd9bbc68ea9e77dd4d029"
                                               "5595a5587c684bfc022100a8c6dc9db08332bf434c651e70087b50775914abce"
                                               "c93799eb944a5e32f4fe8c";
static const gchar device_public_key_hex[]   = "04e2787890a684f95b96b9a2316ca8d3d33d4d79ff4c89dc6f9e888e973990d1"
                                               "d3154133dcc8bd33b99af9dbf0673390d404d092498a3f214cd93f9b9f28fb5f"
                                               "66";
static const gchar firmware_public_key_hex[] = "04f06a84ab51a3a6e8ff46868f91dd720e4cdad21f2e090d11e8f9bfc2ea19ee"
                                               "1b5eac850b4532968a9399f76cd779e7723e8c2ca73b597c0df5f73b94a36f2b"
                                               "6c";
static const gchar firmware_hash_hex[]       = "c3bf47ea1f4a4a605470313cacb3a44f4a461f68c6faeab07e737610cb5ac835";
static const gchar model_signature_hex[]     = "febe6ba3107813e185f05189e69ae79d9f7a40802582d94324459844c8b97ec6"
                                               "c5daed5462276cb8a193c33e350424b0305d63d79a93a9188dcfc0cb5595f6c1";
static const gchar device_signature_hex[]    = "10cc57dd8dafb463510a7327a5fca49b698e999b36448e2023eaf0dff0b0d4a3"
                                               "4f1caf4e872b77364a0a00d7476554d0324c4cc931937e232a0315837d696c06";
static const gchar connect_mac_hex[]         = "587099769025b54ddbae2a7a2d9166b930929e6f0515433cf2e126f71e024cd4";

/* expected application_secret based on above */

static const gchar application_secret_hex[] = "13330ba3135ecf5dc71cede01a886540771efab35c8ba053902b2c1ee7de6efe";

/* test verify_reconnect values */

static const gchar reconnect_random_hex[] = "8a7451c1d3a8dca1c1330ca50d73454b351a49f46c8e9dcee15c964d295c31c9";
static const gchar reconnect_mac_hex[]    = "bf3f3bb3bd6ecb2784c160f526f7bc3b3ca8faf5557194c48e0024a0493903c7";

/* test enrollment_id values */

static const gchar enrollment_nonce_hex[] = "c2101c44c9a667bba397e81f48b143398603e2c9335a68b409e1dbe71e005ca2";
static const gchar enrollment_id_hex[]    = "67109dc70a216331f1580ddac601915929c1ff6c9bcba6544ba572c660c3d91e";

/* test verify_identify values */

static const gchar identify_nonce_hex[] = "3a1b506f5bec089059acefb9b44dfbdea7a599ee9aa267e5252664d60b798053";
static const gchar identify_mac_hex[]   = "53a723eef40713094a90c5ef9996cbd6ba268e30676cd7107705a6c3e3e1eff9";
