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

/*
 * Device key material from the SDCP reference test run.
 * See: https://github.com/Microsoft/SecureDeviceConnectionProtocol/blob/fe82ea1/README.md
 *
 * firmware_private_key_hex (sk_f) is used by dev_connect() to compute the
 * application secret via ECDH(sk_f, pk_h) + KDF, mirroring what the real
 * device firmware would do.  All other key fields (pk_d, pk_f, s_m, s_d,
 * r_d) are taken directly from that same test run.
 *
 * To replace with fresh random key material:
 *   - P-256 keypair (firmware or device keys):
 *       openssl ecparam -name prime256v1 -genkey -noout -out key.pem
 *       openssl ec -in key.pem -noout -text
 *   - Random bytes (device_random_hex, enrollment_nonce_hex, identify_nonce_hex):
 *       openssl rand -hex 32
 *   - firmware_hash_hex: SHA-256 of actual firmware binary:
 *       openssl dgst -sha256 -hex <firmware.bin>
 *   - model_certificate_hex / expired_model_certificate_hex:
 *       run libfprint/drivers/gen-virtual-sdcp-test-cert.py
 *   - model_signature_hex / device_signature_hex:
 *       recompute with the Python generator or by signing with sk_m / sk_d
 *       (see signature coverage comments below)
 */

/* device keys */

static const gchar firmware_private_key_hex[] = "1bdd42b6567101a59ef03e342138f506c83f27ecf21418cd9eaee223af7f3193";
static const gchar device_random_hex[]         = "353eb43ffb422fc96c857140d5c399d588feef46f62bd363b97c823975bb27e7";
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
static const gchar expired_model_certificate_hex[] = "3082018d30820133a003020102020103300a06082a8648ce3d04030230243122"
                                                     "302006035504030c1953444350205669727475616c205465737420526f6f7420"
                                                     "4341301e170d3230303130313030303030305a170d3231303130313030303030"
                                                     "305a302a3128302606035504030c1f53444350205669727475616c2054657374"
                                                     "204d6f64656c20457870697265643059301306072a8648ce3d020106082a8648"
                                                     "ce3d03010703420004c5eb2c24de08a4dd9cfd42c5bc5610277d492111f151bf"
                                                     "33ad71ad9525401d00d9320976c3c83980fab279d04d1fc9f4196da4d68a2f3b"
                                                     "6891189af231bf5088a350304e300c0603551d130101ff04023000301d060355"
                                                     "1d0e041604149244cf70371e7e61c71a80d7066d20427162c1d3301f0603551d"
                                                     "230418301680146ed6652bb4f2fb15f2adfa6388b7317b38b37b26300a06082a"
                                                     "8648ce3d040302034800304502205ca95b6be59eb975b8aaf3278d725eb804ca"
                                                     "5d040c5f3cf9daa8090c4c2efaf6022100fefbe3fbbfe9cf280e7209ade444d8"
                                                     "19d98779ff702e5447080545b529af09de";
static const gchar device_public_key_hex[]   = "04840f109357fbf397e44c895cbfaff6b27527866828c94353120941b6020b1d"
                                               "be75ffd7b22b7ee2b7a57e8e89007f06eee43b7b8fceb382f8a6e78b812ed43"
                                               "7f9";
static const gchar firmware_public_key_hex[] = "04083cb5e7ece3a8ffa2b6d2d52e2c1721f7d8de6eaaca7fad08267e289e97ec"
                                               "a18f3bf8afe57e528b6ad07023df442621c4ad8294816d12852339848eb1196d"
                                               "16";
static const gchar firmware_hash_hex[]       = "c3bf47ea1f4a4a605470313cacb3a44f4a461f68c6faeab07e737610cb5ac835";

/*
 * model_signature_hex: Sign(sk_m, SHA256(pk_d))
 * device_signature_hex: Sign(sk_d, SHA256(C001 || h_f || pk_f))
 *
 * Both taken directly from the SDCP reference test run output; verified to
 * check out against the model certificate's pk_m key already in our truststore.
 * See: https://github.com/Microsoft/SecureDeviceConnectionProtocol/blob/fe82ea1/README.md
 */
static const gchar model_signature_hex[]     = "e9782b0e27729276810f3f1a5dfeaa5852e817e1a5cf1cadf20afbc7fc64b282"
                                               "a8371b36cb975c9b3bce16c92a40308b3651fccfb6fdca0dd3c850c22109b23f";
static const gchar device_signature_hex[]    = "fd914d22d2fcb199a4d988d091d3ab9b1d50863dd4f118218045ccd3fa6609fa"
                                               "f11c6d0290ade334d0f5c954241828bc3723c015a4f4adcb2aede261f347fbfa";

/* enrollment nonce used by the virtual driver for the first enrolled print */
/* regenerate with: openssl rand -hex 32 */

static const gchar enrollment_nonce_hex[] = "c2101c44c9a667bba397e81f48b143398603e2c9335a68b409e1dbe71e005ca2";

/* identify nonce used by the virtual driver for identify operations */
/* regenerate with: openssl rand -hex 32 */

static const gchar identify_nonce_hex[] = "3a1b506f5bec089059acefb9b44dfbdea7a599ee9aa267e5252664d60b798053";
