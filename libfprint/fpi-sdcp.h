/*
 * Secure Device Connection Protocol (SDCP) support implementation
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

#include "fpi-sdcp-device.h"

/**
 * fpi_sdcp_generate_host_key:
 * @private_key: (out) (transfer full): The host private key (sk_h)
 * @public_key: (out) (transfer full): The host public key (pk_h)
 * @error: (out): #GError in case the out values are %NULL
 *
 * Function to generate a new ephemeral ECDH key pair for use with SDCP.
 **/
gboolean fpi_sdcp_generate_host_key (GBytes **private_key,
                                     GBytes **public_key,
                                     GError **error);

/**
 * fpi_sdcp_generate_random:
 * @error: (out): #GError in case the return value is %NULL
 *
 * Returns: A new #GBytes with a secure random of length %FPI_SDCP_RANDOM_SIZE
 **/
GBytes *fpi_sdcp_generate_random (GError **error);

/**
 * fpi_sdcp_verify_connect:
 * @host_private_key: Private key generated using fpi_sdcp_generate_host_key() (sk_h)
 * @host_random: Random generated using fpi_sdcp_generate_random() (r_h)
 * @device_random: The random provided in the device's ConnectResponse (r_d)
 * @claim: #FpiSdcpClaim provided in the device's ConnectResponse (c)
 * @mac: The MAC provided in the device's ConnectResponse (m)
 * @additional_trust_store: (nullable): An optional #GResource containing additional
 *   PEM certificates at the path %FPI_SDCP_TRUST_STORE_PATH that are merged
 *   into the default SDCP trust store before certificate verification.
 *   Pass %NULL to use only the default trust store.
 * @verification_flags: Flags to control which verifications should be performed
 *   during the ConnectResponse validation.
 *   See #FpiDeviceSdcpVerificationFlags for details.
 * @application_secret: (out) (transfer full): A new #GBytes with the derived
 *   application secret (s) of length %FPI_SDCP_APPLICATION_SECRET_SIZE
 * @error: (out): #GError in case the return value is %NULL
 *
 * High level function which internally handles the derivation of all necessary
 * SDCP-related keys and secrets from the device's ConnectResponse and derives
 * the application secret for use with all other SDCP-related functions.
 * The KDF and MAC labels used during key derivation are taken from the
 * @claim label fields; %NULL fields fall back to the %FPI_SDCP_DEFAULT_LABEL_*
 * constants.
 *
 * This function will also perform a validation of the ConnectResponse MAC and
 * optionally perform additional verifications based on the provided
 * @verification_flags.
 * If any of these these validations fail then %NULL will be returned,
 * indicating that the SDCP secure connection channel could not be established.
 *
 * Returns: %TRUE if the @application_secret was successfully derived and the
 * ConnectResponse has been successfully verified
 **/
gboolean fpi_sdcp_verify_connect (GBytes                        *host_private_key,
                                  GBytes                        *host_random,
                                  GBytes                        *device_random,
                                  FpiSdcpClaim                  *claim,
                                  GBytes                        *mac,
                                  GResource                     *additional_trust_store,
                                  FpiDeviceSdcpVerificationFlags verification_flags,
                                  GBytes                       **application_secret,
                                  GError                       **error);

/**
 * fpi_sdcp_verify_reconnect:
 * @application_secret: The host's derived application secret (s)
 * @label: HMAC label, or %NULL to use %FPI_SDCP_DEFAULT_LABEL_RECONNECT
 * @random: The host-generated random sent to the device's Reconnect
 *   command (r)
 * @mac: The MAC provided in the device's ReconnectResponse (m)
 * @error: (out): #GError in case the return value is %FALSE
 *
 * Verifies the SDCP ReconnectResponse.
 *
 * Returns: %TRUE if the ReconnectResponse is verified successfully
 **/
gboolean fpi_sdcp_verify_reconnect (GBytes      *application_secret,
                                    const gchar *label,
                                    GBytes      *random,
                                    GBytes      *mac,
                                    GError     **error);

/**
 * fpi_sdcp_verify_identify:
 * @application_secret: The host's derived application secret (s)
 * @label: HMAC label, or %NULL to use %FPI_SDCP_DEFAULT_LABEL_IDENTIFY
 * @nonce: The host-generated nonce sent to the device's Identify
 *   command (n)
 * @id: The ID provided in the device's AuthorizedIdentity (id)
 * @mac: The MAC provided in the device's AuthorizedIdentity (m)
 * @error: (out): #GError in case the return value is %FALSE
 *
 * Verifies the SDCP AuthorizedIdentity.
 *
 * Returns: %TRUE if the AuthorizedIdentity is verified successfully
 **/
gboolean fpi_sdcp_verify_identify (GBytes      *application_secret,
                                   const gchar *label,
                                   GBytes      *nonce,
                                   GBytes      *id,
                                   GBytes      *mac,
                                   GError     **error);

/**
 * fpi_sdcp_generate_enrollment_id:
 * @application_secret: The host's derived application secret (s)
 * @label: HMAC label, or %NULL to use %FPI_SDCP_DEFAULT_LABEL_ENROLL
 * @nonce: The nonce received from the device in response to the
 *   EnrollBegin command (n)
 * @error: (out): #GError in case the return value is %NULL
 *
 * Generates a new id for use with the device's EnrollCommit command.
 *
 * Returns: A new #GBytes with the generated enrollment id of length
 * %FPI_SDCP_ENROLLMENT_ID_SIZE
 **/
GBytes *fpi_sdcp_generate_enrollment_id (GBytes      *application_secret,
                                         const gchar *label,
                                         GBytes      *nonce,
                                         GError     **error);

/**
 * fpi_sdcp_key_agreement:
 * @private_key: A 32-byte raw P-256 private scalar (device firmware key or host key)
 * @peer_public_key: A 65-byte uncompressed P-256 public key of the peer
 * @error: (out): #GError in case the return value is %NULL
 *
 * Computes ECDH(private_key, peer_public_key) and returns the 32-byte x-coordinate
 * shared secret.  Used by both the host (ECDH(sk_h, pk_f)) and by drivers
 * (ECDH(sk_f, pk_h)) to arrive at the same pre-master secret.
 *
 * Returns: A new #GBytes with the 32-byte raw shared secret, or %NULL on error
 **/
GBytes *fpi_sdcp_key_agreement (GBytes  *private_key,
                                GBytes  *peer_public_key,
                                GError **error);

/**
 * fpi_sdcp_kdf:
 * @key: KBKDF key input
 * @label: Label string (used without trailing NUL as the KBKDF salt)
 * @context_a: (nullable): First context buffer, or %NULL
 * @context_b: (nullable): Second context buffer, or %NULL (concatenated after @context_a)
 * @length: Desired output length in bytes
 * @error: (out): #GError in case the return value is %NULL
 *
 * Runs NIST SP 800-108r1 KBKDF in counter mode with HMAC-SHA256.
 * Equivalent to: KDF(key, label, context_a || context_b, length).
 *
 * Returns: A new #GBytes of @length derived bytes, or %NULL on error
 **/
GBytes *fpi_sdcp_kdf (GBytes      *key,
                      const gchar *label,
                      GBytes      *context_a,
                      GBytes      *context_b,
                      gsize        length,
                      GError     **error);

/**
 * fpi_sdcp_mac:
 * @application_secret: The application secret to use as the HMAC key
 * @label: Label string (included with a trailing NUL byte), or %NULL
 * @data_a: First data buffer, or %NULL
 * @data_b: Second data buffer, or %NULL
 * @error: (out): #GError in case the return value is %NULL
 *
 * Computes HMAC-SHA256(@application_secret, @label || @data_a || @data_b).
 *
 * Returns: A new #GBytes with the MAC of length %FPI_SDCP_MAC_SIZE
 **/
GBytes *fpi_sdcp_mac (GBytes      *application_secret,
                      const gchar *label,
                      GBytes      *data_a,
                      GBytes      *data_b,
                      GError     **error);

/**
 * fpi_sdcp_verify_certificate:
 * @x509_certificate: An X.509 certificate in DER (ASN.1) format
 * @additional_trust_store: (nullable): An optional #GResource containing
 *   additional PEM certificates at the path %FPI_SDCP_TRUST_STORE_PATH that
 *   are merged into the default SDCP trust store.
 *   Use %NULL to use only the default trust store.
 * @verification_flags: Flags to control certificate verification behaviour.
 *   See #FpiDeviceSdcpVerificationFlags for details.
 * @error: (out): #GError on failure
 *
 * Verifies an X.509 certificate (DER-encoded) against the SDCP trust store.
 *
 * Returns: %TRUE if the certificate is trusted
 **/
gboolean fpi_sdcp_verify_certificate (GBytes                        *x509_certificate,
                                      GResource                     *additional_trust_store,
                                      FpiDeviceSdcpVerificationFlags verification_flags,
                                      GError                       **error);
