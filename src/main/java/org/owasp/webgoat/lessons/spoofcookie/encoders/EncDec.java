/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  /*
   * Reversing, hex and base64 are encodings, not protection. Without a key in the mix anybody who
   * sees one cookie can decode it and write a cookie for somebody else. The value is signed.
   */
  private static final String SIGNING_ALGORITHM = "HmacSHA256";
  private static final byte[] SIGNING_KEY = randomKey();
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
  private static final char SEPARATOR = '.';

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String payload = ENCODER.encodeToString(value.toLowerCase().getBytes(StandardCharsets.UTF_8));
    return payload + SEPARATOR + ENCODER.encodeToString(sign(payload));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    int separatorIndex = encodedValue.lastIndexOf(SEPARATOR);
    if (separatorIndex < 0) {
      throw new IllegalArgumentException("Cookie is not valid");
    }

    String payload = encodedValue.substring(0, separatorIndex);
    byte[] providedMac = DECODER.decode(encodedValue.substring(separatorIndex + 1));
    if (!MessageDigest.isEqual(sign(payload), providedMac)) {
      throw new IllegalArgumentException("Cookie is not valid");
    }

    return new String(DECODER.decode(payload), StandardCharsets.UTF_8);
  }

  private static byte[] sign(final String payload) {
    try {
      Mac mac = Mac.getInstance(SIGNING_ALGORITHM);
      mac.init(new SecretKeySpec(SIGNING_KEY, SIGNING_ALGORITHM));
      return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to authenticate the cookie", e);
    }
  }

  private static byte[] randomKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }
}
