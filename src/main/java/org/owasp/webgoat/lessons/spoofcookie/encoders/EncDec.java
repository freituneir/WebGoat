/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

/**
 * Turns a user name into an authentication cookie value and back again.
 *
 * <p>The value does not have to be secret, but it does have to be unforgeable: it is the only thing
 * the cookie login flow has to go on. Encoding gives no such guarantee — every transformation a
 * client can undo, it can also redo for somebody else's name, no matter how many layers are
 * stacked. The name is therefore accompanied by an HMAC computed with a key that never leaves this
 * process, and the tag is verified before the name is handed back to the caller.
 */
public class EncDec {

  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final char SEPARATOR = '.';
  private static final SecretKey SIGNING_KEY = generateSigningKey();
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

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

    int separator = encodedValue.indexOf(SEPARATOR);
    if (separator < 0) {
      throw new IllegalArgumentException("The cookie is not in the expected format");
    }

    String payload = encodedValue.substring(0, separator);
    byte[] presentedTag = DECODER.decode(encodedValue.substring(separator + 1));
    if (!MessageDigest.isEqual(sign(payload), presentedTag)) {
      throw new IllegalArgumentException("The cookie was not issued by this application");
    }

    return new String(DECODER.decode(payload), StandardCharsets.UTF_8);
  }

  private static byte[] sign(final String payload) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(SIGNING_KEY);
      return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to sign the authentication cookie", e);
    }
  }

  private static SecretKey generateSigningKey() {
    try {
      return KeyGenerator.getInstance(HMAC_ALGORITHM).generateKey();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(HMAC_ALGORITHM + " is not available", e);
    }
  }
}
