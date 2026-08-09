/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Issues the callback code the WebWolf introduction lesson delivers out-of-band.
 *
 * <p>The code used to be {@code StringUtils.reverse(username)}: a deterministic transform of a
 * value the caller already knows, so the assignment could be completed without ever receiving the
 * mail or triggering the landing-page request it is meant to prove. The code is now drawn from a
 * CSPRNG, kept server-side and only ever disclosed through those out-of-band channels, so
 * submitting it is evidence that the channel was actually observed.
 */
@Component
public class UniqueCodes {

  /** Excludes easily confused glyphs so a code copied out of a mail message survives the trip. */
  private static final char[] ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789".toCharArray();

  private final SecureRandom random = new SecureRandom();
  private final Map<String, String> codesByUser = new ConcurrentHashMap<>();

  /**
   * The code for this user, generated once and stable afterwards so the mail and landing-page
   * assignments agree. It is the same length as the username the reversed value used to occupy,
   * which keeps the delivered message and the lesson UI unchanged.
   */
  public String codeFor(String username) {
    return codesByUser.computeIfAbsent(username, this::generate);
  }

  /** Constant-time comparison — a code is a bearer secret, so leak no timing signal. */
  public boolean matches(String username, String submittedCode) {
    if (submittedCode == null) {
      return false;
    }
    return MessageDigest.isEqual(
        codeFor(username).getBytes(StandardCharsets.UTF_8),
        submittedCode.getBytes(StandardCharsets.UTF_8));
  }

  private String generate(String username) {
    var code = new StringBuilder(username.length());
    for (int i = 0; i < username.length(); i++) {
      code.append(ALPHABET[random.nextInt(ALPHABET.length)]);
    }
    return code.toString();
  }
}
