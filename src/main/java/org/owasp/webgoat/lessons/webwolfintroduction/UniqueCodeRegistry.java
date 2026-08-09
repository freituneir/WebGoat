/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Holds the unique codes the WebWolf lessons hand out.
 *
 * <p>The codes used to be the reversed user name. A value derived from something public is not a
 * secret: anybody who knows the account name can compute it and finish the assignment without ever
 * receiving the mail or visiting the landing page. Codes are drawn from {@link SecureRandom}
 * instead, kept per user and per flow so a code obtained in one flow cannot be replayed in another,
 * and compared without leaking their length or content through timing.
 */
@Component
public class UniqueCodeRegistry {

  public static final String MAIL = "mail";
  public static final String PASSWORD_RESET = "password-reset";

  private static final int CODE_BYTES = 16;

  private final SecureRandom random = new SecureRandom();
  private final Map<String, String> issuedCodes = new ConcurrentHashMap<>();

  /** The code for this user and flow, creating one the first time it is asked for. */
  public String codeFor(String username, String flow) {
    return issuedCodes.computeIfAbsent(keyOf(username, flow), ignored -> newCode());
  }

  /** Whether the submitted value is the code handed out to this user for this flow. */
  public boolean isValid(String username, String flow, String submitted) {
    String expected = issuedCodes.get(keyOf(username, flow));
    if (expected == null || submitted == null) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), submitted.getBytes(StandardCharsets.UTF_8));
  }

  private String keyOf(String username, String flow) {
    return flow + '/' + username;
  }

  private String newCode() {
    byte[] code = new byte[CODE_BYTES];
    random.nextBytes(code);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(code);
  }
}
