/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static java.nio.charset.StandardCharsets.UTF_8;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Anti-CSRF helpers for this lesson: a per session synchronizer token and an origin check based on
 * the Origin/Referer headers. Both are needed because Spring Security's own CSRF filter is switched
 * off for WebGoat.
 */
final class CsrfProtection {

  private static final String TOKEN_HEADER = "X-CSRF-TOKEN";
  private static final String TOKEN_PARAMETER = "validateReq";
  private static final String TOKEN_SESSION_ATTRIBUTE = "csrf-lesson-token";
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private CsrfProtection() {}

  /** Returns the token bound to this session, generating an unpredictable one on first use. */
  static String tokenFor(HttpSession session) {
    String token = (String) session.getAttribute(TOKEN_SESSION_ATTRIBUTE);
    if (token == null) {
      byte[] randomBytes = new byte[32];
      SECURE_RANDOM.nextBytes(randomBytes);
      token = HexFormat.of().formatHex(randomBytes);
      session.setAttribute(TOKEN_SESSION_ATTRIBUTE, token);
    }
    return token;
  }

  /**
   * Compares the token submitted with the request (header or form field) against the one stored in
   * the session. A cross site request cannot read the token, so it cannot pass this check.
   */
  static boolean hasValidToken(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session == null) {
      return false;
    }
    String expected = (String) session.getAttribute(TOKEN_SESSION_ATTRIBUTE);
    String provided = request.getHeader(TOKEN_HEADER);
    if (provided == null) {
      provided = request.getParameter(TOKEN_PARAMETER);
    }
    if (expected == null || provided == null) {
      return false;
    }
    return MessageDigest.isEqual(expected.getBytes(UTF_8), provided.getBytes(UTF_8));
  }

  /**
   * Returns true only when the request states an Origin (or, as a fallback, a Referer) which points
   * at this application. A missing header proves nothing and is therefore rejected.
   */
  static boolean isSameOrigin(HttpServletRequest request) {
    String host = request.getHeader("Host");
    String source = request.getHeader("Origin");
    if (source == null) {
      source = request.getHeader("Referer");
    }
    if (host == null || source == null) {
      return false;
    }
    try {
      return host.equals(new URI(source).getAuthority());
    } catch (URISyntaxException e) {
      return false;
    }
  }
}
