/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Tells where a state changing request was started from.
 *
 * <p>A browser labels a form post or an XHR with {@code Origin}, and normally also with {@code
 * Referer}. Comparing that label with the address this application is being served on is the
 * standard way of spotting a request that some other page triggered with the victim's cookies.
 *
 * <p>Three outcomes are possible on purpose. A request that proves it came from us, a request that
 * proves it came from somewhere else, and a request that says nothing at all (a script on the
 * command line, an integration test). Endpoints that guard a lesson answer demand the first;
 * endpoints that only have to stop a forged browser request reject the second.
 */
final class OriginCheck {

  private OriginCheck() {}

  /** True only when the request carries a label and that label is our own address. */
  static boolean fromThisApplication(HttpServletRequest request) {
    Boolean sameSite = compareLabel(request);
    return Boolean.TRUE.equals(sameSite);
  }

  /** True only when the request carries a label and that label belongs to another site. */
  static boolean fromAnotherSite(HttpServletRequest request) {
    Boolean sameSite = compareLabel(request);
    return Boolean.FALSE.equals(sameSite);
  }

  /** Null when the request does not say where it came from. */
  private static Boolean compareLabel(HttpServletRequest request) {
    String origin = firstNonBlank(request.getHeader("Origin"), request.getHeader("Referer"));
    if (origin == null) {
      return null;
    }
    // "null" is what a browser sends for a sandboxed frame, a data url or a page that suppresses
    // its referrer. It is never this application, so it counts as another site.
    if ("null".equalsIgnoreCase(origin)) {
      return Boolean.FALSE;
    }
    String claimed = authorityOf(origin);
    return claimed != null && claimed.equalsIgnoreCase(ownAuthority(request));
  }

  private static String firstNonBlank(String first, String second) {
    if (first != null && !first.isBlank()) {
      return first.trim();
    }
    return second == null || second.isBlank() ? null : second.trim();
  }

  /** The host and port this request was served on, in the same shape as an Origin header. */
  private static String ownAuthority(HttpServletRequest request) {
    String scheme = request.getScheme().toLowerCase(Locale.ROOT);
    int port = request.getServerPort();
    boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
    return defaultPort ? request.getServerName() : request.getServerName() + ":" + port;
  }

  /** Reduces an absolute url to host and port, dropping any userinfo an attacker may have added. */
  private static String authorityOf(String url) {
    try {
      String authority = new URI(url).getRawAuthority();
      if (authority == null) {
        return null;
      }
      int userInfo = authority.lastIndexOf('@');
      return userInfo < 0 ? authority : authority.substring(userInfo + 1);
    } catch (URISyntaxException e) {
      return null;
    }
  }
}
