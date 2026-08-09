/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * The few places where requiring a CSRF token would break a client that is not a browser at all.
 *
 * <p>Both applications are also driven from the integration tests and from the command line, and
 * such a client cannot fetch a token before it has a session. A browser always labels its cross site
 * form posts with {@code Origin} or {@code Referer}, so a request carrying neither header cannot
 * have been triggered from another page with the victim's cookies attached, which is exactly the
 * situation the token protects against.
 */
public final class CsrfExemptions {

  private CsrfExemptions() {}

  /** Matches token-less authentication calls made by non browser clients on the given paths. */
  public static RequestMatcher headerlessAuthentication(String... paths) {
    List<String> exempted = Arrays.asList(paths);
    return request ->
        "POST".equalsIgnoreCase(request.getMethod())
            && exempted.contains(pathWithoutContext(request))
            && request.getHeader("Origin") == null
            && request.getHeader("Referer") == null;
  }

  private static String pathWithoutContext(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String context = request.getContextPath();
    if (context == null || context.isEmpty() || !uri.startsWith(context)) {
      return uri;
    }
    return uri.substring(context.length());
  }
}
